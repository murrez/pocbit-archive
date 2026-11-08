package ssh

import (
	"fmt"
	"net"
	"scanner/exploits/ssh/brute"
	"strings"
	"time"
)

func newSSH(target, port string, buf []byte) {
	conn, err := net.DialTimeout("tcp", net.JoinHostPort(target, port), 2*time.Second)
	if err != nil {
		return
	}

	conn.Read(buf)
	conn.Close()

	if strings.Contains(string(buf), "SSH-") {
		brute.BruteForce(fmt.Sprintf("%s:%s", target, port))
	}
}

func NewTarget(target string) {
	parts := strings.Split(target, ":")
	target = parts[0]

	buf := make([]byte, 30)

	go newSSH(target, "22", buf)
	go newSSH(target, "2222", buf)
	go newSSH(target, "22222", buf)
	go newSSH(target, "22022", buf)
}
