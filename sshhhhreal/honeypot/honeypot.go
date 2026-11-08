package honeypot

import (
	"fmt"
	"scanner/exploits/ssh/login"
)

func IsHoneypot(auth *login.Auth) bool {
	err := systemTest(auth.Client)
	if err != nil {
		fmt.Printf("honeypot detected: %s (%s)\n", err.Error(), auth.Target)
		return true
	}

	return false
}
