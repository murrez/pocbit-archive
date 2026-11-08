package utils

import (
	"fmt"
	"os"
	"scanner/exploits/ssh/login"
	"sync"
)

type Result struct {
	Target   string
	Username string
	Password string
}

var Mu sync.Mutex

func (r *Result) Save(name string) {
	Mu.Lock()
	defer Mu.Unlock()

	f, _ := os.OpenFile(name, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0644)
	defer f.Close()

	f.WriteString(fmt.Sprintf("%s|%s|%s\n", r.Target, r.Username, r.Password))
}

func SaveResult(auth *login.Auth, new string) {
	result := &Result{
		Target:   auth.Target,
		Username: auth.Username,
		Password: new,
	}

	if new == "none" {
		result.Password = auth.Password
	}

	result.Save("results.txt")
}
