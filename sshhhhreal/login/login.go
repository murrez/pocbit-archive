package login

import (
	"time"

	"golang.org/x/crypto/ssh"
)

type Auth struct {
	Target   string
	Username string
	Password string
	Client   *ssh.Client
}

func TryLogin(target, user, pass string) (*Auth, error) {
	config := &ssh.ClientConfig{
		User: user,
		Auth: []ssh.AuthMethod{
			ssh.Password(pass),
		},
		HostKeyCallback: ssh.InsecureIgnoreHostKey(),
		Timeout:         3 * time.Second,
	}

	client, err := ssh.Dial("tcp", target, config)
	if err != nil {
		return nil, err
	}

	return &Auth{
		Target:   target,
		Username: user,
		Password: pass,
		Client:   client,
	}, nil
}
