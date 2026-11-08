package honeypot

import (
	"errors"
	"fmt"
	"scanner/exploits/ssh/utils"
	"strings"

	"golang.org/x/crypto/ssh"
)

// honeypot detection
func systemTest(client *ssh.Client) error {
	s1, err := client.NewSession()
	if err != nil {
		return err
	}
	defer s1.Close()

	echoStr := utils.RandomString(10)
	dataStr := utils.RandomString(10)
	fileStr := utils.RandomString(10)
	sleep := utils.RandomInt(300)

	output, err := s1.CombinedOutput(fmt.Sprintf("echo %s && cd /tmp; echo %s > %s && sleep %d &", echoStr, dataStr, fileStr, sleep))
	if err != nil {
		return err
	}

	if !strings.Contains(string(output), echoStr) {
		return errors.New("echo is not woriking...")
	}

	s2, err := client.NewSession()
	if err != nil {
		return err
	}
	defer s2.Close()

	output, err = s2.CombinedOutput(fmt.Sprintf("cat /tmp/%s; rm -rf /tmp/%s && ps | grep 'sleep %d' | grep -v grep", fileStr, fileStr, sleep))
	if err != nil {
		return err
	}

	if !strings.Contains(string(output), dataStr) {
		return errors.New("file system is not working...")
	}

	if !strings.Contains(string(output), fmt.Sprintf("%d", sleep)) {
		return errors.New("process is not working...")
	}

	return nil
}
