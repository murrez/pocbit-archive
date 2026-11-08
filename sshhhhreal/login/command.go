package login

import (
	"strings"
)

func (auth *Auth) RunCommand(command string) string {
	s, err := auth.Client.NewSession()
	if err != nil {
		return ""
	}
	defer s.Close()

	output, err := s.CombinedOutput(command)
	if err != nil {
		return ""
	}

	return strings.ReplaceAll(string(output), "\n", "")
}
