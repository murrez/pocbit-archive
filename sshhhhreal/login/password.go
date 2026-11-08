package login

import (
	"fmt"
	"strings"

	"github.com/tredoe/osutil/user/crypt/md5_crypt"
)

func (auth *Auth) ChangePassword(new string) error {
	s, err := auth.Client.NewSession()
	if err != nil {
		return err
	}
	defer s.Close()

	// stage 1
	output, err := s.CombinedOutput(fmt.Sprintf("echo -e \"%s\n%s\" | passwd", new, new))
	if strings.Contains(string(output), "successfully") || err == nil {
		return nil
	}

	// stage 2
	c := md5_crypt.New()
	hash, err := c.Generate([]byte(new), nil)
	if err != nil {
		return err
	}

	_, err = s.CombinedOutput(fmt.Sprintf("sed -i 's|^root:[^:]*:|root:%s:|' /etc/shadow", string(hash)))
	if err != nil {
		return err
	}

	return nil
}
