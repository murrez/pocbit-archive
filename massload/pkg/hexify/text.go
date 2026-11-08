package hexify

import (
	"bytes"
	"fmt"
	"io"
)

func String(command string, maxBuf int) ([]string, error) {
	rdr := bytes.NewReader([]byte(command))

	var dlrHex []string
	buf := make([]byte, maxBuf)

	for {
		n, err := rdr.Read(buf)
		if err != nil && err != io.EOF {
			return nil, err
		}

		if n == 0 {
			break
		}

		hexStr := ""

		for _, b := range buf[:n] {
			hexStr += fmt.Sprintf("\\x%02x", b)
		}

		dlrHex = append(dlrHex, hexStr)
	}

	return dlrHex, nil
}
