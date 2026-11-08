package hexify

import (
	"fmt"
	"io"
	"os"
)

func File(path string, maxBuf int) ([]string, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}

	defer f.Close()

	var dlrHex []string
	buf := make([]byte, maxBuf)

	for {
		n, err := f.Read(buf)
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
