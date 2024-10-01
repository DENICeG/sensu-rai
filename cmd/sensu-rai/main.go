package main

import (
	"crypto/tls"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"os"
	"strings"
	"time"

	"golang.org/x/net/publicsuffix"
)

var (
	timeBegin   = time.Now()
	httpResp    *http.Response
	raiStartUrl string
	raiInitUrl  string
	raiLoginUrl string
	raiRegacc   string
	raiPassword string
	rai2fa      string
)

func main() {
	RunDefault()
}

func RunDefault() {
	raiStartUrl = os.Getenv("RAI_START_URL")
	raiInitUrl = os.Getenv("RAI_INIT_URL")
	raiLoginUrl = os.Getenv("RAI_LOGIN_URL")
	raiRegacc = os.Getenv("RAI_REGACC")
	raiPassword = os.Getenv("RAI_PW")
	rai2fa = os.Getenv("RAI_2FA")
	RunDefaultWithJar(raiRegacc, raiPassword, rai2fa)
}

func RunDefaultWithJar(account, password, twofa string) {
	log.SetOutput(os.Stderr)
	log.SetPrefix("UTC | ")
	log.SetFlags(log.Ldate | log.Ltime | log.LUTC)

	allgood := true
	patternStart, patternInit, patternLogin := false, false, false

	jar, err := cookiejar.New(&cookiejar.Options{PublicSuffixList: publicsuffix.List})
	if err != nil {
		log.Fatal(err)
	}

	UserClient := &http.Client{
		Jar: jar,
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
			Proxy:           http.ProxyFromEnvironment,
			Dial: (&net.Dialer{
				Timeout:   45 * time.Second,
				KeepAlive: 45 * time.Second,
			}).Dial,
			TLSHandshakeTimeout:   10 * time.Second,
			ExpectContinueTimeout: 1 * time.Second,
		},
	}

	timeFirstRaiStartUrl := time.Now()

	var startcookie *http.Cookie
	reqStart, _ := http.NewRequest("GET", raiStartUrl, nil)
	respStart, err := UserClient.Do(reqStart)
	if err != nil {
		printFailMetricsAndExit(err.Error())
	}
	bodyStartBytes, err := io.ReadAll(respStart.Body)
	if err != nil {
		printFailMetricsAndExit(err.Error())
	}

	timeFirstRaiStartUrlBodyComplete := time.Now()
	durationRaiStartUrl := timeFirstRaiStartUrlBodyComplete.Sub(timeFirstRaiStartUrl).Milliseconds()

	patternStart = strings.Contains(string(bodyStartBytes), "RegAcc-Profil-Pflege")

	if !patternStart {
		allgood = false
	}

	urlRaiStart, err := url.Parse(raiStartUrl)
	if err != nil {
		log.Fatal(err)
	}

	for _, cookie := range jar.Cookies(urlRaiStart) {

		if cookie.Name == "JSESSIONID" {
			startcookie = cookie
		}
	}

	timeRaiInitUrl := time.Now()

	reqInit, _ := http.NewRequest("GET", raiInitUrl, nil)
	reqInit.AddCookie(startcookie)
	respInit, err := UserClient.Do(reqInit)
	if err != nil {
		fmt.Println(err)
	}

	bodyInitBytes, err := io.ReadAll(respInit.Body)
	if err != nil {
		printFailMetricsAndExit(err.Error())
	}

	timeRaiInitUrlComplete := time.Now()
	durationRaiInitUrl := timeRaiInitUrlComplete.Sub(timeRaiInitUrl).Milliseconds()

	patternInit = strings.Contains(string(bodyInitBytes), "j_security_check")

	if !patternInit {
		allgood = false
	}

	postString := fmt.Sprintf("j_password=%s&j_username=%s&j_2fa=%s&login=submit", password, account, twofa)

	postBody := strings.NewReader(postString)

	timeRaiLoginUrl := time.Now()

	httpPostReq, err := http.NewRequest(http.MethodPost, raiLoginUrl, postBody)
	httpPostReq.Header.Add("Content-Type", "application/x-www-form-urlencoded")

	if err != nil {
		printFailMetricsAndExit(err.Error())
	}

	respLogin, err := UserClient.Do(httpPostReq)

	if err != nil {
		fmt.Println(err)
	}
	bodyLoginBytes, err := io.ReadAll(respLogin.Body)
	if err != nil {
		printFailMetricsAndExit(err.Error())
	}

	timeRaiLoginUrlComplete := time.Now()
	durationRaiLoginUrl := timeRaiLoginUrlComplete.Sub(timeRaiLoginUrl).Milliseconds()
	durationRaiTotal := durationRaiInitUrl + durationRaiStartUrl + durationRaiLoginUrl

	patternLogin = strings.Contains(string(bodyLoginBytes), "pw")

	if !patternLogin {
		allgood = false
	}

	if allgood {
		log.Printf("RAI,service=%s,ordertype=%s %s=%d,%s=%d,%s=%d,%s=%d,%s=%d %d\n",
			"rai",
			"login",
			"available", 1,
			"init", durationRaiInitUrl,
			"start", durationRaiStartUrl,
			"login", durationRaiLoginUrl,
			"total", durationRaiTotal,
			timeBegin.Unix())
		log.Printf("OK:  RAI is allRAIt. init: %dms + start: %dms + login: %dms = %dms\n", durationRaiInitUrl, durationRaiStartUrl, durationRaiLoginUrl, durationRaiTotal)
	} else {
		printFailMetricsAndExit("Connection to RAI failed")
	}
	os.Exit(0)
}

func printFailMetricsAndExit(errors ...string) {

	var statusCode int

	if httpResp != nil {
		statusCode = httpResp.StatusCode
		httpResp.Body.Close() // nolint:errcheck
	}

	errStr := "ERROR:"

	for _, err := range errors {
		errStr += " " + err
	}

	log.Printf("%s\n\n", errStr)

	log.Printf("RAI,service=%s %s=%d,%s=%d,%s=%d,%s=%d,%s=%d %d\n",
		"rai",
		"available", 0,
		"registered", 0,
		"duration", 0,
		"order", 0,
		"responsecode", statusCode,
		timeBegin.Unix())
	os.Exit(2)
}
