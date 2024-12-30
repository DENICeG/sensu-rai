package main

import (
	"crypto/tls"
	"errors"
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

type RequestDurations struct {
	InitUrl  int64
	StartUrl int64
	LoginUrl int64
	Total    int64
}

var (
	timeBegin   = time.Now()
	httpResp    *http.Response
	raiStartUrl string
	raiInitUrl  string
	raiLoginUrl string
	raiRegacc   string
	raiPassword string
	rai2fa      string

	errConnectionToRAIFailed = errors.New("Connection to RAI failed")
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
	RunDefaultWithJarWrapper(raiRegacc, raiPassword, rai2fa)
}

func RunDefaultWithJarWrapper(account, password, twofa string) {
	durations, err := RunDefaultWithJar(account, password, twofa)
	if err != nil {
		printFailMetricsAndExit(err.Error())
	}

	// TODO: warum loggen wir hier die gleichen Zeiten 2x?
	log.Printf("RAI,service=%s,ordertype=%s %s=%d,%s=%d,%s=%d,%s=%d,%s=%d %d\n",
		"rai",
		"login",
		"available", 1,
		"init", durations.InitUrl,
		"start", durations.StartUrl,
		"login", durations.LoginUrl,
		"total", durations.Total,
		timeBegin.Unix())
	log.Printf("OK:  RAI is allRAIt. init: %dms + start: %dms + login: %dms = %dms\n",
		durations.InitUrl,
		durations.StartUrl,
		durations.LoginUrl,
		durations.Total)

	os.Exit(0)
}

func RunDefaultWithJar(account, password, twofa string) (RequestDurations, error) {
	log.SetOutput(os.Stderr)
	log.SetPrefix("UTC | ")
	log.SetFlags(log.Ldate | log.Ltime | log.LUTC)

	patternStart, patternInit, patternLogin := false, false, false

	jar, err := cookiejar.New(&cookiejar.Options{PublicSuffixList: publicsuffix.List})
	if err != nil {
		return RequestDurations{}, err
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
	reqStart, _ := http.NewRequest(http.MethodGet, raiStartUrl, nil)
	respStart, err := UserClient.Do(reqStart)
	if err != nil {
		return RequestDurations{}, err
	}

	bodyStartBytes, err := io.ReadAll(respStart.Body)
	if err != nil {
		return RequestDurations{}, err
	}

	timeFirstRaiStartUrlBodyComplete := time.Now()
	durationRaiStartUrl := timeFirstRaiStartUrlBodyComplete.Sub(timeFirstRaiStartUrl).Milliseconds()

	patternStart = strings.Contains(string(bodyStartBytes), "RegAcc-Profil-Pflege")
	if !patternStart {
		return RequestDurations{}, errConnectionToRAIFailed
	}

	urlRaiStart, err := url.Parse(raiStartUrl)
	if err != nil {
		return RequestDurations{}, err
	}

	for _, cookie := range jar.Cookies(urlRaiStart) {

		if cookie.Name == "JSESSIONID" {
			startcookie = cookie
		}
	}

	timeRaiInitUrl := time.Now()

	reqInit, _ := http.NewRequest(http.MethodGet, raiInitUrl, nil)
	reqInit.AddCookie(startcookie)
	respInit, err := UserClient.Do(reqInit)
	if err != nil {
		return RequestDurations{}, err
	}

	bodyInitBytes, err := io.ReadAll(respInit.Body)
	if err != nil {
		return RequestDurations{}, err
	}

	timeRaiInitUrlComplete := time.Now()
	durationRaiInitUrl := timeRaiInitUrlComplete.Sub(timeRaiInitUrl).Milliseconds()

	patternInit = strings.Contains(string(bodyInitBytes), "j_security_check")

	if !patternInit {
		return RequestDurations{}, errConnectionToRAIFailed
	}

	postString := fmt.Sprintf("j_password=%s&j_username=%s&j_2fa=%s&login=submit", password, account, twofa)

	postBody := strings.NewReader(postString)

	timeRaiLoginUrl := time.Now()

	httpPostReq, err := http.NewRequest(http.MethodPost, raiLoginUrl, postBody)
	if err != nil {
		return RequestDurations{}, err
	}

	httpPostReq.Header.Add("Content-Type", "application/x-www-form-urlencoded")

	respLogin, err := UserClient.Do(httpPostReq)
	if err != nil {
		return RequestDurations{}, err
	}

	bodyLoginBytes, err := io.ReadAll(respLogin.Body)
	if err != nil {
		return RequestDurations{}, err
	}

	timeRaiLoginUrlComplete := time.Now()
	durationRaiLoginUrl := timeRaiLoginUrlComplete.Sub(timeRaiLoginUrl).Milliseconds()
	durationRaiTotal := durationRaiInitUrl + durationRaiStartUrl + durationRaiLoginUrl

	patternLogin = strings.Contains(string(bodyLoginBytes), "pw")

	if !patternLogin {
		return RequestDurations{}, errConnectionToRAIFailed
	}

	return RequestDurations{
		InitUrl:  durationRaiInitUrl,
		StartUrl: durationRaiStartUrl,
		LoginUrl: durationRaiLoginUrl,
		Total:    durationRaiTotal,
	}, nil
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
