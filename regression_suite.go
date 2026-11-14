package main

import (
	"bytes"
	"encoding/csv"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"
)

type RetestCase struct {
	ID          string
	Description string
	Expected    string
}

type TestResult struct {
	TestID      string
	Category    string
	Description string
	Expected    string
	Actual      string
	Passed      bool
}

type LoginResponse struct {
	Authentication struct {
		Token string `json:"token"`
	} `json:"authentication"`
}

func main() {
	target := flag.String("target", "http://localhost:3000", "Base URL of the local demo site")
	csvPath := flag.String("csv", "web_retest_cases.csv", "Path to web_retest_cases.csv")
	reportPath := flag.String("out", "security_regression_report.md", "Output Markdown report path")
	flag.Parse()

	baseURL := strings.TrimRight(*target, "/")
	cases, err := loadRetestCases(*csvPath)
	if err != nil {
		fmt.Printf("[!] Failed to load CSV (%s): %v\n", *csvPath, err)
		os.Exit(1)
	}

	client := &http.Client{
		Timeout: 10 * time.Second,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}

	fmt.Printf("=== Running Security Regression Suite against %s ===\n\n", baseURL)

	var results []TestResult

	// 1. Execute CSV Retest Cases
	for _, tc := range cases {
		switch tc.ID {
		case "WEB-T01":
			results = append(results, runWEBT01(client, baseURL, tc))
		case "WEB-T02":
			results = append(results, runWEBT02(client, baseURL, tc))
		case "WEB-T03":
			results = append(results, runWEBT03(client, baseURL, tc))
		case "WEB-T04":
			results = append(results, runWEBT04(client, baseURL, tc))
		}
	}

	// 2. Execute Build Requirement Checks: Security Headers & Login Cookie Flags
	results = append(results, runHeaderChecks(client, baseURL)...)
	results = append(results, runCookieFlagChecks(client, baseURL)...)

	failedCount := 0
	for _, r := range results {
		status := "PASS"
		if !r.Passed {
			status = "FAIL"
			failedCount++
		}
		fmt.Printf("[%s] %-10s | %-18s | %s\n", status, r.TestID, r.Category, r.Actual)
	}

	if err := generateMarkdownReport(*reportPath, baseURL, results); err != nil {
		fmt.Printf("\n[!] Error writing report: %v\n", err)
		os.Exit(1)
	}

	fmt.Printf("\nReport saved to %s (%d passed, %d failed)\n", *reportPath, len(results)-failedCount, failedCount)
	if failedCount > 0 {
		os.Exit(1)
	}
}

func loadRetestCases(path string) ([]RetestCase, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	rows, err := csv.NewReader(f).ReadAll()
	if err != nil {
		return nil, err
	}

	var cases []RetestCase
	for i, row := range rows {
		if i == 0 || len(row) < 3 {
			continue
		}
		cases = append(cases, RetestCase{
			ID:          strings.TrimSpace(row[0]),
			Description: strings.TrimSpace(row[1]),
			Expected:    strings.TrimSpace(row[2]),
		})
	}
	return cases, nil
}

// registerAndLogin creates a fresh customer account and returns both its JWT and any Set-Cookie headers from login
func registerAndLogin(client *http.Client, baseURL string) (string, []*http.Cookie, error) {
	email := fmt.Sprintf("regtest_%d@local.test", time.Now().UnixNano())
	password := "TestPass#2026!"

	regPayload := map[string]interface{}{
		"email":          email,
		"password":       password,
		"passwordRepeat": password,
		"securityQuestion": map[string]interface{}{
			"id":       1,
			"question": "Your eldest siblings middle name?",
		},
		"securityAnswer": "RegressionTest",
	}
	regBody, _ := json.Marshal(regPayload)
	resp, err := client.Post(baseURL+"/api/Users/", "application/json", bytes.NewBuffer(regBody))
	if err != nil {
		return "", nil, err
	}
	resp.Body.Close()

	loginBody, _ := json.Marshal(map[string]string{
		"email":    email,
		"password": password,
	})
	loginResp, err := client.Post(baseURL+"/rest/user/login", "application/json", bytes.NewBuffer(loginBody))
	if err != nil {
		return "", nil, err
	}
	defer loginResp.Body.Close()

	cookies := loginResp.Cookies()

	var parsed LoginResponse
	if err := json.NewDecoder(loginResp.Body).Decode(&parsed); err != nil {
		return "", cookies, err
	}
	if parsed.Authentication.Token == "" {
		return "", cookies, fmt.Errorf("empty authentication token returned")
	}
	return parsed.Authentication.Token, cookies, nil
}

// WEB-T01: Input validation check with 500-character username using session token cookie
func runWEBT01(client *http.Client, baseURL string, tc RetestCase) TestResult {
	token, _, err := registerAndLogin(client, baseURL)
	if err != nil {
		return TestResult{tc.ID, "Input Validation", tc.Description, tc.Expected, "Auth setup failed: " + err.Error(), false}
	}

	form := url.Values{}
	form.Set("username", strings.Repeat("a", 500))

	req, _ := http.NewRequest(http.MethodPost, baseURL+"/profile", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.AddCookie(&http.Cookie{Name: "token", Value: token})

	resp, err := client.Do(req)
	if err != nil {
		return TestResult{tc.ID, "Input Validation", tc.Description, tc.Expected, "Request error: " + err.Error(), false}
	}
	defer resp.Body.Close()

	bodyBytes, _ := io.ReadAll(resp.Body)
	bodyStr := string(bodyBytes)
	hasStack := strings.Contains(bodyStr, "Error:") || strings.Contains(bodyStr, "at ")

	passed := resp.StatusCode == http.StatusBadRequest && !hasStack
	actual := fmt.Sprintf("HTTP %d (500-char payload accepted=%v, stack_trace=%v)", resp.StatusCode, resp.StatusCode == 200 || resp.StatusCode == 302, hasStack)
	return TestResult{tc.ID, "Input Validation", tc.Description, tc.Expected, actual, passed}
}

// WEB-T02: Output encoding & DOM sanitization check on frontend Angular bundle
func runWEBT02(client *http.Client, baseURL string, tc RetestCase) TestResult {
	resp, err := client.Get(baseURL + "/main.js")
	if err != nil {
		return TestResult{tc.ID, "Output Encoding", tc.Description, tc.Expected, "Request error: " + err.Error(), false}
	}
	defer resp.Body.Close()

	bodyBytes, _ := io.ReadAll(resp.Body)
	unsafeDOMSink := strings.Contains(string(bodyBytes), "bypassSecurityTrustHtml")

	passed := !unsafeDOMSink
	actual := fmt.Sprintf("HTTP %d (/main.js bypassSecurityTrustHtml_sink=%v)", resp.StatusCode, unsafeDOMSink)
	return TestResult{tc.ID, "Output Encoding", tc.Description, tc.Expected, actual, passed}
}

// WEB-T03: Access-control check using standard customer (viewer) role against admin API
func runWEBT03(client *http.Client, baseURL string, tc RetestCase) TestResult {
	token, _, err := registerAndLogin(client, baseURL)
	if err != nil {
		return TestResult{tc.ID, "Access Control", tc.Description, tc.Expected, "Auth setup failed: " + err.Error(), false}
	}

	req, _ := http.NewRequest(http.MethodGet, baseURL+"/api/Users", nil)
	req.Header.Set("Authorization", "Bearer "+token)

	resp, err := client.Do(req)
	if err != nil {
		return TestResult{tc.ID, "Access Control", tc.Description, tc.Expected, "Request error: " + err.Error(), false}
	}
	defer resp.Body.Close()

	bodyBytes, _ := io.ReadAll(resp.Body)
	passed := resp.StatusCode == http.StatusUnauthorized || resp.StatusCode == http.StatusForbidden
	actual := fmt.Sprintf("HTTP %d (response_bytes=%d)", resp.StatusCode, len(bodyBytes))
	return TestResult{tc.ID, "Access Control", tc.Description, tc.Expected, actual, passed}
}

// WEB-T04: Public health/version endpoint information exposure check
func runWEBT04(client *http.Client, baseURL string, tc RetestCase) TestResult {
	resp, err := client.Get(baseURL + "/rest/admin/application-version")
	if err != nil {
		return TestResult{tc.ID, "Info Exposure", tc.Description, tc.Expected, "Request error: " + err.Error(), false}
	}
	defer resp.Body.Close()

	bodyBytes, _ := io.ReadAll(resp.Body)
	bodyStr := strings.TrimSpace(string(bodyBytes))

	exposesVersion := strings.Contains(strings.ToLower(bodyStr), "version")
	passed := !exposesVersion
	actual := fmt.Sprintf("HTTP %d, payload=%s", resp.StatusCode, bodyStr)
	return TestResult{tc.ID, "Info Exposure", tc.Description, tc.Expected, actual, passed}
}

// Build Requirement: Security Headers Audit
func runHeaderChecks(client *http.Client, baseURL string) []TestResult {
	resp, err := client.Get(baseURL + "/")
	if err != nil {
		return []TestResult{{
			TestID: "HDR-00", Category: "Security Headers",
			Description: "Fetch root document headers", Expected: "HTTP 200 with security headers",
			Actual: "Request error: " + err.Error(), Passed: false,
		}}
	}
	defer resp.Body.Close()

	requiredHeaders := []struct {
		id       string
		header   string
		expected string
	}{
		{"HDR-01", "Content-Security-Policy", "Restrictive CSP header present"},
		{"HDR-02", "X-Content-Type-Options", "nosniff directive present"},
		{"HDR-03", "X-Frame-Options", "DENY or SAMEORIGIN present"},
		{"HDR-04", "Referrer-Policy", "Strict referrer policy header present"},
	}

	var out []TestResult
	for _, h := range requiredHeaders {
		val := resp.Header.Get(h.header)
		passed := val != ""
		if h.header == "X-Content-Type-Options" {
			passed = strings.EqualFold(val, "nosniff")
		}
		actual := val
		if actual == "" {
			actual = "Missing header"
		}
		out = append(out, TestResult{
			TestID:      h.id,
			Category:    "Security Headers",
			Description: "Verify " + h.header + " response header",
			Expected:    h.expected,
			Actual:      actual,
			Passed:      passed,
		})
	}
	return out
}

// Build Requirement: Login Cookie Security Flags Audit (HttpOnly, Secure, SameSite)
func runCookieFlagChecks(client *http.Client, baseURL string) []TestResult {
	_, cookies, err := registerAndLogin(client, baseURL)
	if err != nil {
		return []TestResult{{
			TestID: "CK-01", Category: "Cookie Flags",
			Description: "Inspect Set-Cookie attributes on POST /rest/user/login",
			Expected:    "Session cookies set with HttpOnly, Secure, and explicit SameSite flags",
			Actual:      "Login request error: " + err.Error(), Passed: false,
		}}
	}

	if len(cookies) == 0 {
		return []TestResult{{
			TestID:      "CK-01",
			Category:    "Cookie Flags",
			Description: "Inspect Set-Cookie attributes on POST /rest/user/login",
			Expected:    "Session cookies set with HttpOnly, Secure, and explicit SameSite flags",
			Actual:      "No Set-Cookie headers issued on login (token stored client-side only)",
			Passed:      true,
		}}
	}

	var out []TestResult
	for i, c := range cookies {
		hasSameSite := c.SameSite != http.SameSiteDefaultMode
		passed := c.HttpOnly && c.Secure && hasSameSite
		actual := fmt.Sprintf("Cookie=%s (HttpOnly=%v, Secure=%v, SameSite=%v)", c.Name, c.HttpOnly, c.Secure, c.SameSite)
		out = append(out, TestResult{
			TestID:      fmt.Sprintf("CK-%02d", i+1),
			Category:    "Cookie Flags",
			Description: "Verify security flags on login cookie " + c.Name,
			Expected:    "HttpOnly=true, Secure=true, and explicit SameSite policy",
			Actual:      actual,
			Passed:      passed,
		})
	}
	return out
}

func generateMarkdownReport(path, target string, results []TestResult) error {
	var sb strings.Builder
	sb.WriteString("# Web Security Regression Suite Report\n\n")
	sb.WriteString(fmt.Sprintf("- **Target Environment:** `%s`\n", target))
	sb.WriteString(fmt.Sprintf("- **Execution Timestamp:** `%s`\n\n", time.Now().Format(time.RFC3339)))
	sb.WriteString("| Test ID | Category | Test Case | Expected Secure Result | Observed Result | Status |\n")
	sb.WriteString("| :--- | :--- | :--- | :--- | :--- | :--- |\n")

	for _, r := range results {
		status := "PASS"
		if !r.Passed {
			status = "**FAIL**"
		}
		sb.WriteString(fmt.Sprintf("| %s | %s | %s | %s | `%s` | %s |\n",
			r.TestID, r.Category, r.Description, r.Expected, r.Actual, status))
	}

	return os.WriteFile(path, []byte(sb.String()), 0644)
}
