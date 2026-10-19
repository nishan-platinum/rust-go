// Command isotest runs the multi-tenant isolation test against a running
// server and exits non-zero on failure, for CI pipelines.
//
//	go run ./cmd/isotest -base http://127.0.0.1:8080 -user admin -pass admin12345
package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"os"
	"regexp"
	"strconv"
	"strings"
	"time"
)

type report struct {
	Duration      time.Duration
	TotalRequests int
	RPS           float64
	TotalLeaks    int
	Pass          bool
	Error         string
	Leaks         []string
	Tenants       []struct {
		TenantID, DBType, FirstError string
		Requests, OK, Errors, Leaks  int
		P50, P95                     time.Duration
	}
	Checks []struct {
		Group, Name, Expect, Got string
		Pass                     bool
	}
}

var csrfRe = regexp.MustCompile(`<meta name="csrf-token" content="([^"]+)">`)

func main() {
	base := flag.String("base", "http://127.0.0.1:8080", "server base URL")
	user := flag.String("user", envOr("ADMIN_USERNAME", "admin"), "admin username")
	pass := flag.String("pass", os.Getenv("ADMIN_PASSWORD"), "admin password (or ADMIN_PASSWORD)")
	conc := flag.Int("c", 32, "concurrent workers")
	reqs := flag.Int("n", 200, "requests per tenant")
	writes := flag.Bool("writes", true, "include writes")
	hotswap := flag.Bool("hotswap", true, "hot-swap one tenant's pool mid-run")
	flag.Parse()

	jar, _ := cookiejar.New(nil)
	c := &http.Client{Jar: jar, Timeout: 10 * time.Minute}

	resp, err := c.PostForm(*base+"/login", url.Values{"username": {*user}, "password": {*pass}})
	must(err)
	body := readAll(resp)
	m := csrfRe.FindSubmatch(body)
	if resp.StatusCode != 200 || m == nil {
		fail("login failed (HTTP %d)", resp.StatusCode)
	}

	form := url.Values{
		"concurrency": {strconv.Itoa(*conc)},
		"requests":    {strconv.Itoa(*reqs)},
	}
	if *writes {
		form.Set("writes", "on")
	}
	if *hotswap {
		form.Set("hotswap", "on")
	}
	req, _ := http.NewRequest(http.MethodPost, *base+"/isolation/run", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Accept", "application/json")
	req.Header.Set("X-CSRF-Token", string(m[1]))
	resp, err = c.Do(req)
	must(err)
	body = readAll(resp)
	if resp.StatusCode != 200 {
		fail("run failed: HTTP %d %s", resp.StatusCode, body)
	}
	var r report
	must(json.Unmarshal(body, &r))
	if r.Error != "" {
		fail("run error: %s", r.Error)
	}

	fmt.Printf("%-10s %-9s %8s %8s %7s %6s %10s %10s\n", "TENANT", "DB", "REQS", "OK", "ERRORS", "LEAKS", "P50", "P95")
	for _, t := range r.Tenants {
		fmt.Printf("%-10s %-9s %8d %8d %7d %6d %10s %10s\n", t.TenantID, t.DBType, t.Requests, t.OK, t.Errors, t.Leaks,
			t.P50.Round(time.Microsecond*100), t.P95.Round(time.Microsecond*100))
		if t.FirstError != "" {
			fmt.Printf("    first error: %s\n", t.FirstError)
		}
	}
	failed := 0
	for _, ch := range r.Checks {
		if !ch.Pass {
			failed++
			fmt.Printf("FAIL [%s] %s: expected %s, got %s\n", ch.Group, ch.Name, ch.Expect, ch.Got)
		}
	}
	for _, l := range r.Leaks {
		fmt.Println("LEAK", l)
	}
	fmt.Printf("\n%d requests in %s (%.0f req/s), %d/%d security checks passed, %d leaks\n",
		r.TotalRequests, r.Duration.Round(time.Millisecond), r.RPS, len(r.Checks)-failed, len(r.Checks), r.TotalLeaks)
	if !r.Pass {
		fmt.Println("RESULT: FAIL")
		os.Exit(1)
	}
	fmt.Println("RESULT: PASS")
}

func envOr(k, d string) string {
	if v := os.Getenv(k); v != "" {
		return v
	}
	return d
}

func readAll(r *http.Response) []byte {
	defer r.Body.Close()
	b, _ := io.ReadAll(r.Body)
	return b
}

func must(err error) {
	if err != nil {
		fail("%v", err)
	}
}

func fail(format string, a ...any) {
	fmt.Fprintf(os.Stderr, "isotest: "+format+"\n", a...)
	os.Exit(2)
}
