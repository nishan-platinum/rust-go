// Package isotest is a black-box multi-tenant isolation test. It calls this
// server over real HTTP (same path as real clients: JWT middleware -> registry
// -> gRPC -> Rust pool -> tenant DB) and checks that nothing crosses tenants.
//
// Phases:
//  1. Load: concurrent mixed reads/writes across all tenants at once. Every
//     response is checked against the tenant marker stored *inside* that
//     tenant's database. Optionally hot-swaps one tenant's pool mid-run.
//  2. Tokens: forged / expired / revoked / cross-tenant tokens must fail.
//  3. Sessions: missing / forged / expired sessions and CSRF must fail.
//  4. Subdomains: a tenant's portal session only works on its own subdomain;
//     unknown subdomains 404; admin pages are not reachable from tenant hosts.
//  5. Custom domains: served only once verified, only for their own tenant,
//     and they stop working the moment they are removed.
package isotest

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"slices"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/example/rust-go/go-api/internal/auth"
	"github.com/example/rust-go/go-api/internal/registry"
	"github.com/example/rust-go/go-api/internal/store"
)

type Runner struct {
	BaseURL  string
	Tokens   *auth.Tokens
	Sessions *auth.Sessions
	Registry *registry.Registry
	Store    *store.Store

	TenantSessions *auth.TenantSessions
	BaseDomain     string

	mu sync.Mutex // one run at a time
}

type Options struct {
	Concurrency       int
	RequestsPerTenant int
	Writes            bool
	HotSwap           bool
}

func (o *Options) Normalize() {
	o.Concurrency = min(max(o.Concurrency, 1), 256)
	o.RequestsPerTenant = min(max(o.RequestsPerTenant, 1), 5000)
}

type TenantResult struct {
	TenantID   string
	DBType     string
	Requests   int
	OK         int
	Errors     int
	Leaks      int
	Sessions   int // distinct DB sessions observed (shows pooling at work)
	P50, P95   time.Duration
	Max        time.Duration
	FirstError string

	latencies []time.Duration
	sessions  map[string]struct{}
}

type Check struct {
	Group  string
	Name   string
	Expect string
	Got    string
	Pass   bool
}

type Report struct {
	StartedAt     time.Time
	Duration      time.Duration
	Options       Options
	TotalRequests int
	RPS           float64
	Tenants       []*TenantResult
	Checks        []Check
	TotalLeaks    int
	Leaks         []string // distinct leak descriptions with counts
	Pass          bool
	Error         string
}

func (r *Report) FailedChecks() int {
	n := 0
	for _, c := range r.Checks {
		if !c.Pass {
			n++
		}
	}
	return n
}

var ErrBusy = fmt.Errorf("an isolation run is already in progress")

func (rn *Runner) Run(ctx context.Context, opts Options, adminID int64) (*Report, error) {
	if !rn.mu.TryLock() {
		return nil, ErrBusy
	}
	defer rn.mu.Unlock()
	opts.Normalize()

	rep := &Report{StartedAt: time.Now(), Options: opts}
	var tenants []store.Tenant
	for _, t := range rn.Registry.All() {
		if t.Enabled {
			tenants = append(tenants, t)
		}
	}
	if len(tenants) == 0 {
		rep.Error = "no enabled tenants"
		return rep, nil
	}

	client := &http.Client{
		Timeout: 30 * time.Second,
		Transport: &http.Transport{
			MaxIdleConns:        opts.Concurrency * 2,
			MaxIdleConnsPerHost: opts.Concurrency * 2,
		},
		// Session checks need to see redirects, not follow them.
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
	}
	defer client.CloseIdleConnections()

	rn.loadPhase(ctx, client, tenants, opts, rep)
	rn.tokenPhase(ctx, client, tenants, rep)
	rn.sessionPhase(ctx, client, adminID, rep)
	rn.portalPhase(ctx, client, tenants, adminID, rep)
	rn.domainPhase(ctx, client, tenants, rep)

	rep.Duration = time.Since(rep.StartedAt)
	rep.Pass = len(rep.Leaks) == 0 && rep.FailedChecks() == 0
	for _, tr := range rep.Tenants {
		if tr.Errors > 0 || tr.Leaks > 0 {
			rep.Pass = false
		}
	}
	rn.Store.Audit(ctx, "isotest", "isolation_run", "",
		fmt.Sprintf("pass=%v requests=%d leaks=%d failed_checks=%d", rep.Pass, rep.TotalRequests, rep.TotalLeaks, rep.FailedChecks()))
	return rep, nil
}

// ---- phase 1: concurrent load ---------------------------------------------

type job struct {
	tenant store.Tenant
	op     string
	token  string
}

type outcome struct {
	tenantID  string
	latency   time.Duration
	err       string
	leak      string
	sessionID string
}

func (rn *Runner) loadPhase(ctx context.Context, c *http.Client, tenants []store.Tenant, opts Options, rep *Report) {
	results := map[string]*TenantResult{}
	tokens := map[string]string{}
	leakCounts := map[string]int{}
	for _, t := range tenants {
		tok, err := rn.Tokens.Mint(t.ID, t.TokenVersion)
		if err != nil {
			rep.Error = "mint token: " + err.Error()
			return
		}
		tokens[t.ID] = tok
		results[t.ID] = &TenantResult{TenantID: t.ID, DBType: t.DBType, sessions: map[string]struct{}{}}
	}

	ops := []string{"whoami", "whoami", "list"}
	if opts.Writes {
		ops = []string{"whoami", "write", "list", "whoami"}
	}
	// Interleave tenants so every database is under load at the same moment.
	var jobs []job
	for i := range opts.RequestsPerTenant {
		for _, t := range tenants {
			jobs = append(jobs, job{tenant: t, op: ops[i%len(ops)], token: tokens[t.ID]})
		}
	}

	jobCh := make(chan job)
	outCh := make(chan outcome, opts.Concurrency)
	var wg sync.WaitGroup
	for range opts.Concurrency {
		wg.Go(func() {
			for j := range jobCh {
				outCh <- rn.do(ctx, c, j)
			}
		})
	}

	start := time.Now()
	swapAt := len(jobs) / 2
	var swapCheck *Check
	go func() {
		defer close(jobCh)
		for i, j := range jobs {
			if opts.HotSwap && i == swapAt {
				c := rn.hotSwap(ctx, tenants[0])
				swapCheck = &c
			}
			select {
			case jobCh <- j:
			case <-ctx.Done():
				return
			}
		}
	}()
	go func() { wg.Wait(); close(outCh) }()

	for o := range outCh {
		tr := results[o.tenantID]
		tr.Requests++
		tr.latencies = append(tr.latencies, o.latency)
		if o.sessionID != "" {
			tr.sessions[o.sessionID] = struct{}{}
		}
		switch {
		case o.leak != "":
			tr.Leaks++
			leakCounts[o.leak]++
		case o.err != "":
			tr.Errors++
			if tr.FirstError == "" {
				tr.FirstError = o.err
			}
		default:
			tr.OK++
		}
	}
	elapsed := time.Since(start)
	// Safe: the dispatcher finished before outCh was closed.
	if swapCheck != nil {
		rep.Checks = append(rep.Checks, *swapCheck)
	}

	for _, t := range tenants {
		tr := results[t.ID]
		slices.Sort(tr.latencies)
		if n := len(tr.latencies); n > 0 {
			tr.P50 = tr.latencies[n/2]
			tr.P95 = tr.latencies[min(n-1, n*95/100)]
			tr.Max = tr.latencies[n-1]
		}
		tr.Sessions = len(tr.sessions)
		rep.TotalRequests += tr.Requests
		rep.TotalLeaks += tr.Leaks
		rep.Tenants = append(rep.Tenants, tr)
	}
	if elapsed > 0 {
		rep.RPS = float64(rep.TotalRequests) / elapsed.Seconds()
	}
	// Identical leaks are grouped so one systematic fault is one line.
	for msg, n := range leakCounts {
		rep.Leaks = append(rep.Leaks, fmt.Sprintf("%s (x%d)", msg, n))
	}
	sort.Strings(rep.Leaks)
}

// hotSwap bumps the tenant's config version (same connection details) while
// requests are in flight. The engine must swap pools with zero failed requests.
func (rn *Runner) hotSwap(ctx context.Context, t store.Tenant) Check {
	c := Check{Group: "pool", Name: fmt.Sprintf("hot pool swap under load (%s)", t.ID), Expect: "version bumped, no request errors"}
	cur, err := rn.Store.GetTenant(ctx, t.ID)
	if err == nil {
		var v int64
		v, err = rn.Store.UpdateTenantConn(ctx, cur)
		if err == nil {
			_, err = rn.Registry.Refresh(ctx, t.ID)
			c.Got = fmt.Sprintf("config v%d -> v%d", cur.ConfigVersion, v)
			c.Pass = true // request errors during the swap show up in the tenant row
		}
	}
	if err != nil {
		c.Got = err.Error()
	}
	return c
}

func (rn *Runner) do(ctx context.Context, c *http.Client, j job) outcome {
	o := outcome{tenantID: j.tenant.ID}
	url := fmt.Sprintf("%s/api/v1/tenants/%s/", rn.BaseURL, j.tenant.ID)
	var req *http.Request
	nonce := auth.RandomToken(9)
	switch j.op {
	case "whoami":
		req, _ = http.NewRequestWithContext(ctx, http.MethodGet, url+"whoami", nil)
	case "list":
		req, _ = http.NewRequestWithContext(ctx, http.MethodGet, url+"items?limit=20", nil)
	case "write":
		body, _ := json.Marshal(map[string]string{"name": "isotest " + j.tenant.ID, "nonce": nonce})
		req, _ = http.NewRequestWithContext(ctx, http.MethodPost, url+"items", bytes.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
	}
	req.Header.Set("Authorization", "Bearer "+j.token)

	start := time.Now()
	resp, err := c.Do(req)
	o.latency = time.Since(start)
	if err != nil {
		o.err = err.Error()
		return o
	}
	defer resp.Body.Close()
	data, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if resp.StatusCode >= 300 {
		o.err = fmt.Sprintf("%s: HTTP %d %s", j.op, resp.StatusCode, strings.TrimSpace(string(data)))
		return o
	}

	tid := j.tenant.ID
	switch j.op {
	case "whoami":
		var w struct {
			TenantID   string `json:"tenant_id"`
			Marker     string `json:"marker_tenant_id"`
			SessionID  string `json:"session_id"`
			SessionTag string `json:"session_tag"`
		}
		if err := json.Unmarshal(data, &w); err != nil {
			o.err = "whoami: bad json"
			return o
		}
		if w.SessionID != "" {
			o.sessionID = w.SessionID
		}
		switch {
		case w.TenantID != tid:
			o.leak = fmt.Sprintf("%s: response labelled tenant %q", tid, w.TenantID)
		case w.Marker != tid:
			o.leak = fmt.Sprintf("%s: served from database owned by %q", tid, w.Marker)
		case w.SessionTag != "" && w.SessionTag != tid:
			o.leak = fmt.Sprintf("%s: pooled DB session %s carried state from tenant %q", tid, w.SessionID, w.SessionTag)
		}
	case "write":
		var it struct {
			Owner string `json:"owner"`
			Nonce string `json:"nonce"`
		}
		if err := json.Unmarshal(data, &it); err != nil {
			o.err = "write: bad json"
			return o
		}
		if it.Owner != tid || it.Nonce != nonce {
			o.leak = fmt.Sprintf("%s: write returned owner=%q nonce match=%v", tid, it.Owner, it.Nonce == nonce)
		}
	case "list":
		var l struct {
			Items []struct {
				ID    string `json:"id"`
				Owner string `json:"owner"`
			} `json:"items"`
		}
		if err := json.Unmarshal(data, &l); err != nil {
			o.err = "list: bad json"
			return o
		}
		for _, it := range l.Items {
			if it.Owner != tid {
				o.leak = fmt.Sprintf("%s: item %s belongs to tenant %q", tid, it.ID, it.Owner)
				break
			}
		}
	}
	return o
}

// ---- phase 2: tokens ------------------------------------------------------

func (rn *Runner) tokenPhase(ctx context.Context, c *http.Client, tenants []store.Tenant, rep *Report) {
	for i, t := range tenants {
		url := fmt.Sprintf("%s/api/v1/tenants/%s/whoami", rn.BaseURL, t.ID)
		valid, _ := rn.Tokens.Mint(t.ID, t.TokenVersion)
		expired, _ := rn.Tokens.MintWith(t.ID, t.TokenVersion, time.Now().Add(-2*time.Hour), time.Hour, "tenant-api")
		wrongAud, _ := rn.Tokens.MintWith(t.ID, t.TokenVersion, time.Now(), time.Minute, "some-other-service")
		revoked, _ := rn.Tokens.Mint(t.ID, t.TokenVersion-1)
		otherKey, _ := auth.NewTokens([]byte(auth.RandomToken(32)), time.Minute).Mint(t.ID, t.TokenVersion)

		cases := []struct {
			name, token string
			want        int
		}{
			{"valid token (control)", valid, 200},
			{"no token", "", 401},
			{"garbage token", "not-a-jwt", 401},
			{"tampered signature", tamper(valid), 401},
			{"alg=none token", algNone(valid), 401},
			{"signed with wrong key", otherKey, 401},
			{"expired token", expired, 401},
			{"wrong audience", wrongAud, 401},
			{"revoked (old token version)", revoked, 401},
		}
		if len(tenants) > 1 {
			other := tenants[(i+1)%len(tenants)]
			stolen, _ := rn.Tokens.Mint(other.ID, other.TokenVersion)
			cases = append(cases, struct {
				name, token string
				want        int
			}{fmt.Sprintf("token of %s on %s", other.ID, t.ID), stolen, 403})
		}
		for _, tc := range cases {
			got := status(ctx, c, http.MethodGet, url, func(r *http.Request) {
				if tc.token != "" {
					r.Header.Set("Authorization", "Bearer "+tc.token)
				}
			})
			rep.Checks = append(rep.Checks, Check{
				Group: "token:" + t.ID, Name: tc.name,
				Expect: fmt.Sprint(tc.want), Got: got, Pass: got == fmt.Sprint(tc.want),
			})
		}
	}
}

// tamper flips one character in the signature segment.
func tamper(tok string) string {
	b := []byte(tok)
	last := len(b) - 2
	if b[last] == 'A' {
		b[last] = 'B'
	} else {
		b[last] = 'A'
	}
	return string(b)
}

// algNone re-encodes the token's claims under {"alg":"none"} with no signature.
func algNone(tok string) string {
	parts := strings.Split(tok, ".")
	hdr := base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"none","typ":"JWT"}`))
	if len(parts) < 2 {
		return hdr + ".."
	}
	return hdr + "." + parts[1] + "."
}

// ---- phase 3: admin sessions ----------------------------------------------

func (rn *Runner) sessionPhase(ctx context.Context, c *http.Client, adminID int64, rep *Report) {
	cookie := rn.Sessions.CookieName()
	add := func(name, expect, got string) {
		rep.Checks = append(rep.Checks, Check{Group: "session", Name: name, Expect: expect, Got: got, Pass: expect == got})
	}
	withCookie := func(v string) func(*http.Request) {
		return func(r *http.Request) { r.AddCookie(&http.Cookie{Name: cookie, Value: v}) }
	}
	dash := rn.BaseURL + "/"

	add("no session cookie -> redirect to login", "303", status(ctx, c, http.MethodGet, dash, nil))
	add("forged session cookie", "303", status(ctx, c, http.MethodGet, dash, withCookie(auth.RandomToken(32))))

	expired, err := rn.Sessions.Create(ctx, adminID, "isotest", "", time.Now().Add(-time.Minute))
	if err == nil {
		add("expired session", "303", status(ctx, c, http.MethodGet, dash, withCookie(expired)))
	}

	live, err := rn.Sessions.Create(ctx, adminID, "isotest", "", time.Now().Add(5*time.Minute))
	if err != nil {
		add("create test session", "ok", err.Error())
		return
	}
	sess, _ := rn.Sessions.Lookup(ctx, live)
	add("valid session", "200", status(ctx, c, http.MethodGet, dash, withCookie(live)))
	add("state change without CSRF token", "403", status(ctx, c, http.MethodPost, rn.BaseURL+"/logout", withCookie(live)))
	add("state change with wrong CSRF token", "403", status(ctx, c, http.MethodPost, rn.BaseURL+"/logout", func(r *http.Request) {
		withCookie(live)(r)
		r.Header.Set("X-CSRF-Token", auth.RandomToken(32))
	}))
	add("session still valid after rejected requests", "200", status(ctx, c, http.MethodGet, dash, withCookie(live)))
	add("logout with CSRF token", "303", status(ctx, c, http.MethodPost, rn.BaseURL+"/logout", func(r *http.Request) {
		withCookie(live)(r)
		r.Header.Set("X-CSRF-Token", sess.CSRFToken)
	}))
	add("session unusable after logout (server-side revoke)", "303", status(ctx, c, http.MethodGet, dash, withCookie(live)))
	add("tenant API rejects admin session cookie", "401",
		status(ctx, c, http.MethodGet, rn.BaseURL+"/api/v1/tenants/x/whoami", withCookie(live)))
}

func status(ctx context.Context, c *http.Client, method, url string, mod func(*http.Request)) string {
	req, err := http.NewRequestWithContext(ctx, method, url, nil)
	if err != nil {
		return err.Error()
	}
	if mod != nil {
		mod(req)
	}
	resp, err := c.Do(req)
	if err != nil {
		return err.Error()
	}
	io.Copy(io.Discard, resp.Body)
	resp.Body.Close()
	return fmt.Sprint(resp.StatusCode)
}

// ---- phase 4: subdomain portals --------------------------------------------

func (rn *Runner) portalPhase(ctx context.Context, c *http.Client, tenants []store.Tenant, adminID int64, rep *Report) {
	if rn.TenantSessions == nil || rn.BaseDomain == "" {
		return
	}
	tcookie := rn.TenantSessions.CookieName()
	acookie := rn.Sessions.CookieName()
	add := func(group, name, expect, got string) {
		rep.Checks = append(rep.Checks, Check{Group: group, Name: name, Expect: expect, Got: got, Pass: expect == got})
	}
	on := onHost
	// Each tenant's live address: its subdomain, or for own-domain-only
	// tenants their primary domain. Tenants still waiting for DNS are skipped.
	host := func(id string) string {
		if t, ok := rn.Registry.Get(id); ok && t.SubdomainEnabled {
			return id + "." + rn.BaseDomain
		}
		return rn.Registry.PrimaryDomain(id)
	}
	var live []store.Tenant
	for _, t := range tenants {
		if host(t.ID) != "" {
			live = append(live, t)
		}
	}
	tenants = live

	unknown := fmt.Sprintf("no-such-tenant-%d", time.Now().UnixNano())
	add("subdomain", "unknown subdomain", "404", status(ctx, c, http.MethodGet, rn.BaseURL+"/", on(unknown+"."+rn.BaseDomain)))

	adminRaw, err := rn.Sessions.Create(ctx, adminID, "isotest", "", time.Now().Add(2*time.Minute))
	if err != nil {
		add("subdomain", "create admin session", "ok", err.Error())
		return
	}

	for i, t := range tenants {
		g := "portal:" + t.ID
		sess := store.TenantSession{TenantID: t.ID, UserID: "isotest", Email: "isotest@" + t.ID, Name: "isotest", Role: "member"}
		raw, err := rn.TenantSessions.CreateUntil(ctx, sess, time.Now().Add(2*time.Minute))
		if err != nil {
			add(g, "create portal session", "ok", err.Error())
			continue
		}
		expired, _ := rn.TenantSessions.CreateUntil(ctx, sess, time.Now().Add(-time.Minute))
		mine := &http.Cookie{Name: tcookie, Value: raw}

		add(g, "own session on own address", "200", status(ctx, c, http.MethodGet, rn.BaseURL+"/", on(host(t.ID), mine)))
		add(g, "no session -> login", "303", status(ctx, c, http.MethodGet, rn.BaseURL+"/", on(host(t.ID))))
		add(g, "expired session", "303", status(ctx, c, http.MethodGet, rn.BaseURL+"/",
			on(host(t.ID), &http.Cookie{Name: tcookie, Value: expired})))
		add(g, "admin session used as tenant cookie", "303", status(ctx, c, http.MethodGet, rn.BaseURL+"/",
			on(host(t.ID), &http.Cookie{Name: tcookie, Value: adminRaw})))
		add(g, "admin console not reachable on tenant host", "404", status(ctx, c, http.MethodGet, rn.BaseURL+"/tenants",
			on(host(t.ID), &http.Cookie{Name: acookie, Value: adminRaw})))
		add(g, "tenant session used as admin cookie", "303", status(ctx, c, http.MethodGet, rn.BaseURL+"/",
			on("admin."+rn.BaseDomain, &http.Cookie{Name: acookie, Value: raw})))
		add(g, "write without CSRF token", "403", status(ctx, c, http.MethodPost, rn.BaseURL+"/items", on(host(t.ID), mine)))
		if len(tenants) > 1 {
			other := tenants[(i+1)%len(tenants)]
			add(g, fmt.Sprintf("%s session on %s address", t.ID, other.ID), "303",
				status(ctx, c, http.MethodGet, rn.BaseURL+"/", on(host(other.ID), mine)))
		}
		_ = rn.TenantSessions.Logout(ctx, raw)
	}
	_ = rn.Sessions.Logout(ctx, adminRaw)
}

// onHost sends a request to host (Host header) with the given cookies.
func onHost(host string, cookies ...*http.Cookie) func(*http.Request) {
	return func(r *http.Request) {
		r.Host = host
		for _, ck := range cookies {
			r.AddCookie(ck)
		}
	}
}

// ---- phase 5: custom domains --------------------------------------------------

func (rn *Runner) domainPhase(ctx context.Context, c *http.Client, tenants []store.Tenant, rep *Report) {
	if rn.TenantSessions == nil || len(tenants) == 0 {
		return
	}
	add := func(name, expect, got string) {
		rep.Checks = append(rep.Checks, Check{Group: "domain", Name: name, Expect: expect, Got: got, Pass: expect == got})
	}
	cookie := rn.TenantSessions.CookieName()
	session := func(t store.Tenant) *http.Cookie {
		raw, err := rn.TenantSessions.CreateUntil(ctx, store.TenantSession{
			TenantID: t.ID, UserID: "isotest", Email: "isotest@" + t.ID, Name: "isotest", Role: "member",
		}, time.Now().Add(2*time.Minute))
		if err != nil {
			return &http.Cookie{Name: cookie}
		}
		return &http.Cookie{Name: cookie, Value: raw}
	}
	get := func(host string, cookies ...*http.Cookie) string {
		return status(ctx, c, http.MethodGet, rn.BaseURL+"/", onHost(host, cookies...))
	}

	// Existing verified domains: own session works, another tenant's does not.
	verified, _ := rn.Store.AllVerifiedDomains(ctx)
	byID := map[string]store.Tenant{}
	for _, t := range tenants {
		byID[t.ID] = t
	}
	for _, d := range verified {
		t, ok := byID[d.TenantID]
		if !ok {
			continue
		}
		add(fmt.Sprintf("%s: own session (%s)", d.Domain, t.ID), "200", get(d.Domain, session(t)))
		for _, other := range tenants {
			if other.ID != t.ID {
				add(fmt.Sprintf("%s: %s session rejected", d.Domain, other.ID), "303", get(d.Domain, session(other)))
				break
			}
		}
	}

	// Subdomain switch: off means the subdomain is not served (own domain only).
	sub := func(t store.Tenant) string { return t.ID + "." + rn.BaseDomain }
	for _, d := range verified {
		t, ok := byID[d.TenantID]
		if !ok {
			continue
		}
		if !t.SubdomainEnabled {
			add(fmt.Sprintf("%s: subdomain off is not served", t.ID), "404", get(sub(t), session(t)))
			continue
		}
		// Temporarily switch it off, then back on.
		_ = rn.Store.SetSubdomainEnabled(ctx, t.ID, false)
		_, _ = rn.Registry.Refresh(ctx, t.ID)
		add(fmt.Sprintf("%s: subdomain switched off -> not served", t.ID), "404", get(sub(t), session(t)))
		add(fmt.Sprintf("%s: own domain still served", t.ID), "200", get(d.Domain, session(t)))
		_ = rn.Store.SetSubdomainEnabled(context.WithoutCancel(ctx), t.ID, true)
		_, _ = rn.Registry.Refresh(context.WithoutCancel(ctx), t.ID)
		add(fmt.Sprintf("%s: subdomain switched on -> served", t.ID), "200", get(sub(t), session(t)))
		break
	}

	// Temporary domains on the first tenant: pending is not served; removing a
	// verified one stops it immediately.
	t := tenants[0]
	stamp := time.Now().UnixNano()
	pending := fmt.Sprintf("isotest-pending-%d.example.test", stamp)
	live := fmt.Sprintf("isotest-live-%d.example.test", stamp)
	defer func() {
		_ = rn.Store.DeleteDomain(context.WithoutCancel(ctx), t.ID, pending)
		_ = rn.Store.DeleteDomain(context.WithoutCancel(ctx), t.ID, live)
		_ = rn.Registry.ReloadDomains(context.WithoutCancel(ctx))
	}()
	mine := session(t)
	if err := rn.Store.AddDomain(ctx, t.ID, pending, auth.RandomToken(9)); err == nil {
		_ = rn.Registry.ReloadDomains(ctx)
		add("unverified domain is not served", "404", get(pending, mine))
	}
	if err := rn.Store.AddDomain(ctx, t.ID, live, auth.RandomToken(9)); err == nil {
		_ = rn.Store.MarkDomainVerified(ctx, t.ID, live)
		_ = rn.Registry.ReloadDomains(ctx)
		add("verified domain is served", "200", get(live, mine))
		_ = rn.Store.DeleteDomain(ctx, t.ID, live)
		_ = rn.Registry.ReloadDomains(ctx)
		add("removed domain stops immediately", "404", get(live, mine))
	}

	ask := func(domain string) string {
		return status(ctx, c, http.MethodGet, rn.BaseURL+"/internal/tls-ask?domain="+domain, nil)
	}
	if len(verified) > 0 {
		add("TLS certificate allowed for verified domain", "200", ask(verified[0].Domain))
	}
	add("TLS certificate refused for unknown domain", "404", ask("evil-"+fmt.Sprint(stamp)+".example.com"))
	add("TLS certificate refused for unverified domain", "404", ask(pending))
}
