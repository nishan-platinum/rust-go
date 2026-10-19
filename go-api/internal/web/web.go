// Package web serves the SciCom CX admin console (admin.<base domain>) and
// the tenant portals (<tenant>.<base domain>): Go templates + HTMX.
package web

import (
	"context"
	"embed"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"html/template"
	"io/fs"
	"log/slog"
	"net/http"
	"strings"
	"sync"
	"time"

	pb "github.com/example/rust-go/go-api/gen/dbengine/v1"
	"github.com/example/rust-go/go-api/internal/auth"
	"github.com/example/rust-go/go-api/internal/domains"
	"github.com/example/rust-go/go-api/internal/engine"
	"github.com/example/rust-go/go-api/internal/httpx"
	"github.com/example/rust-go/go-api/internal/isotest"
	"github.com/example/rust-go/go-api/internal/provision"
	"github.com/example/rust-go/go-api/internal/registry"
	"github.com/example/rust-go/go-api/internal/store"
)

//go:embed templates static
var assets embed.FS

type Web struct {
	Store     *store.Store
	Registry  *registry.Registry
	Engine    *engine.Client
	Sessions  *auth.Sessions
	Tokens    *auth.Tokens
	Isolation *isotest.Runner
	LoginRL   *auth.RateLimiter
	Provision *provision.Service
	Domains   *domains.Service

	TenantSessions *auth.TenantSessions
	TenantURL      func(id string) string
	HostURL        func(host string) string
	BaseDomain     string

	pages map[string]*template.Template
}

func staticHandler() http.Handler {
	static, _ := fs.Sub(assets, "static")
	return http.StripPrefix("/static/", http.FileServerFS(static))
}

// Register mounts the admin console. Templates are parsed once here.
func (wb *Web) Register(mux *http.ServeMux) error {
	if err := wb.parseTemplates(); err != nil {
		return err
	}
	mux.Handle("GET /static/", staticHandler())

	mux.HandleFunc("GET /login", wb.loginPage)
	mux.HandleFunc("POST /login", wb.login)

	authed := func(pattern string, h http.HandlerFunc) { mux.Handle(pattern, wb.requireSession(h)) }
	authed("POST /logout", wb.logout)
	authed("GET /{$}", wb.dashboard)
	authed("GET /ui/health", wb.healthPartial)
	authed("GET /ui/pools", wb.poolsPartial)

	authed("GET /tenants", wb.tenantsPage)
	authed("GET /tenants/new", wb.newTenantPage)
	authed("GET /tenants/check", wb.checkSubdomain)
	authed("POST /tenants", wb.createTenant)
	authed("POST /tenants/test", wb.testConnection)
	authed("GET /tenants/{id}/edit", wb.editTenantPage)
	authed("POST /tenants/{id}", wb.updateTenant)
	authed("POST /tenants/{id}/health", wb.tenantHealth)
	authed("POST /tenants/{id}/provision", wb.reprovision)
	authed("POST /tenants/{id}/revoke", wb.revokeTokens)
	authed("POST /tenants/{id}/token", wb.mintToken)
	authed("POST /tenants/{id}/toggle", wb.toggleTenant)
	authed("GET /tenants/{id}/delete", wb.deleteTenantPage)
	authed("POST /tenants/{id}/delete", wb.deleteTenant)

	authed("GET /tenants/{id}/domains", wb.domainsPage)
	authed("POST /tenants/{id}/domains", wb.addDomain)
	authed("POST /tenants/{id}/domains/{domain}/{action}", wb.domainAction)
	authed("POST /tenants/{id}/subdomain", wb.toggleSubdomain)

	authed("GET /servers", wb.serversPage)
	authed("POST /servers", wb.createServer)
	authed("POST /servers/{id}/test", wb.testServer)
	authed("POST /servers/{id}/default", wb.defaultServer)
	authed("POST /servers/{id}/delete", wb.deleteServer)

	authed("GET /isolation", wb.isolationPage)
	authed("POST /isolation/run", wb.runIsolation)
	authed("GET /audit", wb.auditPage)
	return nil
}

// ---- templates ------------------------------------------------------------

var funcs = template.FuncMap{
	"ms": func(d time.Duration) string {
		return fmt.Sprintf("%.1f ms", float64(d.Microseconds())/1000)
	},
	"secs": func(d time.Duration) string { return fmt.Sprintf("%.2fs", d.Seconds()) },
	"ago": func(t time.Time) string {
		d := time.Since(t).Round(time.Second)
		if d < time.Minute {
			return d.String() + " ago"
		}
		return t.Format("2006-01-02 15:04:05")
	},
	"unix":   func(s int64) string { return time.Unix(s, 0).Format("2006-01-02 15:04:05") },
	"dbname": func(t pb.DbType) string { return engine.DBTypeName(t) },
	"params": func(m map[string]string) string {
		var b strings.Builder
		for k, v := range m {
			fmt.Fprintf(&b, "%s=%s\n", k, v)
		}
		return b.String()
	},
	"pct": func(a, b int) string {
		if b == 0 {
			return "0%"
		}
		return fmt.Sprintf("%.1f%%", 100*float64(a)/float64(b))
	},
}

func (wb *Web) parseTemplates() error {
	fm := template.FuncMap{
		"tenantURL":     wb.TenantURL,
		"hostURL":       wb.HostURL,
		"tenantHost":    wb.tenantHost,
		"subdomain":     func(id string) string { return id + "." + wb.BaseDomain },
		"challengeName": domains.ChallengeName,
		"cnameTarget":   func() string { return wb.Domains.CNAMETarget() },
	}
	for k, v := range funcs {
		fm[k] = v
	}
	wb.pages = map[string]*template.Template{}
	admin := []string{"login", "dashboard", "tenants", "tenant_form", "tenant_new", "tenant_created",
		"tenant_delete", "tenant_domains", "servers", "isolation", "audit"}
	portal := []string{"portal_login", "portal_home", "portal_message"}
	for _, page := range append(admin, portal...) {
		files := []string{"templates/partials.html", "templates/" + page + ".html"}
		switch {
		case strings.HasPrefix(page, "portal_"):
			files = append(files, "templates/portal_layout.html")
		case page != "login":
			files = append(files, "templates/layout.html")
		}
		t, err := template.New(page).Funcs(fm).ParseFS(assets, files...)
		if err != nil {
			return fmt.Errorf("template %s: %w", page, err)
		}
		wb.pages[page] = t
	}
	return nil
}

// tenantHost is the address shown for a tenant: its primary custom domain,
// else its subdomain if that is on, else "" (still waiting for DNS).
func (wb *Web) tenantHost(id string) string {
	if d := wb.Registry.PrimaryDomain(id); d != "" {
		return d
	}
	if t, ok := wb.Registry.Get(id); ok && t.SubdomainEnabled {
		return id + "." + wb.BaseDomain
	}
	return ""
}

type flash struct{ Kind, Msg string }

// page data common to every page.
type pageData struct {
	Title   string
	Nav     string
	Session store.Session
	Flash   *flash
	Data    any
}

func (wb *Web) render(w http.ResponseWriter, r *http.Request, code int, page, nav string, data any) {
	pd := pageData{Title: nav, Nav: nav, Data: data, Flash: readFlash(w, r)}
	if s, ok := sessionFrom(r.Context()); ok {
		pd.Session = s
	}
	root := "layout"
	if page == "login" {
		root = "login"
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(code)
	if err := wb.pages[page].ExecuteTemplate(w, root, pd); err != nil {
		slog.Error("render", "page", page, "err", err)
	}
}

// partial renders a named block from partials.html (HTMX swaps).
func (wb *Web) partial(w http.ResponseWriter, name string, data any) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	if err := wb.pages["dashboard"].ExecuteTemplate(w, name, data); err != nil {
		slog.Error("render partial", "name", name, "err", err)
	}
}

func setFlash(w http.ResponseWriter, kind, msg string) {
	b, _ := json.Marshal(flash{kind, msg})
	http.SetCookie(w, &http.Cookie{Name: "flash", Value: base64.RawURLEncoding.EncodeToString(b),
		Path: "/", MaxAge: 30, HttpOnly: true, SameSite: http.SameSiteStrictMode})
}

func readFlash(w http.ResponseWriter, r *http.Request) *flash {
	c, err := r.Cookie("flash")
	if err != nil {
		return nil
	}
	http.SetCookie(w, &http.Cookie{Name: "flash", Path: "/", MaxAge: -1})
	b, err := base64.RawURLEncoding.DecodeString(c.Value)
	var f flash
	if err != nil || json.Unmarshal(b, &f) != nil {
		return nil
	}
	return &f
}

// ---- session middleware -----------------------------------------------------

type sessKey struct{}

func sessionFrom(ctx context.Context) (store.Session, bool) {
	s, ok := ctx.Value(sessKey{}).(store.Session)
	return s, ok
}

func actor(r *http.Request) string {
	s, _ := sessionFrom(r.Context())
	return "admin:" + s.Username
}

// requireSession authenticates the cookie and enforces CSRF on every
// state-changing request (header for HTMX, hidden field for plain forms).
func (wb *Web) requireSession(next http.HandlerFunc) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var raw string
		if c, err := r.Cookie(wb.Sessions.CookieName()); err == nil {
			raw = c.Value
		}
		sess, err := wb.Sessions.Lookup(r.Context(), raw)
		if err != nil {
			if !errors.Is(err, store.ErrNotFound) {
				slog.Error("session lookup", "err", err)
			}
			if raw != "" {
				wb.Sessions.ClearCookie(w)
			}
			if r.Header.Get("HX-Request") == "true" {
				w.Header().Set("HX-Redirect", "/login")
				w.WriteHeader(http.StatusUnauthorized)
				return
			}
			http.Redirect(w, r, "/login", http.StatusSeeOther)
			return
		}
		if !csrfOK(r, sess.CSRFToken) {
			slog.Warn("csrf check failed", "path", r.URL.Path, "admin", sess.Username, "request_id", httpx.RequestID(r.Context()))
			http.Error(w, "invalid CSRF token", http.StatusForbidden)
			return
		}
		w.Header().Set("Cache-Control", "no-store")
		next(w, r.WithContext(context.WithValue(r.Context(), sessKey{}, sess)))
	})
}

// csrfOK enforces the session's CSRF token on state-changing requests: header
// for HTMX, hidden form field for plain forms.
func csrfOK(r *http.Request, expected string) bool {
	if r.Method == http.MethodGet || r.Method == http.MethodHead {
		return true
	}
	tok := r.Header.Get("X-CSRF-Token")
	if tok == "" {
		tok = r.PostFormValue("csrf_token")
	}
	return auth.CSRFEqual(tok, expected)
}

// ---- login / logout -------------------------------------------------------

func (wb *Web) loginPage(w http.ResponseWriter, r *http.Request) {
	wb.render(w, r, http.StatusOK, "login", "Sign in", map[string]string{})
}

func (wb *Web) login(w http.ResponseWriter, r *http.Request) {
	ip := httpx.ClientIP(r)
	if !wb.LoginRL.Allow(ip) {
		wb.render(w, r, http.StatusTooManyRequests, "login", "Sign in",
			map[string]string{"Error": "Too many attempts. Wait a minute and try again."})
		return
	}
	username := strings.TrimSpace(r.PostFormValue("username"))
	raw, err := wb.Sessions.Login(r.Context(), username, r.PostFormValue("password"), r.UserAgent(), ip)
	if err != nil {
		if !errors.Is(err, auth.ErrBadCredentials) {
			slog.Error("login", "err", err)
		}
		wb.Store.Audit(r.Context(), "anonymous", "login_failed", "", "username="+username+" ip="+ip)
		wb.render(w, r, http.StatusUnauthorized, "login", "Sign in",
			map[string]string{"Error": "Invalid username or password.", "Username": username})
		return
	}
	wb.Store.Audit(r.Context(), "admin:"+username, "login", "", "ip="+ip)
	wb.Sessions.SetCookie(w, raw)
	http.Redirect(w, r, "/", http.StatusSeeOther)
}

func (wb *Web) logout(w http.ResponseWriter, r *http.Request) {
	if c, err := r.Cookie(wb.Sessions.CookieName()); err == nil {
		_ = wb.Sessions.Logout(r.Context(), c.Value)
	}
	wb.Sessions.ClearCookie(w)
	wb.Store.Audit(r.Context(), actor(r), "logout", "", "")
	http.Redirect(w, r, "/login", http.StatusSeeOther)
}

// ---- dashboard --------------------------------------------------------------

type healthRow struct {
	Tenant store.Tenant
	Health *pb.HealthResult
}

func (wb *Web) dashboard(w http.ResponseWriter, r *http.Request) {
	all := wb.Registry.All()
	enabled := 0
	types := map[string]int{}
	for _, t := range all {
		if t.Enabled {
			enabled++
		}
		types[t.DBType]++
	}
	wb.render(w, r, http.StatusOK, "dashboard", "Dashboard", map[string]any{
		"Total": len(all), "Enabled": enabled, "Types": types,
	})
}

// checkAll runs a health check against every tenant concurrently.
func (wb *Web) checkAll(ctx context.Context) []healthRow {
	all := wb.Registry.All()
	rows := make([]healthRow, len(all))
	var wg sync.WaitGroup
	for i, t := range all {
		rows[i].Tenant = t
		if !t.Enabled {
			continue
		}
		wg.Go(func() {
			ctx, cancel := context.WithTimeout(ctx, 8*time.Second)
			defer cancel()
			h, err := wb.Engine.Health(ctx, engine.Req(t))
			if err != nil {
				msg := httpx.ErrMsg(err)
				h = &pb.HealthResult{Ok: false, Error: msg}
			}
			rows[i].Health = h
		})
	}
	wg.Wait()
	return rows
}

func (wb *Web) healthPartial(w http.ResponseWriter, r *http.Request) {
	wb.partial(w, "health", wb.checkAll(r.Context()))
}

func (wb *Web) poolsPartial(w http.ResponseWriter, r *http.Request) {
	res, err := wb.Engine.PoolStats(r.Context(), &pb.PoolStatsRequest{})
	data := map[string]any{"Pools": []*pb.PoolStat{}}
	if err != nil {
		msg := httpx.ErrMsg(err)
		data["Error"] = "Rust engine unreachable: " + msg
	} else {
		data["Pools"] = res.Pools
	}
	wb.partial(w, "pools", data)
}

func (wb *Web) auditPage(w http.ResponseWriter, r *http.Request) {
	entries, err := wb.Store.RecentAudit(r.Context(), 200)
	if err != nil {
		http.Error(w, "failed to load audit log", http.StatusInternalServerError)
		return
	}
	wb.render(w, r, http.StatusOK, "audit", "Audit log", entries)
}

// ---- isolation test -------------------------------------------------------

func (wb *Web) isolationPage(w http.ResponseWriter, r *http.Request) {
	wb.render(w, r, http.StatusOK, "isolation", "Isolation test", map[string]any{
		"Tenants": wb.Registry.All(),
		"Opts":    isotest.Options{Concurrency: 32, RequestsPerTenant: 200, Writes: true, HotSwap: true},
	})
}

func (wb *Web) runIsolation(w http.ResponseWriter, r *http.Request) {
	opts := isotest.Options{
		Concurrency:       atoi(r.PostFormValue("concurrency"), 32),
		RequestsPerTenant: atoi(r.PostFormValue("requests"), 200),
		Writes:            r.PostFormValue("writes") == "on",
		HotSwap:           r.PostFormValue("hotswap") == "on",
	}
	sess, _ := sessionFrom(r.Context())
	rep, err := wb.Isolation.Run(r.Context(), opts, sess.AdminID)
	if err != nil {
		rep = &isotest.Report{Error: err.Error()}
	}
	if r.Header.Get("Accept") == "application/json" {
		httpx.JSON(w, http.StatusOK, rep)
		return
	}
	wb.partial(w, "report", rep)
}

func atoi(s string, def int) int {
	var n int
	if _, err := fmt.Sscan(s, &n); err != nil {
		return def
	}
	return n
}
