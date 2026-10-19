package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"regexp"
	"strconv"
	"syscall"
	"time"

	"github.com/example/rust-go/go-api/internal/api"
	"github.com/example/rust-go/go-api/internal/auth"
	"github.com/example/rust-go/go-api/internal/config"
	"github.com/example/rust-go/go-api/internal/domains"
	"github.com/example/rust-go/go-api/internal/engine"
	"github.com/example/rust-go/go-api/internal/httpx"
	"github.com/example/rust-go/go-api/internal/isotest"
	"github.com/example/rust-go/go-api/internal/provision"
	"github.com/example/rust-go/go-api/internal/registry"
	"github.com/example/rust-go/go-api/internal/secret"
	"github.com/example/rust-go/go-api/internal/store"
	"github.com/example/rust-go/go-api/internal/tenancy"
	"github.com/example/rust-go/go-api/internal/web"
)

func main() {
	slog.SetDefault(slog.New(slog.NewJSONHandler(os.Stdout, nil)))
	if err := run(); err != nil {
		slog.Error("fatal", "err", err)
		os.Exit(1)
	}
}

func run() error {
	cfg, err := config.Load()
	if err != nil {
		return err
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	box, err := secret.New(cfg.MasterKey)
	if err != nil {
		return err
	}
	st, err := store.Open(ctx, cfg.ControlDBURL, box)
	if err != nil {
		return err
	}
	defer st.Close()
	if err := st.Migrate(ctx); err != nil {
		return fmt.Errorf("migrate: %w", err)
	}
	if err := ensureAdmin(ctx, st, cfg); err != nil {
		return err
	}
	seedTenants, err := seedServers(ctx, st, cfg.SeedFile)
	if err != nil {
		return fmt.Errorf("seed: %w", err)
	}

	eng, err := engine.Dial(cfg.EngineAddr, cfg.EngineToken, cfg.EngineTimeout)
	if err != nil {
		return err
	}
	defer eng.Close()

	reg := registry.New(st)
	if err := reg.Reload(ctx); err != nil {
		return err
	}
	// Links prefer a tenant's primary custom domain, then its subdomain; ""
	// while an own-domain-only workspace is still waiting for DNS.
	tenantURL := func(id string) string {
		if d := reg.PrimaryDomain(id); d != "" {
			return cfg.HostURL(d)
		}
		if t, ok := reg.Get(id); ok && t.SubdomainEnabled {
			return cfg.TenantURL(id)
		}
		return ""
	}
	doms := &domains.Service{Store: st, Registry: reg, BaseDomain: cfg.BaseDomain, DevAutoVerify: cfg.DomainDevAutoVerify}
	prov := &provision.Service{Store: st, Registry: reg, Engine: eng, Domains: doms, TenantURL: tenantURL}
	go reg.Run(ctx, 15*time.Second)
	go ensureProvisioned(ctx, reg, eng)
	go createSeedTenants(ctx, prov, seedTenants)
	go purgeSessions(ctx, st)

	sessions := auth.NewSessions(st, cfg.SessionTTL, cfg.CookieSecure)
	tenantSessions := auth.NewTenantSessions(st, cfg.SessionTTL, cfg.CookieSecure)
	tokens := auth.NewTokens(cfg.JWTSecret, cfg.TokenTTL)

	// Admin console + tenant API: admin.<base>, the bare domain and IPs.
	adminMux := http.NewServeMux()
	adminMux.HandleFunc("GET /healthz", func(w http.ResponseWriter, r *http.Request) { w.Write([]byte("ok")) })
	(&api.API{Registry: reg, Tokens: tokens, Engine: eng, Store: st}).Register(adminMux)
	ui := &web.Web{
		Store: st, Registry: reg, Engine: eng, Sessions: sessions, Tokens: tokens,
		LoginRL: auth.NewRateLimiter(10, 5), Provision: prov, Domains: doms,
		TenantSessions: tenantSessions, TenantURL: tenantURL, HostURL: cfg.HostURL, BaseDomain: cfg.BaseDomain,
		Isolation: &isotest.Runner{
			BaseURL: cfg.SelfBaseURL, Tokens: tokens, Sessions: sessions, Registry: reg, Store: st,
			TenantSessions: tenantSessions, BaseDomain: cfg.BaseDomain,
		},
	}
	if err := ui.Register(adminMux); err != nil {
		return err
	}
	router := &tenancy.Router{
		BaseDomain:    cfg.BaseDomain,
		Registry:      reg,
		Admin:         adminMux,
		Portal:        ui.Portal(),
		UnknownTenant: ui.UnknownTenant(),
		TLSAsk:        doms.TLSAllowed,
	}

	srv := &http.Server{
		Addr:              cfg.HTTPAddr,
		Handler:           httpx.Middleware(router),
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       15 * time.Second,
		// Long enough for a large isolation run.
		WriteTimeout:   5 * time.Minute,
		IdleTimeout:    2 * time.Minute,
		MaxHeaderBytes: 1 << 16,
	}
	errCh := make(chan error, 1)
	go func() {
		slog.Info("SciCom CX listening", "addr", cfg.HTTPAddr, "engine", cfg.EngineAddr,
			"admin", cfg.AdminURL(), "tenants", cfg.TenantURL("<tenant>"))
		errCh <- srv.ListenAndServe()
	}()

	select {
	case err := <-errCh:
		return err
	case <-ctx.Done():
	}
	slog.Info("shutting down")
	shutdownCtx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	return srv.Shutdown(shutdownCtx)
}

func ensureAdmin(ctx context.Context, st *store.Store, cfg *config.Config) error {
	if _, err := st.AdminByUsername(ctx, cfg.AdminUsername); err == nil {
		return nil
	} else if !errors.Is(err, store.ErrNotFound) {
		return err
	}
	if len(cfg.AdminPassword) < 8 {
		return errors.New("ADMIN_PASSWORD (min 8 chars) is required to create the initial admin")
	}
	hash, err := auth.HashPassword(cfg.AdminPassword)
	if err != nil {
		return err
	}
	if created, err := st.EnsureAdmin(ctx, cfg.AdminUsername, hash); err != nil {
		return err
	} else if created {
		slog.Info("created initial admin", "username", cfg.AdminUsername)
		st.Audit(ctx, "system", "admin_created", "", cfg.AdminUsername)
	}
	return nil
}

var envRef = regexp.MustCompile(`\$\{([A-Z0-9_]+)(?::-([^}]*))?\}`)

// expandEnv supports ${VAR} and ${VAR:-default}.
func expandEnv(s string) string {
	return envRef.ReplaceAllStringFunc(s, func(m string) string {
		p := envRef.FindStringSubmatch(m)
		if v := os.Getenv(p[1]); v != "" {
			return v
		}
		return p[2]
	})
}

type seedFile struct {
	Servers []struct {
		Port          string            `json:"port"` // string so ${VAR:-5432} works
		Name          string            `json:"name"`
		DBType        string            `json:"db_type"`
		Host          string            `json:"host"`
		AdminUsername string            `json:"admin_username"`
		AdminPassword string            `json:"admin_password"`
		Params        map[string]string `json:"params"`
	} `json:"servers"`
	Tenants []struct {
		ID            string `json:"id"`
		Name          string `json:"name"`
		DBType        string `json:"db_type"`
		AdminEmail    string `json:"admin_email"`
		AdminName     string `json:"admin_name"`
		AdminPassword string `json:"admin_password"`
		Address       string `json:"address"` // "subdomain" (default) or "domain"
		Domain        string `json:"domain"`
	} `json:"tenants"`
}

// seedServers registers the database servers on first boot (empty
// db_servers table) and returns the demo tenants to create. Tenants are only
// seeded on that first boot, so deleted demo tenants do not come back.
func seedServers(ctx context.Context, st *store.Store, path string) ([]provision.Request, error) {
	if path == "" {
		return nil, nil
	}
	if n, err := st.CountServers(ctx); err != nil || n > 0 {
		return nil, err
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var f seedFile
	if err := json.Unmarshal([]byte(expandEnv(string(raw))), &f); err != nil {
		return nil, err
	}
	for _, s := range f.Servers {
		port, err := strconv.Atoi(s.Port)
		if err != nil {
			return nil, fmt.Errorf("server %s: bad port %q", s.Name, s.Port)
		}
		d := store.DBServer{Name: s.Name, DBType: s.DBType, Host: s.Host, Port: port,
			AdminUsername: s.AdminUsername, AdminPassword: s.AdminPassword, Params: s.Params}
		if _, err := st.CreateServer(ctx, d); err != nil {
			return nil, fmt.Errorf("server %s: %w", s.Name, err)
		}
		slog.Info("seeded database server", "name", d.Name, "db_type", d.DBType, "host", d.Host, "port", d.Port)
	}
	st.Audit(ctx, "system", "servers_seeded", "", fmt.Sprintf("%d servers from %s", len(f.Servers), path))
	var out []provision.Request
	for _, t := range f.Tenants {
		out = append(out, provision.Request{ID: t.ID, Name: t.Name, DBType: t.DBType, Mode: "managed",
			AdminEmail: t.AdminEmail, AdminName: t.AdminName, AdminPassword: t.AdminPassword,
			Address: provision.Address(t.Address), CustomDomain: t.Domain})
	}
	return out, nil
}

// retryEach calls try for every item until it reports done, retrying the
// rest every 3s (up to 40 rounds) while the engine and databases start up.
// It returns the items that never finished.
func retryEach[T any](ctx context.Context, items []T, try func(item T, round int) (done bool)) []T {
	for round := 0; round < 40 && len(items) > 0; round++ {
		var pending []T
		for _, it := range items {
			if !try(it, round) {
				pending = append(pending, it)
			}
		}
		if items = pending; len(items) > 0 {
			select {
			case <-ctx.Done():
				return items
			case <-time.After(3 * time.Second):
			}
		}
	}
	return items
}

// createSeedTenants creates the demo tenants through the same flow as the UI.
func createSeedTenants(ctx context.Context, prov *provision.Service, reqs []provision.Request) {
	failed := retryEach(ctx, reqs, func(req provision.Request, _ int) bool {
		res := prov.Create(ctx, req, "system")
		switch {
		case res.OK:
			slog.Info("seeded tenant", "id", req.ID, "db_type", req.DBType, "url", res.PortalURL)
		case len(res.Steps) == 1: // validation failed: retrying will not help
			slog.Error("seed tenant invalid", "id", req.ID, "err", res.Steps[0].Detail)
		default:
			return false
		}
		return true
	})
	for _, r := range failed {
		slog.Error("seed tenant could not be created", "id", r.ID)
	}
}

// ensureProvisioned makes sure every enabled tenant's database has its tables
// and claim marker (idempotent), e.g. after a database was restored.
func ensureProvisioned(ctx context.Context, reg *registry.Registry, eng *engine.Client) {
	failed := retryEach(ctx, reg.All(), func(t store.Tenant, round int) bool {
		if !t.Enabled {
			return true
		}
		res, err := eng.Provision(ctx, engine.Req(t))
		if err != nil {
			if round%5 == 0 {
				slog.Warn("provision pending", "tenant", t.ID, "err", err)
			}
			return false
		}
		slog.Info("tenant provisioned", "tenant", t.ID, "claimed_now", res.ClaimedNow)
		return true
	})
	for _, t := range failed {
		slog.Error("tenant could not be provisioned", "tenant", t.ID)
	}
}

func purgeSessions(ctx context.Context, st *store.Store) {
	t := time.NewTicker(10 * time.Minute)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			if n, err := st.PurgeExpiredSessions(ctx); err == nil && n > 0 {
				slog.Info("purged expired sessions", "count", n)
			}
		}
	}
}
