// Package provision creates and deletes tenants end to end:
//
//	validate -> (managed) create DB + DB user on the server, or (external)
//	check the existing DB -> register in the central DB -> create tables and
//	claim the DB -> create the tenant admin user inside the tenant DB ->
//	verify the subdomain is served from the right database.
//
// Every step is recorded so the UI can show a checklist. If a step fails,
// everything done so far is rolled back.
package provision

import (
	"context"
	"errors"
	"fmt"
	"net/mail"
	"regexp"
	"strings"

	pb "github.com/example/rust-go/go-api/gen/dbengine/v1"
	"github.com/example/rust-go/go-api/internal/auth"
	"github.com/example/rust-go/go-api/internal/domains"
	"github.com/example/rust-go/go-api/internal/engine"
	"github.com/example/rust-go/go-api/internal/httpx"
	"github.com/example/rust-go/go-api/internal/registry"
	"github.com/example/rust-go/go-api/internal/store"
)

var (
	// The tenant id is its subdomain: a DNS label of 2-28 characters.
	IDPattern = regexp.MustCompile(`^[a-z0-9][a-z0-9-]{0,26}[a-z0-9]$`)
	// Subdomains that must never be given to a tenant.
	Reserved = map[string]bool{
		"admin": true, "www": true, "api": true, "app": true, "static": true, "assets": true,
		"mail": true, "smtp": true, "ftp": true, "status": true, "support": true, "help": true,
		"docs": true, "auth": true, "login": true, "sso": true, "central": true, "scicom": true,
	}
	DBTypes      = []string{"postgres", "mysql", "mariadb", "mongodb"}
	DefaultPorts = map[string]int{"postgres": 5432, "mysql": 3306, "mariadb": 3306, "mongodb": 27017}
)

type Service struct {
	Store     *store.Store
	Registry  *registry.Registry
	Engine    *engine.Client
	Domains   *domains.Service
	TenantURL func(id string) string
}

type Request struct {
	ID     string
	Name   string
	DBType string
	// "managed" (create the DB on ServerID, or the type's default server) or
	// "external" (connect to the existing database described by External).
	Mode     string
	ServerID int64
	External store.Tenant

	AdminEmail    string
	AdminName     string
	AdminPassword string // generated when empty

	Address      Address
	CustomDomain string // required for AddressDomain
}

// Address is where a new workspace is reachable.
type Address string

const (
	// AddressSubdomain serves <id>.<BASE_DOMAIN>, live immediately.
	AddressSubdomain Address = "subdomain"
	// AddressDomain serves only the client's own domain, live once verified.
	AddressDomain Address = "domain"
)

type Step struct {
	Name   string
	OK     bool
	Detail string
}

type Result struct {
	OK                bool
	Steps             []Step
	Tenant            store.Tenant
	PortalURL         string // "" while an own-domain-only workspace waits for DNS
	AdminEmail        string
	GeneratedPassword string // shown once, never stored in clear
	// The custom domain added during creation (nil if none); unverified ones
	// carry the DNS records to show.
	Domain *store.Domain
}

func (r *Result) step(name string, err error, detail string) bool {
	if err != nil {
		r.Steps = append(r.Steps, Step{Name: name, Detail: httpx.ErrMsg(err)})
		return false
	}
	r.Steps = append(r.Steps, Step{Name: name, OK: true, Detail: detail})
	return true
}

// CheckConnection logs in with conn on a throwaway connection and, for a
// tenant database, checks it is not claimed by another tenant.
func (s *Service) CheckConnection(ctx context.Context, conn *pb.TenantConn) error {
	if conn.ConfigVersion == 0 {
		conn.ConfigVersion = 1 // not saved yet; the engine requires a version
	}
	h, err := s.Engine.TestConnection(ctx, &pb.TestConnectionRequest{Conn: conn})
	if err != nil {
		return errors.New(httpx.ErrMsg(err))
	}
	if !h.Ok {
		return errors.New(h.Error)
	}
	return nil
}

// ManagedNames derives the database and DB user name from the tenant id.
func ManagedNames(id string) (database, user string) {
	n := "scx_" + strings.ReplaceAll(id, "-", "_")
	return n, n
}

// CheckID reports why an id cannot be used as a subdomain ("" when it can).
func (s *Service) CheckID(ctx context.Context, id string) string {
	switch {
	case !IDPattern.MatchString(id):
		return "Use 2-28 lowercase letters, digits or '-' (not at the start or end)."
	case Reserved[id]:
		return "This ID is reserved."
	}
	if _, err := s.Store.GetTenant(ctx, id); err == nil {
		return "A tenant with this ID already exists."
	} else if !errors.Is(err, store.ErrNotFound) {
		return "Could not check availability."
	}
	return ""
}

func (s *Service) validate(ctx context.Context, req *Request) error {
	var problems []string
	if msg := s.CheckID(ctx, req.ID); msg != "" {
		problems = append(problems, "Tenant ID: "+msg)
	}
	switch req.Address {
	case "", AddressSubdomain:
		req.Address, req.CustomDomain = AddressSubdomain, ""
	case AddressDomain:
		if d, err := s.Domains.Available(ctx, req.CustomDomain); err != nil {
			problems = append(problems, "Client's domain: "+err.Error())
		} else {
			req.CustomDomain = d
		}
	default:
		problems = append(problems, "Choose the workspace address.")
	}
	if strings.TrimSpace(req.Name) == "" {
		problems = append(problems, "Tenant name is required.")
	}
	if !contains(DBTypes, req.DBType) {
		problems = append(problems, "Choose a database type.")
	}
	if req.Mode != "managed" && req.Mode != "external" {
		problems = append(problems, "Choose how the database is set up.")
	}
	if a, err := mail.ParseAddress(req.AdminEmail); err != nil || a.Address != req.AdminEmail {
		problems = append(problems, "Tenant admin email is not valid.")
	}
	if req.AdminPassword != "" && len(req.AdminPassword) < 8 {
		problems = append(problems, "Tenant admin password must be at least 8 characters (or leave it empty to generate one).")
	}
	if req.Mode == "external" {
		e := req.External
		if e.Host == "" || e.Port < 1 || e.Port > 65535 || e.Username == "" || e.Password == "" || e.Database == "" {
			problems = append(problems, "External database: host, port, username, password and database are required.")
		}
	}
	if len(problems) > 0 {
		return errors.New(strings.Join(problems, " "))
	}
	return nil
}

func contains(list []string, v string) bool {
	for _, x := range list {
		if x == v {
			return true
		}
	}
	return false
}

// Create runs the whole flow. It never returns a partially created tenant: on
// any failure the steps already done are undone.
func (s *Service) Create(ctx context.Context, req Request, actor string) *Result {
	req.ID = strings.ToLower(strings.TrimSpace(req.ID))
	req.AdminEmail = strings.ToLower(strings.TrimSpace(req.AdminEmail))
	res := &Result{AdminEmail: req.AdminEmail}
	if !res.step("Validate request", s.validate(ctx, &req), "tenant ID "+req.ID+" is available") {
		return res
	}
	if req.AdminPassword == "" {
		req.AdminPassword = auth.RandomToken(12)
		res.GeneratedPassword = req.AdminPassword
	}
	if strings.TrimSpace(req.AdminName) == "" {
		req.AdminName = "Administrator"
	}

	// Undo log, run in reverse on failure.
	var undo []func(context.Context)
	fail := func() *Result {
		failed := res.Steps[len(res.Steps)-1]
		ctx := context.WithoutCancel(ctx)
		for i := len(undo) - 1; i >= 0; i-- {
			undo[i](ctx)
		}
		if len(undo) > 0 {
			res.Steps = append(res.Steps, Step{Name: "Roll back", OK: true, Detail: "everything created so far was removed"})
		}
		s.Store.Audit(ctx, actor, "tenant_create_failed", req.ID, failed.Name+": "+failed.Detail)
		return res
	}

	t := store.Tenant{ID: req.ID, Name: strings.TrimSpace(req.Name), DBType: req.DBType, Mode: req.Mode,
		SubdomainEnabled: req.Address == AddressSubdomain}
	if req.Mode == "managed" {
		srv, err := s.server(ctx, req)
		if !res.step("Pick database server", err, fmt.Sprintf("%s (%s:%d)", srv.Name, srv.Host, srv.Port)) {
			return fail()
		}
		dbName, dbUser := ManagedNames(req.ID)
		password := auth.RandomToken(24)
		out, err := s.Engine.CreateTenantDatabase(ctx, &pb.CreateTenantDatabaseRequest{
			Server: engine.Server(srv), Database: dbName, Username: dbUser, Password: password,
		})
		if !res.step("Create database and DB user", err,
			fmt.Sprintf("%s database %q, user %q with a random password", req.DBType, dbName, dbUser)) {
			return fail()
		}
		if out.DatabaseCreated || out.UserCreated {
			undo = append(undo, func(ctx context.Context) {
				_, _ = s.Engine.DropTenantDatabase(ctx, &pb.DropTenantDatabaseRequest{
					Server: engine.Server(srv), Database: dbName, Username: dbUser,
				})
			})
		}
		t.Host, t.Port, t.Username, t.Password, t.Database = srv.Host, srv.Port, dbUser, password, dbName
		t.Params = tenantParams(srv)
		t.ServerID = &srv.ID
	} else {
		e := req.External
		t.Host, t.Port, t.Username, t.Password, t.Database, t.Params = e.Host, e.Port, e.Username, e.Password, e.Database, e.Params
		err := s.CheckConnection(ctx, engine.Conn(t))
		if !res.step("Connect to existing database", err, fmt.Sprintf("%s:%d/%s reachable and unclaimed", e.Host, e.Port, e.Database)) {
			return fail()
		}
	}

	err := s.Store.CreateTenant(ctx, t)
	if errors.Is(err, store.ErrDuplicate) {
		err = errors.New("another tenant already uses this subdomain or this exact database")
	}
	if !res.step("Register tenant in central database", err, "scicomcx_central.tenants") {
		return fail()
	}
	undo = append(undo, func(ctx context.Context) {
		_, _ = s.Engine.EvictTenant(ctx, &pb.EvictTenantRequest{TenantId: req.ID})
		_ = s.Store.DeleteTenant(ctx, req.ID)
		_ = s.Registry.Reload(ctx)
	})
	if t, err = s.Registry.Refresh(ctx, req.ID); err != nil {
		res.step("Load tenant", err, "")
		return fail()
	}

	prov, err := s.Engine.Provision(ctx, engine.Req(t))
	if !res.step("Create tables and claim database", err,
		"tenant_meta, tenant_users, items; marker = "+prov.GetMarkerTenantId()) {
		return fail()
	}

	hash, err := auth.HashPassword(req.AdminPassword)
	if err == nil {
		_, err = s.Engine.CreateUser(ctx, &pb.CreateUserRequest{
			Conn: engine.Conn(t), Email: req.AdminEmail, Name: req.AdminName, Role: "admin", PasswordHash: hash,
		})
	}
	if !res.step("Create tenant admin (stored in tenant database)", err, req.AdminEmail) {
		return fail()
	}

	who, err := s.Engine.WhoAmI(ctx, engine.Req(t))
	if err == nil && who.MarkerTenantId != t.ID {
		err = fmt.Errorf("workspace would be served from the database of %q", who.MarkerTenantId)
	}
	if req.Address == AddressSubdomain {
		if !res.step("Activate subdomain", err, s.TenantURL(t.ID)+" is served from "+who.GetDatabase()) {
			return fail()
		}
	} else {
		if !res.step("Check workspace database", err, "served from "+who.GetDatabase()) {
			return fail()
		}
		d, err := s.Domains.Add(ctx, t.ID, req.CustomDomain, actor)
		detail := d.Domain + " is live"
		if !d.Verified() {
			detail = d.Domain + " added; goes live once the client's DNS records are verified"
		}
		if !res.step("Add client's domain", err, detail) {
			return fail() // without it the workspace would have no address
		}
		res.Domain = &d
	}

	res.OK, res.Tenant = true, t
	if res.Domain == nil || res.Domain.Verified() {
		res.PortalURL = s.TenantURL(t.ID)
	}
	s.Store.Audit(ctx, actor, "tenant_created", t.ID,
		fmt.Sprintf("%s %s %s:%d/%s admin=%s", t.Mode, t.DBType, t.Host, t.Port, t.Database, req.AdminEmail))
	return res
}

func (s *Service) server(ctx context.Context, req Request) (store.DBServer, error) {
	var srv store.DBServer
	var err error
	if req.ServerID > 0 {
		srv, err = s.Store.GetServer(ctx, req.ServerID)
	} else {
		srv, err = s.Store.DefaultServer(ctx, req.DBType)
	}
	if errors.Is(err, store.ErrNotFound) {
		return srv, fmt.Errorf("no %s server is configured; add one under Database servers", req.DBType)
	}
	if err == nil && srv.DBType != req.DBType {
		return srv, fmt.Errorf("server %s is %s, not %s", srv.Name, srv.DBType, req.DBType)
	}
	return srv, err
}

// tenantParams copies the server's driver params that also apply to tenant
// connections (TLS mode). Admin-only params are dropped; a managed Mongo user
// lives in the tenant database, so authSource defaults to it.
func tenantParams(srv store.DBServer) map[string]string {
	out := map[string]string{}
	if v, ok := srv.Params["sslmode"]; ok {
		out["sslmode"] = v
	}
	return out
}

// Delete removes a tenant. With dropData, a managed tenant's database and DB
// user are dropped permanently first (external databases are never dropped).
func (s *Service) Delete(ctx context.Context, id string, dropData bool, actor string) error {
	t, err := s.Store.GetTenant(ctx, id)
	if err != nil {
		return err
	}
	_, _ = s.Engine.EvictTenant(ctx, &pb.EvictTenantRequest{TenantId: id})
	dropped := false
	if dropData && t.Managed() && t.ServerID != nil {
		srv, err := s.Store.GetServer(ctx, *t.ServerID)
		if err != nil {
			return fmt.Errorf("load server: %w", err)
		}
		if _, err := s.Engine.DropTenantDatabase(ctx, &pb.DropTenantDatabaseRequest{
			Server: engine.Server(srv), Database: t.Database, Username: t.Username,
		}); err != nil {
			return fmt.Errorf("drop database: %s", httpx.ErrMsg(err))
		}
		dropped = true
	}
	if err := s.Store.DeleteTenant(ctx, id); err != nil {
		return err
	}
	_ = s.Registry.Reload(ctx)
	s.Store.Audit(ctx, actor, "tenant_deleted", id, fmt.Sprintf("mode=%s database_dropped=%v", t.Mode, dropped))
	return nil
}
