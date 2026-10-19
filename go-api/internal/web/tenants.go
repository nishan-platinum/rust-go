package web

import (
	"errors"
	"fmt"
	"html/template"
	"log/slog"
	"net/http"
	"slices"
	"strconv"
	"strings"
	"time"

	pb "github.com/example/rust-go/go-api/gen/dbengine/v1"
	"github.com/example/rust-go/go-api/internal/engine"
	"github.com/example/rust-go/go-api/internal/httpx"
	"github.com/example/rust-go/go-api/internal/provision"
	"github.com/example/rust-go/go-api/internal/store"
)

// actionResult is rendered inline next to a tenant row.
type actionResult struct {
	OK     bool
	Title  string
	Detail string
	Token  string
	Curl   string
}

func (wb *Web) result(w http.ResponseWriter, res actionResult) {
	wb.partial(w, "action_result", res)
}

type tenantsData struct {
	Tenants []store.Tenant
	Total   int
	Query   string // search text
	DBType  string // "" = all types
	Types   []string
}

// tenantsPage lists tenants newest first, optionally filtered by a search
// text (name, ID, address, database, host) and a database type.
func (wb *Web) tenantsPage(w http.ResponseWriter, r *http.Request) {
	d := tenantsData{
		Query:  strings.TrimSpace(r.URL.Query().Get("q")),
		DBType: r.URL.Query().Get("db"),
		Types:  provision.DBTypes,
	}
	all := wb.Registry.All()
	d.Total = len(all)
	q := strings.ToLower(d.Query)
	for _, t := range all {
		if d.DBType != "" && t.DBType != d.DBType {
			continue
		}
		haystack := strings.ToLower(strings.Join([]string{t.ID, t.Name, t.DBType, t.Database, t.Host, wb.tenantHost(t.ID)}, " "))
		if strings.Contains(haystack, q) {
			d.Tenants = append(d.Tenants, t)
		}
	}
	slices.SortStableFunc(d.Tenants, func(a, b store.Tenant) int { return b.CreatedAt.Compare(a.CreatedAt) })
	wb.render(w, r, http.StatusOK, "tenants", "Tenants", d)
}

type formData struct {
	Tenant store.Tenant
	Errors []string
	Ports  map[string]int
}

type wizardData struct {
	Req     provision.Request
	Servers []store.DBServer
	Types   []string
	Errors  []string
	Base    string
	DevAuto bool
}

func (wb *Web) wizard(w http.ResponseWriter, r *http.Request, code int, d wizardData) {
	servers, err := wb.Store.ListServers(r.Context())
	if err != nil {
		slog.Error("list servers", "err", err)
	}
	d.Servers, d.Types, d.Base, d.DevAuto = servers, provision.DBTypes, wb.BaseDomain, wb.Domains.DevAutoVerify
	if d.Req.DBType == "" {
		d.Req.DBType = "postgres"
	}
	if d.Req.Mode == "" {
		d.Req.Mode = "managed"
	}
	if d.Req.Address == "" {
		d.Req.Address = provision.AddressSubdomain
	}
	if d.Req.External.Port == 0 {
		d.Req.External.Port = provision.DefaultPorts[d.Req.DBType]
	}
	wb.render(w, r, code, "tenant_new", "New tenant", d)
}

func (wb *Web) newTenantPage(w http.ResponseWriter, r *http.Request) {
	wb.wizard(w, r, http.StatusOK, wizardData{})
}

// checkSubdomain is the live availability hint on the wizard.
func (wb *Web) checkSubdomain(w http.ResponseWriter, r *http.Request) {
	id := strings.ToLower(strings.TrimSpace(r.URL.Query().Get("id")))
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	if id == "" {
		return
	}
	if msg := wb.Provision.CheckID(r.Context(), id); msg != "" {
		fmt.Fprintf(w, `<span class="err-text">✗ %s</span>`, template.HTMLEscapeString(msg))
		return
	}
	fmt.Fprintf(w, `<span class="ok-text">✓ %s is available</span>`, template.HTMLEscapeString(id))
}
func (wb *Web) editTenantPage(w http.ResponseWriter, r *http.Request) {
	t, err := wb.Store.GetTenant(r.Context(), r.PathValue("id"))
	if err != nil {
		http.NotFound(w, r)
		return
	}
	t.Password = "" // never send the stored password back to the browser
	wb.render(w, r, http.StatusOK, "tenant_form", "Edit "+t.ID, formData{Tenant: t, Ports: provision.DefaultPorts})
}

// parseForm reads and validates the tenant form. An empty password on edit
// means "keep the current one".
func (wb *Web) parseForm(r *http.Request, id string) (store.Tenant, []string) {
	var errs []string
	port, err := strconv.Atoi(strings.TrimSpace(r.PostFormValue("port")))
	if err != nil || port < 1 || port > 65535 {
		errs = append(errs, "Port must be 1-65535.")
	}
	t := store.Tenant{
		ID:       id,
		Name:     strings.TrimSpace(r.PostFormValue("name")),
		DBType:   r.PostFormValue("db_type"),
		Host:     strings.TrimSpace(r.PostFormValue("host")),
		Port:     port,
		Username: strings.TrimSpace(r.PostFormValue("username")),
		Password: r.PostFormValue("password"),
		Database: strings.TrimSpace(r.PostFormValue("database")),
		Params:   parseParams(r.PostFormValue("params")),
	}
	if !provision.IDPattern.MatchString(t.ID) {
		errs = append(errs, "Tenant ID must be 2-28 chars of a-z, 0-9 and '-'.")
	}
	if _, ok := provision.DefaultPorts[t.DBType]; !ok {
		errs = append(errs, "Choose a database type.")
	}
	if t.Name == "" || t.Host == "" || t.Username == "" || t.Database == "" {
		errs = append(errs, "Name, host, username and database are required.")
	}
	if t.Password == "" {
		if cur, err := wb.Store.GetTenant(r.Context(), id); err == nil {
			t.Password = cur.Password
		} else {
			errs = append(errs, "Password is required.")
		}
	}
	return t, errs
}

func (wb *Web) testConnection(w http.ResponseWriter, r *http.Request) {
	t, errs := wb.parseForm(r, r.PostFormValue("id"))
	if len(errs) > 0 {
		wb.result(w, actionResult{Title: "Fix the form first", Detail: strings.Join(errs, " ")})
		return
	}
	start := time.Now()
	if err := wb.Provision.CheckConnection(r.Context(), engine.Conn(t)); err != nil {
		wb.result(w, actionResult{Title: "Connection failed", Detail: err.Error()})
		return
	}
	wb.result(w, actionResult{OK: true, Title: "Connection OK",
		Detail: fmt.Sprintf("%s reachable and not claimed by another tenant (%d ms).", t.DBType, time.Since(start).Milliseconds())})
}

func (wb *Web) createTenant(w http.ResponseWriter, r *http.Request) {
	port, _ := strconv.Atoi(strings.TrimSpace(r.PostFormValue("port")))
	serverID, _ := strconv.ParseInt(r.PostFormValue("server_id"), 10, 64)
	req := provision.Request{
		ID:       strings.ToLower(strings.TrimSpace(r.PostFormValue("id"))),
		Name:     strings.TrimSpace(r.PostFormValue("name")),
		DBType:   r.PostFormValue("db_type"),
		Mode:     r.PostFormValue("mode"),
		ServerID: serverID,
		External: store.Tenant{
			Host:     strings.TrimSpace(r.PostFormValue("host")),
			Port:     port,
			Username: strings.TrimSpace(r.PostFormValue("username")),
			Password: r.PostFormValue("password"),
			Database: strings.TrimSpace(r.PostFormValue("database")),
			Params:   parseParams(r.PostFormValue("params")),
		},
		AdminEmail:    strings.TrimSpace(r.PostFormValue("admin_email")),
		AdminName:     strings.TrimSpace(r.PostFormValue("admin_name")),
		AdminPassword: r.PostFormValue("admin_password"),
		Address:       provision.Address(r.PostFormValue("address")),
		CustomDomain:  strings.TrimSpace(r.PostFormValue("custom_domain")),
	}
	res := wb.Provision.Create(r.Context(), req, actor(r))
	if !res.OK && len(res.Steps) == 1 {
		// Validation failed: show the form again with the problems.
		req.External.Password, req.AdminPassword = "", ""
		wb.wizard(w, r, http.StatusUnprocessableEntity, wizardData{Req: req, Errors: []string{res.Steps[0].Detail}})
		return
	}
	code := http.StatusCreated
	if !res.OK {
		code = http.StatusUnprocessableEntity
	}
	wb.render(w, r, code, "tenant_created", "New tenant", map[string]any{"Req": req, "Res": res})
}

func parseParams(raw string) map[string]string {
	out := map[string]string{}
	for line := range strings.Lines(raw) {
		k, v, ok := strings.Cut(strings.TrimSpace(line), "=")
		if k = strings.TrimSpace(k); ok && k != "" {
			out[k] = strings.TrimSpace(v)
		}
	}
	return out
}
func (wb *Web) updateTenant(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	before, err := wb.Store.GetTenant(r.Context(), id)
	if err != nil {
		http.NotFound(w, r)
		return
	}
	t, errs := wb.parseForm(r, id)
	if len(errs) == 0 {
		if err := wb.Provision.CheckConnection(r.Context(), engine.Conn(t)); err != nil {
			errs = append(errs, "Connection check failed: "+err.Error())
		}
	}
	if len(errs) == 0 {
		if _, err := wb.Store.UpdateTenantConn(r.Context(), t); err != nil {
			if errors.Is(err, store.ErrDuplicate) {
				errs = append(errs, "Another tenant already uses this exact database.")
			} else {
				slog.Error("update tenant", "err", err)
				errs = append(errs, "Could not save tenant.")
			}
		}
	}
	if len(errs) > 0 {
		t.Password = ""
		wb.render(w, r, http.StatusUnprocessableEntity, "tenant_form", "Edit "+id,
			formData{Tenant: t, Errors: errs, Ports: provision.DefaultPorts})
		return
	}
	wb.Store.Audit(r.Context(), actor(r), "tenant_db_changed", id,
		fmt.Sprintf("%s %s:%d/%s -> %s %s:%d/%s", before.DBType, before.Host, before.Port, before.Database,
			t.DBType, t.Host, t.Port, t.Database))
	wb.afterSave(w, r, id, "updated")
}

// afterSave refreshes the cache and provisions the (possibly new) database.
func (wb *Web) afterSave(w http.ResponseWriter, r *http.Request, id, verb string) {
	t, err := wb.Registry.Refresh(r.Context(), id)
	if err != nil {
		setFlash(w, "err", "Saved, but reloading the tenant failed: "+err.Error())
	} else if res, err := wb.Engine.Provision(r.Context(), engine.Req(t)); err != nil {
		msg := httpx.ErrMsg(err)
		setFlash(w, "err", fmt.Sprintf("Tenant %s %s (config v%d) but provisioning failed: %s", id, verb, t.ConfigVersion, msg))
	} else {
		claim := "already claimed"
		if res.ClaimedNow {
			claim = "database claimed"
		}
		setFlash(w, "ok", fmt.Sprintf("Tenant %s %s: config v%d, %s, %s. The engine switches pools on the next request.",
			id, verb, t.ConfigVersion, t.DBType, claim))
	}
	http.Redirect(w, r, "/tenants", http.StatusSeeOther)
}

func (wb *Web) tenantFromPath(w http.ResponseWriter, r *http.Request) (store.Tenant, bool) {
	t, ok := wb.Registry.Get(r.PathValue("id"))
	if !ok {
		wb.result(w, actionResult{Title: "Unknown tenant"})
	}
	return t, ok
}

func (wb *Web) tenantHealth(w http.ResponseWriter, r *http.Request) {
	t, ok := wb.tenantFromPath(w, r)
	if !ok {
		return
	}
	h, err := wb.Engine.Health(r.Context(), engine.Req(t))
	if err != nil {
		msg := httpx.ErrMsg(err)
		wb.result(w, actionResult{Title: "Health check failed", Detail: msg})
		return
	}
	if !h.Ok {
		wb.result(w, actionResult{Title: "Unhealthy", Detail: h.Error})
		return
	}
	wb.result(w, actionResult{OK: true, Title: "Healthy", Detail: fmt.Sprintf("%s, %d ms", h.ServerVersion, h.LatencyMs)})
}

func (wb *Web) reprovision(w http.ResponseWriter, r *http.Request) {
	t, ok := wb.tenantFromPath(w, r)
	if !ok {
		return
	}
	res, err := wb.Engine.Provision(r.Context(), engine.Req(t))
	if err != nil {
		msg := httpx.ErrMsg(err)
		wb.result(w, actionResult{Title: "Provision failed", Detail: msg})
		return
	}
	wb.Store.Audit(r.Context(), actor(r), "tenant_provisioned", t.ID, fmt.Sprintf("claimed_now=%v", res.ClaimedNow))
	wb.result(w, actionResult{OK: true, Title: "Provisioned",
		Detail: fmt.Sprintf("Tables ready. Database marker = %q (claimed now: %v).", res.MarkerTenantId, res.ClaimedNow)})
}

func (wb *Web) revokeTokens(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	v, err := wb.Store.BumpTokenVersion(r.Context(), id)
	if err != nil {
		wb.result(w, actionResult{Title: "Revoke failed", Detail: err.Error()})
		return
	}
	_, _ = wb.Registry.Refresh(r.Context(), id)
	wb.Store.Audit(r.Context(), actor(r), "tokens_revoked", id, fmt.Sprintf("token_version=%d", v))
	wb.result(w, actionResult{OK: true, Title: "All tokens revoked",
		Detail: fmt.Sprintf("Token version is now %d. Every previously issued token for %s now returns 401.", v, id)})
}

func (wb *Web) mintToken(w http.ResponseWriter, r *http.Request) {
	t, ok := wb.tenantFromPath(w, r)
	if !ok {
		return
	}
	tok, err := wb.Tokens.Mint(t.ID, t.TokenVersion)
	if err != nil {
		wb.result(w, actionResult{Title: "Mint failed", Detail: err.Error()})
		return
	}
	wb.Store.Audit(r.Context(), actor(r), "token_minted", t.ID, fmt.Sprintf("tv=%d", t.TokenVersion))
	base := "http://" + r.Host
	wb.result(w, actionResult{OK: true, Title: "Tenant token",
		Detail: fmt.Sprintf("Valid for %s. Shown once; it is not stored.", wb.Tokens.TTL()),
		Token:  tok,
		Curl:   fmt.Sprintf("curl -H 'Authorization: Bearer %s' %s/api/v1/tenants/%s/whoami", tok, base, t.ID)})
}

func (wb *Web) toggleTenant(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	t, ok := wb.Registry.Get(id)
	if !ok {
		http.NotFound(w, r)
		return
	}
	if err := wb.Store.SetTenantEnabled(r.Context(), id, !t.Enabled); err != nil {
		setFlash(w, "err", err.Error())
	} else {
		state := map[bool]string{true: "enabled", false: "disabled"}[!t.Enabled]
		_, _ = wb.Registry.Refresh(r.Context(), id)
		if t.Enabled {
			_, _ = wb.Engine.EvictTenant(r.Context(), &pb.EvictTenantRequest{TenantId: id})
		}
		wb.Store.Audit(r.Context(), actor(r), "tenant_"+state, id, "")
		setFlash(w, "ok", "Tenant "+id+" "+state+".")
	}
	http.Redirect(w, r, "/tenants", http.StatusSeeOther)
}

func (wb *Web) deleteTenantPage(w http.ResponseWriter, r *http.Request) {
	t, err := wb.Store.GetTenant(r.Context(), r.PathValue("id"))
	if err != nil {
		http.NotFound(w, r)
		return
	}
	t.Password = ""
	wb.render(w, r, http.StatusOK, "tenant_delete", "Tenants", t)
}

func (wb *Web) deleteTenant(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	drop := r.PostFormValue("drop_data") == "on"
	if drop && r.PostFormValue("confirm_id") != id {
		setFlash(w, "err", "Type the tenant id exactly to confirm deleting its database. Nothing was deleted.")
		http.Redirect(w, r, "/tenants/"+id+"/delete", http.StatusSeeOther)
		return
	}
	if err := wb.Provision.Delete(r.Context(), id, drop, actor(r)); err != nil {
		setFlash(w, "err", "Delete failed: "+err.Error())
		http.Redirect(w, r, "/tenants", http.StatusSeeOther)
		return
	}
	msg := "Tenant " + id + " deleted. Its database was left untouched."
	if drop {
		msg = "Tenant " + id + " deleted, including its database and DB user."
	}
	setFlash(w, "ok", msg)
	http.Redirect(w, r, "/tenants", http.StatusSeeOther)
}
