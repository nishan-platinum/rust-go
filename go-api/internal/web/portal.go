package web

import (
	"context"
	"errors"
	"log/slog"
	"net/http"
	"net/mail"
	"strings"
	"sync"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	pb "github.com/example/rust-go/go-api/gen/dbengine/v1"
	"github.com/example/rust-go/go-api/internal/auth"
	"github.com/example/rust-go/go-api/internal/engine"
	"github.com/example/rust-go/go-api/internal/httpx"
	"github.com/example/rust-go/go-api/internal/store"
	"github.com/example/rust-go/go-api/internal/tenancy"
)

// Portal returns the handler for <tenant>.<base domain>. The tenant is
// already resolved by tenancy.Router; every page only ever talks to that
// tenant's own database.
func (wb *Web) Portal() http.Handler {
	mux := http.NewServeMux()
	mux.Handle("GET /static/", staticHandler())
	mux.HandleFunc("GET /login", wb.portalLoginPage)
	mux.HandleFunc("POST /login", wb.portalLogin)
	authed := func(pattern string, h http.HandlerFunc) { mux.Handle(pattern, wb.requireTenantSession(h)) }
	authed("GET /{$}", wb.portalHome)
	authed("POST /logout", wb.portalLogout)
	authed("POST /items", wb.portalAddItem)
	authed("POST /users", wb.portalAddUser)

	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t, _ := tenancy.TenantFrom(r.Context())
		if !t.Enabled && !strings.HasPrefix(r.URL.Path, "/static/") {
			wb.portalMessage(w, r, http.StatusForbidden, "Workspace disabled",
				"This workspace is currently disabled. Contact your SciCom CX administrator.")
			return
		}
		mux.ServeHTTP(w, r)
	})
}

// UnknownTenant renders the page for a subdomain that has no tenant.
func (wb *Web) UnknownTenant() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasPrefix(r.URL.Path, "/static/") {
			staticHandler().ServeHTTP(w, r)
			return
		}
		wb.portalMessage(w, r, http.StatusNotFound, "Workspace not found",
			"There is no SciCom CX workspace at "+tenancy.Hostname(r)+".")
	})
}

type portalData struct {
	Title    string
	Tenant   store.Tenant
	User     store.TenantSession
	LoggedIn bool
	Flash    *flash
	Data     any
}

func (wb *Web) renderPortal(w http.ResponseWriter, r *http.Request, code int, page, title string, data any) {
	pd := portalData{Title: title, Data: data, Flash: readFlash(w, r)}
	pd.Tenant, _ = tenancy.TenantFrom(r.Context())
	pd.Tenant.Password = "" // never reaches a template
	if u, ok := r.Context().Value(tenantUserKey{}).(store.TenantSession); ok {
		pd.User, pd.LoggedIn = u, true
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(code)
	if err := wb.pages[page].ExecuteTemplate(w, "portal", pd); err != nil {
		slog.Error("render portal", "page", page, "err", err)
	}
}

func (wb *Web) portalMessage(w http.ResponseWriter, r *http.Request, code int, title, msg string) {
	wb.renderPortal(w, r, code, "portal_message", title, map[string]string{"Heading": title, "Message": msg})
}

type tenantUserKey struct{}

// requireTenantSession accepts only a session issued for *this* tenant and
// enforces CSRF on state changes.
func (wb *Web) requireTenantSession(next http.HandlerFunc) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t, _ := tenancy.TenantFrom(r.Context())
		var raw string
		if c, err := r.Cookie(wb.TenantSessions.CookieName()); err == nil {
			raw = c.Value
		}
		sess, err := wb.TenantSessions.Lookup(r.Context(), raw, t.ID)
		if err != nil {
			if !errors.Is(err, store.ErrNotFound) {
				slog.Error("tenant session lookup", "tenant", t.ID, "err", err)
			}
			if raw != "" {
				wb.TenantSessions.ClearCookie(w)
			}
			http.Redirect(w, r, "/login", http.StatusSeeOther)
			return
		}
		if !csrfOK(r, sess.CSRFToken) {
			http.Error(w, "invalid CSRF token", http.StatusForbidden)
			return
		}
		w.Header().Set("Cache-Control", "no-store")
		next(w, r.WithContext(context.WithValue(r.Context(), tenantUserKey{}, sess)))
	})
}

func (wb *Web) portalLoginPage(w http.ResponseWriter, r *http.Request) {
	wb.renderPortal(w, r, http.StatusOK, "portal_login", "Sign in", map[string]string{})
}

func (wb *Web) portalLogin(w http.ResponseWriter, r *http.Request) {
	t, _ := tenancy.TenantFrom(r.Context())
	ip := httpx.ClientIP(r)
	email := strings.ToLower(strings.TrimSpace(r.PostFormValue("email")))
	fail := func(code int, msg string) {
		wb.renderPortal(w, r, code, "portal_login", "Sign in", map[string]string{"Error": msg, "Email": email})
	}
	if !wb.LoginRL.Allow(t.ID + "|" + ip) {
		fail(http.StatusTooManyRequests, "Too many attempts. Wait a minute and try again.")
		return
	}
	u, err := wb.Engine.GetUserByEmail(r.Context(), &pb.GetUserByEmailRequest{Conn: engine.Conn(t), Email: email})
	if err != nil && status.Code(err) != codes.NotFound {
		slog.Error("tenant login lookup", "tenant", t.ID, "err", err)
		fail(http.StatusServiceUnavailable, "This workspace's database is unavailable right now.")
		return
	}
	// Unknown email: empty hash, same cost as a real check.
	if !auth.CheckPassword(u.GetPasswordHash(), r.PostFormValue("password")) {
		wb.Store.Audit(r.Context(), "anonymous", "tenant_login_failed", t.ID, "email="+email+" ip="+ip)
		fail(http.StatusUnauthorized, "Invalid email or password.")
		return
	}
	raw, err := wb.TenantSessions.Create(r.Context(), store.TenantSession{
		TenantID: t.ID, UserID: u.Id, Email: u.Email, Name: u.Name, Role: u.Role,
	})
	if err != nil {
		slog.Error("tenant session create", "err", err)
		fail(http.StatusInternalServerError, "Could not sign you in.")
		return
	}
	wb.Store.Audit(r.Context(), "user:"+u.Email, "tenant_login", t.ID, "ip="+ip)
	wb.TenantSessions.SetCookie(w, raw)
	http.Redirect(w, r, "/", http.StatusSeeOther)
}

func (wb *Web) portalLogout(w http.ResponseWriter, r *http.Request) {
	if c, err := r.Cookie(wb.TenantSessions.CookieName()); err == nil {
		_ = wb.TenantSessions.Logout(r.Context(), c.Value)
	}
	wb.TenantSessions.ClearCookie(w)
	http.Redirect(w, r, "/login", http.StatusSeeOther)
}

func (wb *Web) portalHome(w http.ResponseWriter, r *http.Request) {
	t, _ := tenancy.TenantFrom(r.Context())
	ctx := r.Context()
	// Three independent reads from the tenant DB, fetched concurrently.
	var (
		wg    sync.WaitGroup
		who   *pb.WhoAmIResult
		items *pb.ListItemsResult
		users *pb.ListUsersResult
		err   error
	)
	wg.Go(func() { who, err = wb.Engine.WhoAmI(ctx, engine.Req(t)) })
	wg.Go(func() { items, _ = wb.Engine.ListItems(ctx, &pb.ListItemsRequest{Conn: engine.Conn(t), Limit: 20}) })
	wg.Go(func() { users, _ = wb.Engine.ListUsers(ctx, &pb.ListUsersRequest{Conn: engine.Conn(t)}) })
	wg.Wait()
	data := map[string]any{"Who": who, "Items": items.GetItems(), "Users": users.GetUsers()}
	if err != nil {
		data["Errors"] = []string{httpx.ErrMsg(err)}
	}
	wb.renderPortal(w, r, http.StatusOK, "portal_home", t.Name, data)
}

func (wb *Web) portalAddItem(w http.ResponseWriter, r *http.Request) {
	t, _ := tenancy.TenantFrom(r.Context())
	name := strings.TrimSpace(r.PostFormValue("name"))
	if name == "" || len(name) > 255 {
		setFlash(w, "err", "Item name must be 1-255 characters.")
	} else if _, err := wb.Engine.InsertItem(r.Context(), &pb.InsertItemRequest{
		Conn: engine.Conn(t), Name: name, Owner: t.ID, Nonce: auth.RandomToken(9),
	}); err != nil {
		msg := httpx.ErrMsg(err)
		setFlash(w, "err", "Could not save: "+msg)
	} else {
		setFlash(w, "ok", "Saved to your "+t.DBType+" database.")
	}
	http.Redirect(w, r, "/", http.StatusSeeOther)
}

func (wb *Web) portalAddUser(w http.ResponseWriter, r *http.Request) {
	t, _ := tenancy.TenantFrom(r.Context())
	me := r.Context().Value(tenantUserKey{}).(store.TenantSession)
	defer http.Redirect(w, r, "/", http.StatusSeeOther)
	if me.Role != "admin" {
		setFlash(w, "err", "Only workspace admins can add users.")
		return
	}
	email := strings.ToLower(strings.TrimSpace(r.PostFormValue("email")))
	name := strings.TrimSpace(r.PostFormValue("name"))
	password := r.PostFormValue("password")
	role := r.PostFormValue("role")
	if a, err := mail.ParseAddress(email); err != nil || a.Address != email {
		setFlash(w, "err", "Enter a valid email address.")
		return
	}
	if len(password) < 8 || (role != "admin" && role != "member") {
		setFlash(w, "err", "Password must be at least 8 characters and role admin or member.")
		return
	}
	hash, err := auth.HashPassword(password)
	if err == nil {
		_, err = wb.Engine.CreateUser(r.Context(), &pb.CreateUserRequest{
			Conn: engine.Conn(t), Email: email, Name: name, Role: role, PasswordHash: hash,
		})
	}
	if err != nil {
		msg := httpx.ErrMsg(err)
		if status.Code(err) == codes.AlreadyExists {
			msg = "A user with this email already exists."
		}
		setFlash(w, "err", msg)
		return
	}
	wb.Store.Audit(r.Context(), "user:"+me.Email, "tenant_user_added", t.ID, email+" role="+role)
	setFlash(w, "ok", "User "+email+" added. They can sign in at "+tenancy.Hostname(r)+".")
}
