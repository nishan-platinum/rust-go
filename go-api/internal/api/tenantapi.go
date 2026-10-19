// Package api is the tenant-facing data API, authenticated with tenant JWTs.
//
//	GET  /api/v1/tenants/{tid}/whoami
//	GET  /api/v1/tenants/{tid}/items?limit=N
//	POST /api/v1/tenants/{tid}/items   {"name": "...", "nonce": "..."}
package api

import (
	"context"
	"encoding/json"
	"log/slog"
	"net/http"
	"strconv"
	"strings"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	pb "github.com/example/rust-go/go-api/gen/dbengine/v1"
	"github.com/example/rust-go/go-api/internal/auth"
	"github.com/example/rust-go/go-api/internal/engine"
	"github.com/example/rust-go/go-api/internal/httpx"
	"github.com/example/rust-go/go-api/internal/registry"
	"github.com/example/rust-go/go-api/internal/store"
)

type API struct {
	Registry *registry.Registry
	Tokens   *auth.Tokens
	Engine   *engine.Client
	Store    *store.Store
}

func (a *API) Register(mux *http.ServeMux) {
	mux.Handle("GET /api/v1/tenants/{tid}/whoami", a.tenantAuth(a.whoami))
	mux.Handle("GET /api/v1/tenants/{tid}/items", a.tenantAuth(a.listItems))
	mux.Handle("POST /api/v1/tenants/{tid}/items", a.tenantAuth(a.insertItem))
}

type tenantHandler func(w http.ResponseWriter, r *http.Request, t store.Tenant)

// tenantAuth is the core isolation check. Order matters:
//  1. valid signature/alg/iss/aud/exp       -> else 401
//  2. token tenant == path tenant           -> else 403 (cross-tenant attempt)
//  3. tenant exists and is enabled          -> else 403
//  4. token version == tenant token version -> else 401 (revoked)
func (a *API) tenantAuth(next tenantHandler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		raw, ok := strings.CutPrefix(r.Header.Get("Authorization"), "Bearer ")
		if !ok || raw == "" {
			w.Header().Set("WWW-Authenticate", `Bearer realm="tenant-api"`)
			httpx.Error(w, r, http.StatusUnauthorized, "missing bearer token")
			return
		}
		claims, err := a.Tokens.Verify(raw)
		if err != nil {
			w.Header().Set("WWW-Authenticate", `Bearer error="invalid_token"`)
			httpx.Error(w, r, http.StatusUnauthorized, "invalid token")
			return
		}
		pathTID := r.PathValue("tid")
		if claims.TenantID != pathTID {
			slog.Warn("cross-tenant access blocked", "token_tid", claims.TenantID, "path_tid", pathTID,
				"jti", claims.ID, "ip", httpx.ClientIP(r), "request_id", httpx.RequestID(r.Context()))
			// Detached context: the audit row must be written even if the client hangs up.
			go a.Store.Audit(context.WithoutCancel(r.Context()), "tenant:"+claims.TenantID,
				"cross_tenant_blocked", pathTID, "jti="+claims.ID)
			httpx.Error(w, r, http.StatusForbidden, "token is not valid for this tenant")
			return
		}
		t, ok := a.Registry.Get(pathTID)
		if !ok || !t.Enabled {
			httpx.Error(w, r, http.StatusForbidden, "tenant unavailable")
			return
		}
		if claims.TokenVersion != t.TokenVersion {
			httpx.Error(w, r, http.StatusUnauthorized, "token revoked")
			return
		}
		next(w, r, t)
	})
}

func (a *API) engineErr(w http.ResponseWriter, r *http.Request, t store.Tenant, err error) {
	code, msg := httpx.GRPCStatus(err)
	slog.Warn("engine call failed", "tenant", t.ID, "err", err, "request_id", httpx.RequestID(r.Context()))
	httpx.Error(w, r, code, msg)
}

// call runs fn and, if the engine says our config version is stale (another
// request already moved the tenant to a newer config), refreshes the tenant
// and retries once with the new version.
func call[T any](ctx context.Context, a *API, t store.Tenant, fn func(store.Tenant) (T, error)) (T, error) {
	res, err := fn(t)
	if status.Code(err) != codes.FailedPrecondition || !strings.Contains(status.Convert(err).Message(), "stale config version") {
		return res, err
	}
	fresh, ferr := a.Registry.Refresh(ctx, t.ID)
	if ferr != nil || fresh.ConfigVersion <= t.ConfigVersion {
		return res, err
	}
	return fn(fresh)
}

func (a *API) whoami(w http.ResponseWriter, r *http.Request, t store.Tenant) {
	res, err := call(r.Context(), a, t, func(t store.Tenant) (*pb.WhoAmIResult, error) {
		return a.Engine.WhoAmI(r.Context(), engine.Req(t))
	})
	if err != nil {
		a.engineErr(w, r, t, err)
		return
	}
	httpx.JSON(w, http.StatusOK, map[string]any{
		"tenant_id":        t.ID,
		"db_type":          t.DBType,
		"marker_tenant_id": res.MarkerTenantId,
		"database":         res.Database,
		"server_version":   res.ServerVersion,
		"session_id":       res.SessionId,
		"session_tag":      res.SessionTag,
		"request_id":       httpx.RequestID(r.Context()),
	})
}

func (a *API) listItems(w http.ResponseWriter, r *http.Request, t store.Tenant) {
	limit, _ := strconv.Atoi(r.URL.Query().Get("limit"))
	if limit <= 0 {
		limit = 50
	}
	res, err := call(r.Context(), a, t, func(t store.Tenant) (*pb.ListItemsResult, error) {
		return a.Engine.ListItems(r.Context(), &pb.ListItemsRequest{Conn: engine.Conn(t), Limit: uint32(limit)})
	})
	if err != nil {
		a.engineErr(w, r, t, err)
		return
	}
	items := make([]map[string]any, 0, len(res.Items))
	for _, it := range res.Items {
		items = append(items, itemJSON(it))
	}
	httpx.JSON(w, http.StatusOK, map[string]any{"tenant_id": t.ID, "items": items})
}

func (a *API) insertItem(w http.ResponseWriter, r *http.Request, t store.Tenant) {
	var body struct {
		Name  string `json:"name"`
		Nonce string `json:"nonce"`
	}
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 4096)).Decode(&body); err != nil || body.Name == "" {
		httpx.Error(w, r, http.StatusBadRequest, "body must be JSON with a non-empty name")
		return
	}
	// Owner always comes from the verified token, never from the client.
	it, err := call(r.Context(), a, t, func(t store.Tenant) (*pb.Item, error) {
		return a.Engine.InsertItem(r.Context(), &pb.InsertItemRequest{
			Conn: engine.Conn(t), Name: body.Name, Owner: t.ID, Nonce: body.Nonce,
		})
	})
	if err != nil {
		a.engineErr(w, r, t, err)
		return
	}
	httpx.JSON(w, http.StatusCreated, itemJSON(it))
}

func itemJSON(it *pb.Item) map[string]any {
	return map[string]any{
		"id": it.Id, "name": it.Name, "owner": it.Owner, "nonce": it.Nonce, "created_at": it.CreatedAtUnix,
	}
}
