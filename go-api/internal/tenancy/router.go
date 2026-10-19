// Package tenancy routes requests by Host header:
//
//	admin.<base>, <base>, localhost, IP addresses -> platform admin console
//	<tenant>.<base>                               -> that tenant's portal
//	a verified custom domain (support.acme.com)    -> that tenant's portal
//	anything else                                 -> "workspace not found"
package tenancy

import (
	"context"
	"net"
	"net/http"
	"strings"

	"github.com/example/rust-go/go-api/internal/registry"
	"github.com/example/rust-go/go-api/internal/store"
)

type tenantKey struct{}

// TenantFrom returns the tenant resolved from the request's subdomain.
func TenantFrom(ctx context.Context) (store.Tenant, bool) {
	t, ok := ctx.Value(tenantKey{}).(store.Tenant)
	return t, ok
}

type Router struct {
	BaseDomain    string
	Registry      *registry.Registry
	Admin         http.Handler
	Portal        http.Handler
	UnknownTenant http.Handler
	// TLSAsk answers "may a certificate be issued for ?domain=" for a TLS
	// proxy. It is reachable on any host because the proxy calls it directly.
	TLSAsk func(domain string) bool
}

// Hostname returns the lower-cased host without port.
func Hostname(r *http.Request) string {
	host := r.Host
	if h, _, err := net.SplitHostPort(host); err == nil {
		host = h
	}
	return strings.ToLower(strings.TrimSuffix(host, "."))
}

func (rt *Router) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path == "/internal/tls-ask" && rt.TLSAsk != nil {
		if rt.TLSAsk(strings.ToLower(r.URL.Query().Get("domain"))) {
			w.WriteHeader(http.StatusOK)
		} else {
			w.WriteHeader(http.StatusNotFound)
		}
		return
	}
	host := Hostname(r)
	if host == rt.BaseDomain || host == "admin."+rt.BaseDomain || host == "localhost" || net.ParseIP(host) != nil {
		rt.Admin.ServeHTTP(w, r)
		return
	}
	t, ok := rt.Registry.ByDomain(host)
	if !ok {
		if sub, isSub := strings.CutSuffix(host, "."+rt.BaseDomain); isSub && !strings.Contains(sub, ".") {
			t, ok = rt.Registry.Get(sub)
			ok = ok && t.SubdomainEnabled // own-domain-only tenants have no subdomain
		}
	}
	if !ok {
		rt.UnknownTenant.ServeHTTP(w, r)
		return
	}
	rt.Portal.ServeHTTP(w, r.WithContext(context.WithValue(r.Context(), tenantKey{}, t)))
}
