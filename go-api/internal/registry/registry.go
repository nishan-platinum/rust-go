// Package registry is an in-memory, read-mostly cache of the tenant table so
// the hot request path never queries the control DB.
package registry

import (
	"context"
	"errors"
	"log/slog"
	"sort"
	"sync"
	"time"

	"github.com/example/rust-go/go-api/internal/store"
)

type Registry struct {
	store    *store.Store
	mu       sync.RWMutex
	byID     map[string]store.Tenant
	byDomain map[string]string // verified custom domain -> tenant id
	primary  map[string]string // tenant id -> primary custom domain
}

func New(s *store.Store) *Registry {
	return &Registry{store: s, byID: map[string]store.Tenant{}, byDomain: map[string]string{}, primary: map[string]string{}}
}

// Reload replaces the cache (tenants and verified domains) from the control DB.
func (r *Registry) Reload(ctx context.Context) error {
	list, err := r.store.ListTenants(ctx)
	if err != nil {
		return err
	}
	m := make(map[string]store.Tenant, len(list))
	for _, t := range list {
		m[t.ID] = t
	}
	r.mu.Lock()
	r.byID = m
	r.mu.Unlock()
	return r.ReloadDomains(ctx)
}

// ReloadDomains refreshes only the custom-domain maps (after a domain is
// added, verified, made primary or removed).
func (r *Registry) ReloadDomains(ctx context.Context) error {
	list, err := r.store.AllVerifiedDomains(ctx)
	if err != nil {
		return err
	}
	byDomain := make(map[string]string, len(list))
	primary := map[string]string{}
	for _, d := range list {
		byDomain[d.Domain] = d.TenantID
		if d.IsPrimary {
			primary[d.TenantID] = d.Domain
		}
	}
	r.mu.Lock()
	r.byDomain, r.primary = byDomain, primary
	r.mu.Unlock()
	return nil
}

// ByDomain returns the tenant serving a verified custom domain.
func (r *Registry) ByDomain(domain string) (store.Tenant, bool) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	t, ok := r.byID[r.byDomain[domain]]
	return t, ok
}

// PrimaryDomain is the tenant's primary custom domain, or "" if none.
func (r *Registry) PrimaryDomain(id string) string {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return r.primary[id]
}

// Run refreshes periodically so changes made by other API replicas are picked
// up. (With multiple replicas you would add LISTEN/NOTIFY for instant updates.)
func (r *Registry) Run(ctx context.Context, every time.Duration) {
	t := time.NewTicker(every)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			if err := r.Reload(ctx); err != nil {
				slog.Warn("tenant registry reload failed", "err", err)
			}
		}
	}
}

// Refresh reloads one tenant from the control DB (used when the engine reports
// that our cached config version is stale).
func (r *Registry) Refresh(ctx context.Context, id string) (store.Tenant, error) {
	t, err := r.store.GetTenant(ctx, id)
	r.mu.Lock()
	defer r.mu.Unlock()
	switch {
	case err == nil:
		r.byID[id] = t
	case errors.Is(err, store.ErrNotFound):
		delete(r.byID, id)
	}
	return t, err
}

func (r *Registry) Get(id string) (store.Tenant, bool) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	t, ok := r.byID[id]
	return t, ok
}

func (r *Registry) All() []store.Tenant {
	r.mu.RLock()
	out := make([]store.Tenant, 0, len(r.byID))
	for _, t := range r.byID {
		out = append(out, t)
	}
	r.mu.RUnlock()
	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	return out
}
