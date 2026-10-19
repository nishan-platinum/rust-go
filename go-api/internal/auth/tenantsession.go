package auth

import (
	"context"
	"time"

	"github.com/example/rust-go/go-api/internal/store"
)

// TenantSessions are sessions of tenant users on their own subdomain. Cookies
// are host-only (no Domain attribute), so the browser never sends acme's
// cookie to globex's subdomain; the server additionally binds every session
// to its tenant id.
type TenantSessions struct {
	sessionCookie
	store *store.Store
}

func NewTenantSessions(s *store.Store, ttl time.Duration, secure bool) *TenantSessions {
	return &TenantSessions{sessionCookie: newSessionCookie("scx_tsid", ttl, secure), store: s}
}

func (s *TenantSessions) Create(ctx context.Context, ts store.TenantSession) (string, error) {
	return s.CreateUntil(ctx, ts, time.Now().Add(s.ttl))
}

// CreateUntil is exposed so the isolation test can create expired sessions.
func (s *TenantSessions) CreateUntil(ctx context.Context, ts store.TenantSession, expires time.Time) (string, error) {
	raw := RandomToken(32)
	ts.CSRFToken = RandomToken(32)
	ts.ExpiresAt = expires
	if err := s.store.CreateTenantSession(ctx, hashToken(raw), ts); err != nil {
		return "", err
	}
	return raw, nil
}

func (s *TenantSessions) Lookup(ctx context.Context, raw, tenantID string) (store.TenantSession, error) {
	if raw == "" {
		return store.TenantSession{}, store.ErrNotFound
	}
	return s.store.TenantSessionByHash(ctx, hashToken(raw), tenantID)
}

func (s *TenantSessions) Logout(ctx context.Context, raw string) error {
	return s.store.DeleteTenantSession(ctx, hashToken(raw))
}
