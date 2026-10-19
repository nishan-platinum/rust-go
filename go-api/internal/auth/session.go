// Package auth holds the two independent auth mechanisms:
//   - admin sessions for the dashboard (server-side, cookie + CSRF), and
//   - tenant tokens (JWT) for the tenant data API.
package auth

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"time"

	"golang.org/x/crypto/bcrypt"

	"github.com/example/rust-go/go-api/internal/store"
)

var ErrBadCredentials = errors.New("invalid username or password")

func HashPassword(pw string) (string, error) {
	h, err := bcrypt.GenerateFromPassword([]byte(pw), bcryptCost)
	return string(h), err
}

func RandomToken(nBytes int) string {
	b := make([]byte, nBytes)
	if _, err := rand.Read(b); err != nil {
		panic(err) // crypto/rand failing is unrecoverable
	}
	return base64.RawURLEncoding.EncodeToString(b)
}

func hashToken(raw string) []byte {
	h := sha256.Sum256([]byte(raw))
	return h[:]
}

// Sessions are platform-admin sessions on the admin console.
type Sessions struct {
	sessionCookie
	store *store.Store
}

func NewSessions(s *store.Store, ttl time.Duration, secure bool) *Sessions {
	return &Sessions{sessionCookie: newSessionCookie("scx_sid", ttl, secure), store: s}
}

// Login verifies credentials and returns a new raw session token.
func (s *Sessions) Login(ctx context.Context, username, password, ua, ip string) (string, error) {
	a, err := s.store.AdminByUsername(ctx, username)
	if err != nil && !errors.Is(err, store.ErrNotFound) {
		return "", err
	}
	if !CheckPassword(a.PasswordHash, password) { // empty hash for unknown users
		return "", ErrBadCredentials
	}
	return s.Create(ctx, a.ID, ua, ip, time.Now().Add(s.ttl))
}

// Create issues a session. Exposed (with explicit expiry) so the isolation
// test can create already-expired sessions.
func (s *Sessions) Create(ctx context.Context, adminID int64, ua, ip string, expires time.Time) (string, error) {
	raw := RandomToken(32)
	if err := s.store.CreateSession(ctx, hashToken(raw), adminID, RandomToken(32), ua, ip, expires); err != nil {
		return "", err
	}
	return raw, nil
}

func (s *Sessions) Lookup(ctx context.Context, raw string) (store.Session, error) {
	if raw == "" {
		return store.Session{}, store.ErrNotFound
	}
	return s.store.SessionByHash(ctx, hashToken(raw))
}

func (s *Sessions) Logout(ctx context.Context, raw string) error {
	return s.store.DeleteSession(ctx, hashToken(raw))
}

func CSRFEqual(a, b string) bool {
	return a != "" && subtle.ConstantTimeCompare([]byte(a), []byte(b)) == 1
}
