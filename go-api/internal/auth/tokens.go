package auth

import (
	"errors"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

const (
	tokenIssuer   = "rust-go-api"
	tokenAudience = "tenant-api"
)

// TenantClaims binds a token to exactly one tenant (tid) and to the tenant's
// current token version (tv). Bumping tv revokes all outstanding tokens.
type TenantClaims struct {
	TenantID     string `json:"tid"`
	TokenVersion int64  `json:"tv"`
	jwt.RegisteredClaims
}

type Tokens struct {
	secret []byte
	ttl    time.Duration
}

func NewTokens(secret []byte, ttl time.Duration) *Tokens {
	return &Tokens{secret: secret, ttl: ttl}
}

func (t *Tokens) TTL() time.Duration { return t.ttl }

func (t *Tokens) Mint(tenantID string, tokenVersion int64) (string, error) {
	return t.MintWith(tenantID, tokenVersion, time.Now(), t.ttl, tokenAudience)
}

// MintWith exposes every knob so the isolation test can build expired or
// wrong-audience tokens with the real key.
func (t *Tokens) MintWith(tenantID string, tokenVersion int64, now time.Time, ttl time.Duration, audience string) (string, error) {
	claims := TenantClaims{
		TenantID:     tenantID,
		TokenVersion: tokenVersion,
		RegisteredClaims: jwt.RegisteredClaims{
			Issuer:    tokenIssuer,
			Subject:   "tenant:" + tenantID,
			Audience:  jwt.ClaimStrings{audience},
			IssuedAt:  jwt.NewNumericDate(now),
			NotBefore: jwt.NewNumericDate(now),
			ExpiresAt: jwt.NewNumericDate(now.Add(ttl)),
			ID:        RandomToken(12),
		},
	}
	return jwt.NewWithClaims(jwt.SigningMethodHS256, claims).SignedString(t.secret)
}

var ErrInvalidToken = errors.New("invalid token")

// Verify checks signature, algorithm (HS256 only, so "none" and alg
// confusion are rejected), issuer, audience and expiry.
func (t *Tokens) Verify(raw string) (*TenantClaims, error) {
	var c TenantClaims
	_, err := jwt.ParseWithClaims(raw, &c,
		func(*jwt.Token) (any, error) { return t.secret, nil },
		jwt.WithValidMethods([]string{jwt.SigningMethodHS256.Alg()}),
		jwt.WithIssuer(tokenIssuer),
		jwt.WithAudience(tokenAudience),
		jwt.WithExpirationRequired(),
		jwt.WithIssuedAt(),
		jwt.WithLeeway(5*time.Second),
	)
	if err != nil {
		return nil, errors.Join(ErrInvalidToken, err)
	}
	if c.TenantID == "" {
		return nil, errors.Join(ErrInvalidToken, errors.New("missing tid"))
	}
	return &c, nil
}
