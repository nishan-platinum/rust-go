package auth

import (
	"net/http"
	"sync"
	"time"

	"golang.org/x/crypto/bcrypt"
)

// sessionCookie is the host-only cookie shared by admin and tenant sessions.
// Host-only (no Domain attribute) means a cookie set on acme's subdomain is
// never sent to another subdomain.
type sessionCookie struct {
	name   string
	ttl    time.Duration
	secure bool
}

// newSessionCookie uses the __Host- prefix over HTTPS, which pins the cookie
// to this exact host and path "/".
func newSessionCookie(base string, ttl time.Duration, secure bool) sessionCookie {
	if secure {
		base = "__Host-" + base
	}
	return sessionCookie{name: base, ttl: ttl, secure: secure}
}

func (c sessionCookie) CookieName() string { return c.name }

func (c sessionCookie) SetCookie(w http.ResponseWriter, raw string) {
	c.write(w, raw, int(c.ttl.Seconds()))
}

func (c sessionCookie) ClearCookie(w http.ResponseWriter) { c.write(w, "", -1) }

func (c sessionCookie) write(w http.ResponseWriter, value string, maxAge int) {
	http.SetCookie(w, &http.Cookie{
		Name: c.name, Value: value, Path: "/", MaxAge: maxAge,
		HttpOnly: true, Secure: c.secure, SameSite: http.SameSiteStrictMode,
	})
}

// dummyHash is compared against when a login names an unknown user, so it
// costs the same as a real check (no user enumeration via timing). Computed
// once, on first use.
var dummyHash = sync.OnceValue(func() []byte {
	h, _ := bcrypt.GenerateFromPassword([]byte("dummy-password"), bcryptCost)
	return h
})

const bcryptCost = 12

// CheckPassword compares a bcrypt hash; an empty hash (unknown user) still
// spends the time of a real comparison and returns false.
func CheckPassword(hash, password string) bool {
	if hash == "" {
		_ = bcrypt.CompareHashAndPassword(dummyHash(), []byte(password))
		return false
	}
	return bcrypt.CompareHashAndPassword([]byte(hash), []byte(password)) == nil
}
