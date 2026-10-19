// Package config loads service configuration from environment variables and
// fails fast on anything missing or weak.
package config

import (
	"encoding/base64"
	"errors"
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"
)

type Config struct {
	HTTPAddr      string
	ControlDBURL  string
	EngineAddr    string
	EngineToken   string
	MasterKey     []byte // AES-256 key for tenant DB passwords at rest
	JWTSecret     []byte
	AdminUsername string
	AdminPassword string
	SeedFile      string
	CookieSecure  bool
	SessionTTL    time.Duration
	TokenTTL      time.Duration
	EngineTimeout time.Duration
	// Base URL the isolation test uses to call this server over real HTTP.
	SelfBaseURL string

	// Tenants are served at <tenant>.<BaseDomain>; the admin console at
	// admin.<BaseDomain> (and the bare domain / IP addresses).
	BaseDomain   string
	PublicScheme string
	PublicPort   string // empty when using the scheme's default port

	// Verify *.localhost custom domains without DNS (local testing only).
	DomainDevAutoVerify bool
}

// HostURL is the public URL of a host served by this platform.
func (c *Config) HostURL(host string) string {
	if c.PublicPort == "" {
		return c.PublicScheme + "://" + host
	}
	return c.PublicScheme + "://" + host + ":" + c.PublicPort
}

// TenantURL is the public portal URL of a tenant.
func (c *Config) TenantURL(id string) string { return c.HostURL(id + "." + c.BaseDomain) }

// AdminURL is the public URL of the platform admin console.
func (c *Config) AdminURL() string { return c.HostURL("admin." + c.BaseDomain) }

func Load() (*Config, error) {
	var errs []error
	req := func(key string) string {
		v := os.Getenv(key)
		if v == "" {
			errs = append(errs, fmt.Errorf("%s is required", key))
		}
		return v
	}

	c := &Config{
		HTTPAddr:      env("HTTP_ADDR", "127.0.0.1:8080"),
		ControlDBURL:  req("CONTROL_DB_URL"),
		EngineAddr:    env("ENGINE_ADDR", "127.0.0.1:50051"),
		EngineToken:   req("ENGINE_INTERNAL_TOKEN"),
		JWTSecret:     []byte(req("JWT_SECRET")),
		AdminUsername: env("ADMIN_USERNAME", "admin"),
		AdminPassword: os.Getenv("ADMIN_PASSWORD"),
		SeedFile:      os.Getenv("SEED_FILE"),
		CookieSecure:  envBool("COOKIE_SECURE", true),
		SessionTTL:    envDuration("SESSION_TTL", 8*time.Hour),
		TokenTTL:      envDuration("TOKEN_TTL", 15*time.Minute),
		EngineTimeout: envDuration("ENGINE_TIMEOUT", 10*time.Second),

		DomainDevAutoVerify: envBool("DOMAIN_DEV_AUTOVERIFY", false),
	}
	c.SelfBaseURL = env("SELF_BASE_URL", "http://"+loopback(c.HTTPAddr))
	c.BaseDomain = strings.ToLower(strings.Trim(env("BASE_DOMAIN", "scicomcx.localhost"), "."))
	c.PublicScheme = env("PUBLIC_SCHEME", "http")
	c.PublicPort = env("PUBLIC_PORT", port(c.HTTPAddr))
	if c.PublicPort == "80" && c.PublicScheme == "http" || c.PublicPort == "443" && c.PublicScheme == "https" {
		c.PublicPort = ""
	}

	if mk := req("MASTER_KEY"); mk != "" {
		key, err := base64.StdEncoding.DecodeString(mk)
		if err != nil || len(key) != 32 {
			errs = append(errs, errors.New("MASTER_KEY must be 32 bytes, base64 encoded"))
		}
		c.MasterKey = key
	}
	if len(c.JWTSecret) > 0 && len(c.JWTSecret) < 32 {
		errs = append(errs, errors.New("JWT_SECRET must be at least 32 bytes"))
	}
	if len(c.EngineToken) > 0 && len(c.EngineToken) < 16 {
		errs = append(errs, errors.New("ENGINE_INTERNAL_TOKEN must be at least 16 characters"))
	}
	return c, errors.Join(errs...)
}

// loopback turns a listen address like 0.0.0.0:8080 into 127.0.0.1:8080.
func loopback(addr string) string {
	for i := len(addr) - 1; i >= 0; i-- {
		if addr[i] == ':' {
			return "127.0.0.1" + addr[i:]
		}
	}
	return addr
}

func port(addr string) string {
	if i := strings.LastIndexByte(addr, ':'); i >= 0 {
		return addr[i+1:]
	}
	return ""
}

func env(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return def
}

func envBool(key string, def bool) bool {
	if b, err := strconv.ParseBool(os.Getenv(key)); err == nil {
		return b
	}
	return def
}

func envDuration(key string, def time.Duration) time.Duration {
	if d, err := time.ParseDuration(os.Getenv(key)); err == nil {
		return d
	}
	return def
}
