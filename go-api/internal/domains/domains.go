// Package domains manages optional custom domains (e.g. support.acme.com).
// A tenant's subdomain always works; a custom domain is only served after
// the client proves ownership with a DNS TXT record.
package domains

import (
	"context"
	"errors"
	"fmt"
	"net"
	"regexp"
	"slices"
	"strings"

	"github.com/example/rust-go/go-api/internal/auth"
	"github.com/example/rust-go/go-api/internal/registry"
	"github.com/example/rust-go/go-api/internal/store"
)

var labelRe = regexp.MustCompile(`^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$`)

type Service struct {
	Store      *store.Store
	Registry   *registry.Registry
	BaseDomain string
	// DevAutoVerify verifies *.localhost domains without DNS (local testing only).
	DevAutoVerify bool
	// LookupTXT defaults to net.DefaultResolver.LookupTXT.
	LookupTXT func(ctx context.Context, name string) ([]string, error)
}

// ChallengeName is the TXT record that proves ownership of domain.
func ChallengeName(domain string) string { return "_scicomcx-challenge." + domain }

// CNAMETarget is where clients point their domain.
func (s *Service) CNAMETarget() string { return "tenants." + s.BaseDomain }

func (s *Service) devDomain(d string) bool {
	return s.DevAutoVerify && strings.HasSuffix(d, ".localhost")
}

// Normalize lower-cases and validates a domain typed by an admin. It accepts
// "https://Support.Acme.com/" and returns "support.acme.com".
func (s *Service) Normalize(raw string) (string, error) {
	d := strings.ToLower(strings.TrimSpace(raw))
	d = strings.TrimPrefix(strings.TrimPrefix(d, "https://"), "http://")
	d = strings.TrimSuffix(strings.SplitN(d, "/", 2)[0], ".")
	labels := strings.Split(d, ".")
	switch {
	case len(d) > 253 || len(labels) < 2 || net.ParseIP(d) != nil:
		return "", errors.New("enter a full domain name such as support.acme.com")
	case d == s.BaseDomain || strings.HasSuffix(d, "."+s.BaseDomain):
		return "", fmt.Errorf("%s domains are managed automatically; use the tenant's subdomain", s.BaseDomain)
	}
	for _, l := range labels {
		if !labelRe.MatchString(l) {
			return "", fmt.Errorf("%q is not a valid domain name", d)
		}
	}
	return d, nil
}

// Available normalizes raw and checks no tenant uses it yet (validation
// before a tenant is created).
func (s *Service) Available(ctx context.Context, raw string) (string, error) {
	d, err := s.Normalize(raw)
	if err != nil {
		return "", err
	}
	if _, err := s.Store.GetDomain(ctx, d); err == nil {
		return "", fmt.Errorf("%s is already used by another tenant", d)
	} else if !errors.Is(err, store.ErrNotFound) {
		return "", err
	}
	return d, nil
}

// liveDomains counts the tenant's verified domains.
func (s *Service) liveDomains(ctx context.Context, tenantID string) (int, error) {
	list, err := s.Store.ListDomains(ctx, tenantID)
	n := 0
	for _, d := range list {
		if d.Verified() {
			n++
		}
	}
	return n, err
}

var errLastAddress = errors.New("this is the workspace's last live address; turn the subdomain on or verify another domain first")

// SetSubdomain switches <id>.<BASE_DOMAIN> on or off. It can only be switched
// off while a verified custom domain keeps the workspace reachable.
func (s *Service) SetSubdomain(ctx context.Context, tenantID string, on bool, actor string) error {
	if !on {
		if n, err := s.liveDomains(ctx, tenantID); err != nil {
			return err
		} else if n == 0 {
			return errLastAddress
		}
	}
	if err := s.Store.SetSubdomainEnabled(ctx, tenantID, on); err != nil {
		return err
	}
	s.Store.Audit(ctx, actor, map[bool]string{true: "subdomain_on", false: "subdomain_off"}[on], tenantID, "")
	_, err := s.Registry.Refresh(ctx, tenantID)
	return err
}

// Add registers a pending domain (auto-verified for *.localhost in dev) and
// returns it as stored. A zero Domain means nothing was added.
func (s *Service) Add(ctx context.Context, tenantID, raw, actor string) (store.Domain, error) {
	name, err := s.Normalize(raw)
	if err != nil {
		return store.Domain{}, err
	}
	if err := s.Store.AddDomain(ctx, tenantID, name, auth.RandomToken(18)); err != nil {
		if errors.Is(err, store.ErrDuplicate) {
			err = fmt.Errorf("%s is already added (to this or another tenant)", name)
		}
		return store.Domain{}, err
	}
	s.Store.Audit(ctx, actor, "domain_added", tenantID, name)
	if s.devDomain(name) {
		err = s.Verify(ctx, tenantID, name, actor)
	}
	d, gerr := s.Store.GetDomain(ctx, name)
	return d, errors.Join(err, gerr)
}

// Verify checks the TXT record and, if it matches, starts serving the domain.
func (s *Service) Verify(ctx context.Context, tenantID, domain, actor string) error {
	d, err := s.Store.GetDomain(ctx, domain)
	if err != nil || d.TenantID != tenantID {
		return errors.New("unknown domain")
	}
	if !s.devDomain(domain) {
		lookup := s.LookupTXT
		if lookup == nil {
			lookup = net.DefaultResolver.LookupTXT
		}
		records, err := lookup(ctx, ChallengeName(domain))
		if err != nil || !slices.Contains(records, d.VerifyToken) {
			return fmt.Errorf("TXT record %s with the verification code was not found yet; DNS changes can take a few minutes", ChallengeName(domain))
		}
	}
	if err := s.Store.MarkDomainVerified(ctx, tenantID, domain); err != nil {
		return err
	}
	s.Store.Audit(ctx, actor, "domain_verified", tenantID, domain)
	// The first verified domain becomes primary, so links use it.
	if s.Registry.PrimaryDomain(tenantID) == "" {
		_ = s.Store.SetPrimaryDomain(ctx, tenantID, domain)
	}
	return s.Registry.ReloadDomains(ctx)
}

func (s *Service) SetPrimary(ctx context.Context, tenantID, domain, actor string) error {
	if err := s.Store.SetPrimaryDomain(ctx, tenantID, domain); err != nil {
		return errors.New("only a verified domain of this tenant can be primary")
	}
	s.Store.Audit(ctx, actor, "domain_primary", tenantID, domain)
	return s.Registry.ReloadDomains(ctx)
}

// Remove stops serving the domain immediately. The last live address of a
// tenant without subdomain cannot be removed.
func (s *Service) Remove(ctx context.Context, tenantID, domain, actor string) error {
	if t, ok := s.Registry.Get(tenantID); ok && !t.SubdomainEnabled {
		if d, err := s.Store.GetDomain(ctx, domain); err == nil && d.Verified() {
			if n, err := s.liveDomains(ctx, tenantID); err == nil && n <= 1 {
				return errLastAddress
			}
		}
	}
	if err := s.Store.DeleteDomain(ctx, tenantID, domain); err != nil {
		return err
	}
	s.Store.Audit(ctx, actor, "domain_removed", tenantID, domain)
	if s.Registry.PrimaryDomain(tenantID) == domain {
		// Promote another verified domain so links keep working.
		list, _ := s.Store.ListDomains(ctx, tenantID)
		for _, d := range list {
			if d.Verified() {
				_ = s.Store.SetPrimaryDomain(ctx, tenantID, d.Domain)
				break
			}
		}
	}
	return s.Registry.ReloadDomains(ctx)
}

// TLSAllowed answers a TLS proxy (e.g. Caddy on-demand TLS): may a
// certificate be issued for this host? Only for hosts we actually serve.
func (s *Service) TLSAllowed(host string) bool {
	if _, ok := s.Registry.ByDomain(host); ok {
		return true
	}
	if host == s.BaseDomain || host == "admin."+s.BaseDomain {
		return true
	}
	sub, ok := strings.CutSuffix(host, "."+s.BaseDomain)
	if !ok {
		return false
	}
	t, ok := s.Registry.Get(sub)
	return ok && t.SubdomainEnabled
}
