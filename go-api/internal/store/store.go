// Package store is the control-plane database: admins, sessions, the tenant
// registry and the audit log. It lives in PostgreSQL.
package store

import (
	"context"
	_ "embed"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/example/rust-go/go-api/internal/secret"
)

//go:embed schema.sql
var schema string

var (
	ErrNotFound  = errors.New("not found")
	ErrDuplicate = errors.New("already exists")
)

type Store struct {
	db  *pgxpool.Pool
	box *secret.Box
}

func Open(ctx context.Context, url string, box *secret.Box) (*Store, error) {
	db, err := pgxpool.New(ctx, url)
	if err != nil {
		return nil, err
	}
	// The control DB may still be starting; retry briefly.
	for i := 0; ; i++ {
		if err = db.Ping(ctx); err == nil || i == 30 {
			break
		}
		time.Sleep(time.Second)
	}
	if err != nil {
		db.Close()
		return nil, fmt.Errorf("control db: %w", err)
	}
	return &Store{db: db, box: box}, nil
}

func (s *Store) Close() { s.db.Close() }

func (s *Store) Migrate(ctx context.Context) error {
	_, err := s.db.Exec(ctx, schema)
	return err
}

func mapErr(err error) error {
	if errors.Is(err, pgx.ErrNoRows) {
		return ErrNotFound
	}
	var pg *pgconn.PgError
	if errors.As(err, &pg) && pg.Code == "23505" {
		return fmt.Errorf("%w: %s", ErrDuplicate, pg.ConstraintName)
	}
	return err
}

// ---- admins ---------------------------------------------------------------

type Admin struct {
	ID           int64
	Username     string
	PasswordHash string
}

// EnsureAdmin creates the admin if it does not exist. It never overwrites an
// existing password.
func (s *Store) EnsureAdmin(ctx context.Context, username, hash string) (created bool, err error) {
	tag, err := s.db.Exec(ctx,
		`INSERT INTO admins (username, password_hash) VALUES ($1, $2) ON CONFLICT (username) DO NOTHING`,
		username, hash)
	return tag.RowsAffected() == 1, err
}

func (s *Store) AdminByUsername(ctx context.Context, username string) (Admin, error) {
	var a Admin
	err := s.db.QueryRow(ctx,
		`SELECT id, username, password_hash FROM admins WHERE username = $1`, username,
	).Scan(&a.ID, &a.Username, &a.PasswordHash)
	return a, mapErr(err)
}

// ---- sessions -------------------------------------------------------------

type Session struct {
	AdminID   int64
	Username  string
	CSRFToken string
	ExpiresAt time.Time
}

func (s *Store) CreateSession(ctx context.Context, tokenHash []byte, adminID int64, csrf, ua, ip string, expires time.Time) error {
	_, err := s.db.Exec(ctx,
		`INSERT INTO sessions (token_hash, admin_id, csrf_token, user_agent, ip, expires_at)
		 VALUES ($1, $2, $3, $4, $5, $6)`,
		tokenHash, adminID, csrf, ua, ip, expires)
	return err
}

// SessionByHash returns only unexpired sessions.
func (s *Store) SessionByHash(ctx context.Context, tokenHash []byte) (Session, error) {
	var ss Session
	err := s.db.QueryRow(ctx,
		`SELECT s.admin_id, a.username, s.csrf_token, s.expires_at
		 FROM sessions s JOIN admins a ON a.id = s.admin_id
		 WHERE s.token_hash = $1 AND s.expires_at > now()`, tokenHash,
	).Scan(&ss.AdminID, &ss.Username, &ss.CSRFToken, &ss.ExpiresAt)
	return ss, mapErr(err)
}

func (s *Store) DeleteSession(ctx context.Context, tokenHash []byte) error {
	_, err := s.db.Exec(ctx, `DELETE FROM sessions WHERE token_hash = $1`, tokenHash)
	return err
}

// PurgeExpiredSessions removes expired admin and tenant-portal sessions.
func (s *Store) PurgeExpiredSessions(ctx context.Context) (int64, error) {
	a, err := s.db.Exec(ctx, `DELETE FROM sessions WHERE expires_at <= now()`)
	if err != nil {
		return 0, err
	}
	t, err := s.db.Exec(ctx, `DELETE FROM tenant_sessions WHERE expires_at <= now()`)
	return a.RowsAffected() + t.RowsAffected(), err
}

// ---- tenant portal sessions -------------------------------------------------

type TenantSession struct {
	TenantID  string
	UserID    string
	Email     string
	Name      string
	Role      string
	CSRFToken string
	ExpiresAt time.Time
}

func (s *Store) CreateTenantSession(ctx context.Context, tokenHash []byte, ts TenantSession) error {
	_, err := s.db.Exec(ctx,
		`INSERT INTO tenant_sessions (token_hash, tenant_id, user_id, email, name, role, csrf_token, expires_at)
		 VALUES ($1, $2, $3, $4, $5, $6, $7, $8)`,
		tokenHash, ts.TenantID, ts.UserID, ts.Email, ts.Name, ts.Role, ts.CSRFToken, ts.ExpiresAt)
	return err
}

// TenantSessionByHash only matches an unexpired session *of this tenant*, so
// a cookie replayed on another tenant's subdomain is rejected.
func (s *Store) TenantSessionByHash(ctx context.Context, tokenHash []byte, tenantID string) (TenantSession, error) {
	var ts TenantSession
	err := s.db.QueryRow(ctx,
		`SELECT tenant_id, user_id, email, name, role, csrf_token, expires_at FROM tenant_sessions
		 WHERE token_hash = $1 AND tenant_id = $2 AND expires_at > now()`, tokenHash, tenantID,
	).Scan(&ts.TenantID, &ts.UserID, &ts.Email, &ts.Name, &ts.Role, &ts.CSRFToken, &ts.ExpiresAt)
	return ts, mapErr(err)
}

func (s *Store) DeleteTenantSession(ctx context.Context, tokenHash []byte) error {
	_, err := s.db.Exec(ctx, `DELETE FROM tenant_sessions WHERE token_hash = $1`, tokenHash)
	return err
}

// ---- database servers -------------------------------------------------------

type DBServer struct {
	ID            int64
	Name          string
	DBType        string
	Host          string
	Port          int
	AdminUsername string
	AdminPassword string // plaintext in memory only
	Params        map[string]string
	IsDefault     bool
	TenantCount   int
}

// Server passwords are bound to the server name as associated data.
func serverAAD(name string) string { return "dbserver:" + name }

const serverCols = `s.id, s.name, s.db_type, s.host, s.port, s.admin_username, s.admin_password_enc,
	s.params, s.is_default, (SELECT count(*) FROM tenants t WHERE t.server_id = s.id)`

func (s *Store) scanServer(row pgx.Row) (DBServer, error) {
	var d DBServer
	var enc, params []byte
	err := row.Scan(&d.ID, &d.Name, &d.DBType, &d.Host, &d.Port, &d.AdminUsername, &enc, &params,
		&d.IsDefault, &d.TenantCount)
	if err != nil {
		return d, mapErr(err)
	}
	if err := json.Unmarshal(params, &d.Params); err != nil {
		return d, err
	}
	if d.AdminPassword, err = s.box.Open(enc, serverAAD(d.Name)); err != nil {
		return d, fmt.Errorf("server %s: %w", d.Name, err)
	}
	return d, nil
}

func (s *Store) ListServers(ctx context.Context) ([]DBServer, error) {
	rows, err := s.db.Query(ctx, `SELECT `+serverCols+` FROM db_servers s ORDER BY s.db_type, s.name`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []DBServer
	for rows.Next() {
		d, err := s.scanServer(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, d)
	}
	return out, rows.Err()
}

func (s *Store) GetServer(ctx context.Context, id int64) (DBServer, error) {
	return s.scanServer(s.db.QueryRow(ctx, `SELECT `+serverCols+` FROM db_servers s WHERE s.id = $1`, id))
}

func (s *Store) DefaultServer(ctx context.Context, dbType string) (DBServer, error) {
	return s.scanServer(s.db.QueryRow(ctx,
		`SELECT `+serverCols+` FROM db_servers s WHERE s.db_type = $1 ORDER BY s.is_default DESC, s.id LIMIT 1`, dbType))
}

// CreateServer inserts a server; the first server of a type becomes its default.
func (s *Store) CreateServer(ctx context.Context, d DBServer) (int64, error) {
	enc, err := s.box.Seal(d.AdminPassword, serverAAD(d.Name))
	if err != nil {
		return 0, err
	}
	params, _ := json.Marshal(nonNil(d.Params))
	var id int64
	err = s.db.QueryRow(ctx,
		`INSERT INTO db_servers (name, db_type, host, port, admin_username, admin_password_enc, params, is_default)
		 VALUES ($1, $2, $3, $4, $5, $6, $7, NOT EXISTS (SELECT 1 FROM db_servers WHERE db_type = $2))
		 RETURNING id`,
		d.Name, d.DBType, d.Host, d.Port, d.AdminUsername, enc, params).Scan(&id)
	return id, mapErr(err)
}

func (s *Store) SetDefaultServer(ctx context.Context, id int64) error {
	tx, err := s.db.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)
	var dbType string
	if err := tx.QueryRow(ctx, `SELECT db_type FROM db_servers WHERE id = $1`, id).Scan(&dbType); err != nil {
		return mapErr(err)
	}
	if _, err := tx.Exec(ctx, `UPDATE db_servers SET is_default = false WHERE db_type = $1`, dbType); err != nil {
		return err
	}
	if _, err := tx.Exec(ctx, `UPDATE db_servers SET is_default = true WHERE id = $1`, id); err != nil {
		return err
	}
	return tx.Commit(ctx)
}

var ErrInUse = errors.New("still in use")

func (s *Store) DeleteServer(ctx context.Context, id int64) error {
	tag, err := s.db.Exec(ctx, `DELETE FROM db_servers WHERE id = $1`, id)
	var pg *pgconn.PgError
	if errors.As(err, &pg) && pg.Code == "23503" {
		return ErrInUse
	}
	if err == nil && tag.RowsAffected() == 0 {
		return ErrNotFound
	}
	return err
}

func (s *Store) CountServers(ctx context.Context) (int, error) {
	var n int
	err := s.db.QueryRow(ctx, `SELECT count(*) FROM db_servers`).Scan(&n)
	return n, err
}

// ---- tenants --------------------------------------------------------------

type Tenant struct {
	ID            string            `json:"id"`
	Name          string            `json:"name"`
	DBType        string            `json:"db_type"`
	Host          string            `json:"host"`
	Port          int               `json:"port"`
	Username      string            `json:"username"`
	Password      string            `json:"password"` // plaintext in memory only
	Database      string            `json:"database"`
	Params        map[string]string `json:"params"`
	ConfigVersion int64             `json:"-"`
	TokenVersion  int64             `json:"-"`
	Enabled       bool              `json:"-"`
	Mode          string            `json:"-"` // "managed" or "external"
	ServerID      *int64            `json:"-"` // set for managed tenants
	// SubdomainEnabled: whether <id>.<BASE_DOMAIN> is served.
	SubdomainEnabled bool      `json:"-"`
	CreatedAt        time.Time `json:"-"`
	UpdatedAt        time.Time `json:"-"`
}

func (t Tenant) Managed() bool { return t.Mode == "managed" }

const tenantCols = `id, name, db_type, host, port, username, password_enc, database, params,
	config_version, token_version, enabled, mode, server_id, subdomain_enabled, created_at, updated_at`

func (s *Store) scanTenant(row pgx.Row) (Tenant, error) {
	var t Tenant
	var enc, params []byte
	err := row.Scan(&t.ID, &t.Name, &t.DBType, &t.Host, &t.Port, &t.Username, &enc, &t.Database,
		&params, &t.ConfigVersion, &t.TokenVersion, &t.Enabled, &t.Mode, &t.ServerID, &t.SubdomainEnabled, &t.CreatedAt, &t.UpdatedAt)
	if err != nil {
		return t, mapErr(err)
	}
	if err := json.Unmarshal(params, &t.Params); err != nil {
		return t, err
	}
	t.Password, err = s.box.Open(enc, t.ID)
	if err != nil {
		return t, fmt.Errorf("tenant %s: %w", t.ID, err)
	}
	return t, nil
}

func (s *Store) ListTenants(ctx context.Context) ([]Tenant, error) {
	rows, err := s.db.Query(ctx, `SELECT `+tenantCols+` FROM tenants ORDER BY id`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Tenant
	for rows.Next() {
		t, err := s.scanTenant(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, t)
	}
	return out, rows.Err()
}

func (s *Store) GetTenant(ctx context.Context, id string) (Tenant, error) {
	return s.scanTenant(s.db.QueryRow(ctx, `SELECT `+tenantCols+` FROM tenants WHERE id = $1`, id))
}

func (s *Store) CreateTenant(ctx context.Context, t Tenant) error {
	enc, err := s.box.Seal(t.Password, t.ID)
	if err != nil {
		return err
	}
	params, _ := json.Marshal(nonNil(t.Params))
	if t.Mode == "" {
		t.Mode = "external"
	}
	_, err = s.db.Exec(ctx,
		`INSERT INTO tenants (id, name, db_type, host, port, username, password_enc, database, params, mode, server_id, subdomain_enabled)
		 VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12)`,
		t.ID, t.Name, t.DBType, t.Host, t.Port, t.Username, enc, t.Database, params, t.Mode, t.ServerID, t.SubdomainEnabled)
	return mapErr(err)
}

// UpdateTenantConn changes connection details and bumps config_version so the
// engine drops the old pool on the next request.
func (s *Store) UpdateTenantConn(ctx context.Context, t Tenant) (int64, error) {
	enc, err := s.box.Seal(t.Password, t.ID)
	if err != nil {
		return 0, err
	}
	params, _ := json.Marshal(nonNil(t.Params))
	var v int64
	err = s.db.QueryRow(ctx,
		`UPDATE tenants SET name = $2, db_type = $3, host = $4, port = $5, username = $6,
		        password_enc = $7, database = $8, params = $9,
		        config_version = config_version + 1, updated_at = now()
		 WHERE id = $1 RETURNING config_version`,
		t.ID, t.Name, t.DBType, t.Host, t.Port, t.Username, enc, t.Database, params,
	).Scan(&v)
	return v, mapErr(err)
}

func (s *Store) SetTenantEnabled(ctx context.Context, id string, enabled bool) error {
	return s.execOne(ctx, `UPDATE tenants SET enabled = $2, updated_at = now() WHERE id = $1`, id, enabled)
}

func (s *Store) SetSubdomainEnabled(ctx context.Context, id string, on bool) error {
	return s.execOne(ctx, `UPDATE tenants SET subdomain_enabled = $2, updated_at = now() WHERE id = $1`, id, on)
}

// BumpTokenVersion revokes every token previously issued to the tenant.
func (s *Store) BumpTokenVersion(ctx context.Context, id string) (int64, error) {
	var v int64
	err := s.db.QueryRow(ctx,
		`UPDATE tenants SET token_version = token_version + 1, updated_at = now()
		 WHERE id = $1 RETURNING token_version`, id).Scan(&v)
	return v, mapErr(err)
}

func (s *Store) DeleteTenant(ctx context.Context, id string) error {
	return s.execOne(ctx, `DELETE FROM tenants WHERE id = $1`, id)
}

func nonNil(m map[string]string) map[string]string {
	if m == nil {
		return map[string]string{}
	}
	return m
}

// ---- custom domains -----------------------------------------------------------

type Domain struct {
	Domain      string
	TenantID    string
	VerifyToken string
	VerifiedAt  *time.Time
	IsPrimary   bool
}

func (d Domain) Verified() bool { return d.VerifiedAt != nil }

func (s *Store) ListDomains(ctx context.Context, tenantID string) ([]Domain, error) {
	return s.queryDomains(ctx, `WHERE tenant_id = $1 ORDER BY is_primary DESC, domain`, tenantID)
}

// AllVerifiedDomains feeds the router's domain -> tenant map.
func (s *Store) AllVerifiedDomains(ctx context.Context) ([]Domain, error) {
	return s.queryDomains(ctx, `WHERE verified_at IS NOT NULL`)
}

func (s *Store) GetDomain(ctx context.Context, domain string) (Domain, error) {
	list, err := s.queryDomains(ctx, `WHERE domain = $1`, domain)
	if err == nil && len(list) == 0 {
		err = ErrNotFound
	}
	if err != nil {
		return Domain{}, err
	}
	return list[0], nil
}

func (s *Store) queryDomains(ctx context.Context, where string, args ...any) ([]Domain, error) {
	rows, err := s.db.Query(ctx,
		`SELECT domain, tenant_id, verify_token, verified_at, is_primary FROM tenant_domains `+where, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Domain
	for rows.Next() {
		var d Domain
		if err := rows.Scan(&d.Domain, &d.TenantID, &d.VerifyToken, &d.VerifiedAt, &d.IsPrimary); err != nil {
			return nil, err
		}
		out = append(out, d)
	}
	return out, rows.Err()
}

func (s *Store) AddDomain(ctx context.Context, tenantID, domain, token string) error {
	_, err := s.db.Exec(ctx,
		`INSERT INTO tenant_domains (domain, tenant_id, verify_token) VALUES ($1, $2, $3)`,
		domain, tenantID, token)
	return mapErr(err)
}

func (s *Store) MarkDomainVerified(ctx context.Context, tenantID, domain string) error {
	return s.execOne(ctx, `UPDATE tenant_domains SET verified_at = now() WHERE domain = $1 AND tenant_id = $2`, domain, tenantID)
}

// SetPrimaryDomain makes a verified domain the tenant's primary one.
func (s *Store) SetPrimaryDomain(ctx context.Context, tenantID, domain string) error {
	tx, err := s.db.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)
	if _, err := tx.Exec(ctx, `UPDATE tenant_domains SET is_primary = false WHERE tenant_id = $1`, tenantID); err != nil {
		return err
	}
	tag, err := tx.Exec(ctx,
		`UPDATE tenant_domains SET is_primary = true WHERE domain = $1 AND tenant_id = $2 AND verified_at IS NOT NULL`,
		domain, tenantID)
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		return ErrNotFound
	}
	return tx.Commit(ctx)
}

func (s *Store) DeleteDomain(ctx context.Context, tenantID, domain string) error {
	return s.execOne(ctx, `DELETE FROM tenant_domains WHERE domain = $1 AND tenant_id = $2`, domain, tenantID)
}

// execOne runs a statement that must affect exactly one row.
func (s *Store) execOne(ctx context.Context, sql string, args ...any) error {
	tag, err := s.db.Exec(ctx, sql, args...)
	if err == nil && tag.RowsAffected() == 0 {
		return ErrNotFound
	}
	return err
}

// ---- audit ----------------------------------------------------------------

type AuditEntry struct {
	At       time.Time
	Actor    string
	Action   string
	TenantID string
	Detail   string
}

func (s *Store) Audit(ctx context.Context, actor, action, tenantID, detail string) {
	// Audit must never break the request, so failures are logged, not returned.
	_, err := s.db.Exec(ctx,
		`INSERT INTO audit_log (actor, action, tenant_id, detail) VALUES ($1, $2, $3, $4)`,
		actor, action, tenantID, detail)
	if err != nil {
		slog.Error("audit write failed", "action", action, "err", err)
	}
}

func (s *Store) RecentAudit(ctx context.Context, limit int) ([]AuditEntry, error) {
	rows, err := s.db.Query(ctx,
		`SELECT at, actor, action, tenant_id, detail FROM audit_log ORDER BY at DESC LIMIT $1`, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []AuditEntry
	for rows.Next() {
		var e AuditEntry
		if err := rows.Scan(&e.At, &e.Actor, &e.Action, &e.TenantID, &e.Detail); err != nil {
			return nil, err
		}
		out = append(out, e)
	}
	return out, rows.Err()
}
