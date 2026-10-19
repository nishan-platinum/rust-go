use std::collections::HashMap;

use sqlx::PgPool;
use sqlx::postgres::{PgConnectOptions, PgSslMode};

use super::{ItemRow, Login, NewUser, PoolSettings, UserRow, map_user_err, pool_options};
use crate::error::{EngineError, Result};
use crate::pb::{Item, ProvisionResult, TenantConn, TenantUser, WhoAmIResult};

const UNDEFINED_TABLE: &str = "42P01";

fn ssl_mode(params: &HashMap<String, String>) -> Result<PgSslMode> {
    Ok(match params.get("sslmode").map(String::as_str) {
        None | Some("prefer") => PgSslMode::Prefer,
        Some("disable") => PgSslMode::Disable,
        Some("require") => PgSslMode::Require,
        Some("verify-ca") => PgSslMode::VerifyCa,
        Some("verify-full") => PgSslMode::VerifyFull,
        Some(other) => return Err(EngineError::Invalid(format!("unknown sslmode '{other}'"))),
    })
}

/// Connection options shared by tenant pools and server-admin connections.
/// `app` shows up in pg_stat_activity so DBAs can attribute connections.
pub fn options(l: &Login, database: &str, app: &str) -> Result<PgConnectOptions> {
    Ok(PgConnectOptions::new_without_pgpass()
        .host(l.host)
        .port(l.port as u16)
        .username(l.user)
        .password(l.password)
        .database(database)
        .ssl_mode(ssl_mode(l.params)?)
        .application_name(app))
}

pub async fn connect(c: &TenantConn, s: &PoolSettings) -> Result<PgPool> {
    let app = format!("rust-engine/{}", c.tenant_id);
    let opts = options(&Login::tenant(c), &c.database, &app)?;
    Ok(pool_options(s).connect_with(opts).await?)
}

fn is_undefined_table(e: &sqlx::Error) -> bool {
    matches!(e, sqlx::Error::Database(d) if d.code().as_deref() == Some(UNDEFINED_TABLE))
}

pub async fn claim_owner(p: &PgPool) -> Result<Option<String>> {
    match sqlx::query_scalar("SELECT tenant_id FROM tenant_meta WHERE id = 1")
        .fetch_optional(p)
        .await
    {
        Err(e) if is_undefined_table(&e) => Ok(None),
        r => Ok(r?),
    }
}

pub async fn server_version(p: &PgPool) -> Result<String> {
    Ok(sqlx::query_scalar("SELECT version()").fetch_one(p).await?)
}

pub async fn provision(p: &PgPool, tenant_id: &str) -> Result<ProvisionResult> {
    let mut tx = p.begin().await?;
    for ddl in [
        "CREATE TABLE IF NOT EXISTS tenant_meta (
            id         int PRIMARY KEY DEFAULT 1 CHECK (id = 1),
            tenant_id  text NOT NULL,
            claimed_at timestamptz NOT NULL DEFAULT now()
        )",
        "CREATE TABLE IF NOT EXISTS items (
            id         bigserial PRIMARY KEY,
            name       text NOT NULL,
            owner      text NOT NULL,
            nonce      text NOT NULL,
            created_at timestamptz NOT NULL DEFAULT now()
        )",
        "CREATE TABLE IF NOT EXISTS tenant_users (
            id            bigserial PRIMARY KEY,
            email         text NOT NULL UNIQUE,
            name          text NOT NULL,
            role          text NOT NULL,
            password_hash text NOT NULL,
            created_at    timestamptz NOT NULL DEFAULT now()
        )",
    ] {
        sqlx::query(ddl).execute(&mut *tx).await?;
    }
    let inserted: Option<String> = sqlx::query_scalar(
        "INSERT INTO tenant_meta (id, tenant_id) VALUES (1, $1)
         ON CONFLICT (id) DO NOTHING RETURNING tenant_id",
    )
    .bind(tenant_id)
    .fetch_optional(&mut *tx)
    .await?;
    let owner: String = sqlx::query_scalar("SELECT tenant_id FROM tenant_meta WHERE id = 1")
        .fetch_one(&mut *tx)
        .await?;
    tx.commit().await?;
    super::claim_result(owner, tenant_id, inserted.is_some())
}

pub async fn whoami(p: &PgPool, tenant_id: &str) -> Result<WhoAmIResult> {
    // All statements must run on the same physical connection.
    let mut conn = p.acquire().await?;

    let prev: Option<String> = sqlx::query_scalar("SELECT current_setting('app.tenant_id', true)")
        .fetch_one(&mut *conn)
        .await?;
    // Session-level (is_local = false): deliberately survives on the pooled
    // connection so the next request can detect where it came from.
    sqlx::query("SELECT set_config('app.tenant_id', $1, false)")
        .bind(tenant_id)
        .execute(&mut *conn)
        .await?;

    // Marker and session details in one round trip.
    let row: Option<(String, String, String, String)> = match sqlx::query_as(
        "SELECT tenant_id, current_database()::text, pg_backend_pid()::text,
                current_setting('server_version')
         FROM tenant_meta WHERE id = 1",
    )
    .fetch_optional(&mut *conn)
    .await
    {
        Err(e) if is_undefined_table(&e) => None,
        r => r?,
    };
    let (marker, database, pid, version) = row.ok_or(EngineError::NotProvisioned)?;

    Ok(WhoAmIResult {
        marker_tenant_id: marker,
        database,
        server_version: format!("PostgreSQL {version}"),
        session_id: pid,
        session_tag: prev.unwrap_or_default(),
    })
}

const ITEM_COLUMNS: &str = "id::text, name, owner, nonce, extract(epoch FROM created_at)::bigint";

pub async fn list_items(p: &PgPool, limit: u32) -> Result<Vec<Item>> {
    let sql = format!("SELECT {ITEM_COLUMNS} FROM items ORDER BY id DESC LIMIT $1");
    let rows: Vec<ItemRow> = sqlx::query_as(sqlx::AssertSqlSafe(sql))
        .bind(limit as i64)
        .fetch_all(p)
        .await?;
    Ok(rows.into_iter().map(Into::into).collect())
}

pub async fn insert_item(p: &PgPool, name: &str, owner: &str, nonce: &str) -> Result<Item> {
    let sql = format!(
        "INSERT INTO items (name, owner, nonce) VALUES ($1, $2, $3) RETURNING {ITEM_COLUMNS}"
    );
    let row: ItemRow = sqlx::query_as(sqlx::AssertSqlSafe(sql))
        .bind(name)
        .bind(owner)
        .bind(nonce)
        .fetch_one(p)
        .await?;
    Ok(row.into())
}

// ---- tenant users ---------------------------------------------------------

const USER_COLUMNS: &str =
    "id::text, email, name, role, password_hash, extract(epoch FROM created_at)::bigint";

pub async fn create_user(p: &PgPool, u: &NewUser<'_>) -> Result<TenantUser> {
    let sql = format!(
        "INSERT INTO tenant_users (email, name, role, password_hash) VALUES ($1, $2, $3, $4) RETURNING {USER_COLUMNS}"
    );
    let row: UserRow = sqlx::query_as(sqlx::AssertSqlSafe(sql))
        .bind(u.email)
        .bind(u.name)
        .bind(u.role)
        .bind(u.password_hash)
        .fetch_one(p)
        .await
        .map_err(|e| map_user_err(e, is_undefined_table))?;
    Ok(row.into())
}

pub async fn user_by_email(p: &PgPool, email: &str) -> Result<TenantUser> {
    let sql = format!("SELECT {USER_COLUMNS} FROM tenant_users WHERE email = $1");
    let row: Option<UserRow> = sqlx::query_as(sqlx::AssertSqlSafe(sql))
        .bind(email)
        .fetch_optional(p)
        .await
        .map_err(|e| map_user_err(e, is_undefined_table))?;
    row.map(Into::into).ok_or(EngineError::NotFound)
}

pub async fn list_users(p: &PgPool) -> Result<Vec<TenantUser>> {
    let sql = format!("SELECT {USER_COLUMNS} FROM tenant_users ORDER BY id");
    let rows: Vec<UserRow> = sqlx::query_as(sqlx::AssertSqlSafe(sql))
        .fetch_all(p)
        .await
        .map_err(|e| map_user_err(e, is_undefined_table))?;
    Ok(rows.into_iter().map(Into::into).collect())
}
