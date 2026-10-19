//! MySQL and MariaDB (same wire protocol).

use std::collections::HashMap;

use sqlx::MySqlPool;
use sqlx::mysql::{MySqlConnectOptions, MySqlSslMode};

use super::{ItemRow, Login, NewUser, PoolSettings, UserRow, map_user_err, pool_options};
use crate::error::{EngineError, Result};
use crate::pb::{Item, ProvisionResult, TenantConn, TenantUser, WhoAmIResult};

const NO_SUCH_TABLE: &str = "42S02";

fn ssl_mode(params: &HashMap<String, String>) -> Result<MySqlSslMode> {
    Ok(match params.get("sslmode").map(String::as_str) {
        None | Some("preferred") | Some("prefer") => MySqlSslMode::Preferred,
        Some("disabled") | Some("disable") => MySqlSslMode::Disabled,
        Some("required") | Some("require") => MySqlSslMode::Required,
        Some("verify_ca") => MySqlSslMode::VerifyCa,
        Some("verify_identity") => MySqlSslMode::VerifyIdentity,
        Some(other) => return Err(EngineError::Invalid(format!("unknown sslmode '{other}'"))),
    })
}

/// Connection options shared by tenant pools and server-admin connections
/// (which connect without selecting a database).
pub fn options(l: &Login, database: Option<&str>) -> Result<MySqlConnectOptions> {
    let opts = MySqlConnectOptions::new()
        .host(l.host)
        .port(l.port as u16)
        .username(l.user)
        .password(l.password)
        .ssl_mode(ssl_mode(l.params)?);
    Ok(match database {
        Some(db) => opts.database(db),
        None => opts,
    })
}

pub async fn connect(c: &TenantConn, s: &PoolSettings) -> Result<MySqlPool> {
    let opts = options(&Login::tenant(c), Some(&c.database))?;
    Ok(pool_options(s).connect_with(opts).await?)
}

fn is_no_such_table(e: &sqlx::Error) -> bool {
    matches!(e, sqlx::Error::Database(d) if d.code().as_deref() == Some(NO_SUCH_TABLE))
}

pub async fn claim_owner(p: &MySqlPool) -> Result<Option<String>> {
    match sqlx::query_scalar("SELECT tenant_id FROM tenant_meta WHERE id = 1")
        .fetch_optional(p)
        .await
    {
        Err(e) if is_no_such_table(&e) => Ok(None),
        r => Ok(r?),
    }
}

pub async fn server_version(p: &MySqlPool) -> Result<String> {
    Ok(sqlx::query_scalar("SELECT CAST(VERSION() AS CHAR)")
        .fetch_one(p)
        .await?)
}

pub async fn provision(p: &MySqlPool, tenant_id: &str) -> Result<ProvisionResult> {
    // DDL auto-commits in MySQL, so no transaction here; INSERT IGNORE on the
    // single-row primary key makes the claim atomic.
    for ddl in [
        "CREATE TABLE IF NOT EXISTS tenant_meta (
            id         TINYINT PRIMARY KEY,
            tenant_id  VARCHAR(128) NOT NULL,
            claimed_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
        )",
        "CREATE TABLE IF NOT EXISTS items (
            id         BIGINT AUTO_INCREMENT PRIMARY KEY,
            name       VARCHAR(255) NOT NULL,
            owner      VARCHAR(128) NOT NULL,
            nonce      VARCHAR(128) NOT NULL,
            created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
        )",
        "CREATE TABLE IF NOT EXISTS tenant_users (
            id            BIGINT AUTO_INCREMENT PRIMARY KEY,
            email         VARCHAR(255) NOT NULL UNIQUE,
            name          VARCHAR(255) NOT NULL,
            role          VARCHAR(32) NOT NULL,
            password_hash VARCHAR(255) NOT NULL,
            created_at    TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
        )",
    ] {
        sqlx::query(ddl).execute(p).await?;
    }
    let res = sqlx::query("INSERT IGNORE INTO tenant_meta (id, tenant_id) VALUES (1, ?)")
        .bind(tenant_id)
        .execute(p)
        .await?;
    let owner: String = sqlx::query_scalar("SELECT tenant_id FROM tenant_meta WHERE id = 1")
        .fetch_one(p)
        .await?;
    super::claim_result(owner, tenant_id, res.rows_affected() == 1)
}

pub async fn whoami(p: &MySqlPool, tenant_id: &str) -> Result<WhoAmIResult> {
    // User variables are per-connection, so everything runs on one connection.
    let mut conn = p.acquire().await?;

    let prev: String = sqlx::query_scalar("SELECT CAST(COALESCE(@app_tenant_id, '') AS CHAR)")
        .fetch_one(&mut *conn)
        .await?;
    sqlx::query("SET @app_tenant_id = ?")
        .bind(tenant_id)
        .execute(&mut *conn)
        .await?;

    // Marker and session details in one round trip.
    let row: Option<(String, Option<String>, String, String)> = match sqlx::query_as(
        "SELECT tenant_id, CAST(DATABASE() AS CHAR), CAST(CONNECTION_ID() AS CHAR),
                CAST(VERSION() AS CHAR)
         FROM tenant_meta WHERE id = 1",
    )
    .fetch_optional(&mut *conn)
    .await
    {
        Err(e) if is_no_such_table(&e) => None,
        r => r?,
    };
    let (marker, database, conn_id, version) = row.ok_or(EngineError::NotProvisioned)?;

    Ok(WhoAmIResult {
        marker_tenant_id: marker,
        database: database.unwrap_or_default(),
        server_version: version,
        session_id: conn_id,
        session_tag: prev,
    })
}

const ITEM_COLUMNS: &str =
    "CAST(id AS CHAR), name, owner, nonce, CAST(UNIX_TIMESTAMP(created_at) AS SIGNED)";

pub async fn list_items(p: &MySqlPool, limit: u32) -> Result<Vec<Item>> {
    let sql = format!("SELECT {ITEM_COLUMNS} FROM items ORDER BY id DESC LIMIT ?");
    // Only compile-time constants are interpolated; values are bound.
    let rows: Vec<ItemRow> = sqlx::query_as(sqlx::AssertSqlSafe(sql))
        .bind(limit)
        .fetch_all(p)
        .await?;
    Ok(rows.into_iter().map(Into::into).collect())
}

pub async fn insert_item(p: &MySqlPool, name: &str, owner: &str, nonce: &str) -> Result<Item> {
    let mut conn = p.acquire().await?;
    let res = sqlx::query("INSERT INTO items (name, owner, nonce) VALUES (?, ?, ?)")
        .bind(name)
        .bind(owner)
        .bind(nonce)
        .execute(&mut *conn)
        .await?;
    let sql = format!("SELECT {ITEM_COLUMNS} FROM items WHERE id = ?");
    let row: ItemRow = sqlx::query_as(sqlx::AssertSqlSafe(sql))
        .bind(res.last_insert_id())
        .fetch_one(&mut *conn)
        .await?;
    Ok(row.into())
}

// ---- tenant users ---------------------------------------------------------

const USER_COLUMNS: &str = "CAST(id AS CHAR), email, name, role, password_hash, \
     CAST(UNIX_TIMESTAMP(created_at) AS SIGNED)";

pub async fn create_user(p: &MySqlPool, u: &NewUser<'_>) -> Result<TenantUser> {
    let mut conn = p.acquire().await?;
    let res = sqlx::query(
        "INSERT INTO tenant_users (email, name, role, password_hash) VALUES (?, ?, ?, ?)",
    )
    .bind(u.email)
    .bind(u.name)
    .bind(u.role)
    .bind(u.password_hash)
    .execute(&mut *conn)
    .await
    .map_err(|e| map_user_err(e, is_no_such_table))?;
    let sql = format!("SELECT {USER_COLUMNS} FROM tenant_users WHERE id = ?");
    let row: UserRow = sqlx::query_as(sqlx::AssertSqlSafe(sql))
        .bind(res.last_insert_id())
        .fetch_one(&mut *conn)
        .await?;
    Ok(row.into())
}

pub async fn user_by_email(p: &MySqlPool, email: &str) -> Result<TenantUser> {
    let sql = format!("SELECT {USER_COLUMNS} FROM tenant_users WHERE email = ?");
    let row: Option<UserRow> = sqlx::query_as(sqlx::AssertSqlSafe(sql))
        .bind(email)
        .fetch_optional(p)
        .await
        .map_err(|e| map_user_err(e, is_no_such_table))?;
    row.map(Into::into).ok_or(EngineError::NotFound)
}

pub async fn list_users(p: &MySqlPool) -> Result<Vec<TenantUser>> {
    let sql = format!("SELECT {USER_COLUMNS} FROM tenant_users ORDER BY id");
    let rows: Vec<UserRow> = sqlx::query_as(sqlx::AssertSqlSafe(sql))
        .fetch_all(p)
        .await
        .map_err(|e| map_user_err(e, is_no_such_table))?;
    Ok(rows.into_iter().map(Into::into).collect())
}
