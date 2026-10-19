//! Database backends. MySQL and MariaDB share the MySQL wire protocol, so both
//! use the `mysql` backend; the db_type is kept separately for reporting.

pub mod mongo;
pub mod mysql;
pub mod postgres;

use std::collections::HashMap;
use std::time::Duration;

use crate::error::{EngineError, Result};
use crate::pb::{
    DbType, HealthResult, Item, ProvisionResult, ServerConn, TenantConn, TenantUser, WhoAmIResult,
};

// ---- helpers shared by the backends -----------------------------------------

/// Where and as whom to connect: a tenant's own login, or a server's admin
/// login. Every driver builds its connection options from this.
pub struct Login<'a> {
    pub host: &'a str,
    pub port: u32,
    pub user: &'a str,
    pub password: &'a str,
    pub params: &'a HashMap<String, String>,
}

impl<'a> Login<'a> {
    pub fn tenant(c: &'a TenantConn) -> Self {
        Login {
            host: &c.host,
            port: c.port,
            user: &c.username,
            password: &c.password,
            params: &c.params,
        }
    }

    pub fn admin(s: &'a ServerConn) -> Self {
        Login {
            host: &s.host,
            port: s.port,
            user: &s.admin_username,
            password: &s.admin_password,
            params: &s.params,
        }
    }
}

/// (id, name, owner, nonce, created_at) as returned by the SQL backends.
pub(crate) type ItemRow = (String, String, String, String, i64);
/// (id, email, name, role, password_hash, created_at).
pub(crate) type UserRow = (String, String, String, String, String, i64);

impl From<ItemRow> for Item {
    fn from((id, name, owner, nonce, created_at_unix): ItemRow) -> Self {
        Item {
            id,
            name,
            owner,
            nonce,
            created_at_unix,
        }
    }
}

impl From<UserRow> for TenantUser {
    fn from((id, email, name, role, password_hash, created_at_unix): UserRow) -> Self {
        TenantUser {
            id,
            email,
            name,
            role,
            password_hash,
            created_at_unix,
        }
    }
}

/// Pool settings shared by the SQL backends.
pub(crate) fn pool_options<DB: sqlx::Database>(s: &PoolSettings) -> sqlx::pool::PoolOptions<DB> {
    sqlx::pool::PoolOptions::new()
        .max_connections(s.max_connections)
        .acquire_timeout(s.acquire_timeout)
        .idle_timeout(s.idle_timeout)
}

/// Maps tenant-user query errors: duplicate email and missing table get
/// their own errors. `is_missing_table` is the backend's own check.
pub(crate) fn map_user_err(
    e: sqlx::Error,
    is_missing_table: fn(&sqlx::Error) -> bool,
) -> EngineError {
    match &e {
        sqlx::Error::Database(d) if d.is_unique_violation() => duplicate_email(),
        _ if is_missing_table(&e) => EngineError::NotProvisioned,
        _ => e.into(),
    }
}

pub(crate) fn duplicate_email() -> EngineError {
    EngineError::AlreadyExists("a user with this email already exists".into())
}

/// Result of a provision call once the current owner of the database is known.
pub(crate) fn claim_result(
    owner: String,
    tenant_id: &str,
    claimed_now: bool,
) -> Result<ProvisionResult> {
    if owner != tenant_id {
        return Err(EngineError::ClaimedByOther {
            owner,
            tenant: tenant_id.into(),
        });
    }
    Ok(ProvisionResult {
        claimed_now,
        marker_tenant_id: owner,
    })
}

/// A user to insert into the tenant's own `tenant_users` table/collection.
pub struct NewUser<'a> {
    pub email: &'a str,
    pub name: &'a str,
    pub role: &'a str,
    pub password_hash: &'a str,
}

#[derive(Clone, Debug)]
pub struct PoolSettings {
    pub max_connections: u32,
    pub acquire_timeout: Duration,
    pub idle_timeout: Duration,
    /// How long a retired pool may keep serving in-flight requests.
    pub drain_grace: Duration,
}

pub enum Backend {
    Postgres(sqlx::PgPool),
    MySql(sqlx::MySqlPool),
    Mongo(mongodb::Database),
}

impl Backend {
    pub async fn connect(conn: &TenantConn, db_type: DbType, s: &PoolSettings) -> Result<Self> {
        Ok(match db_type {
            DbType::Postgres => Backend::Postgres(postgres::connect(conn, s).await?),
            DbType::Mysql | DbType::Mariadb => Backend::MySql(mysql::connect(conn, s).await?),
            DbType::Mongodb => Backend::Mongo(mongo::connect(conn, s).await?),
            DbType::Unspecified => unreachable!("validated by caller"),
        })
    }

    /// Returns the tenant id stored in the database, or None if the database
    /// has not been provisioned yet.
    pub async fn claim_owner(&self) -> Result<Option<String>> {
        match self {
            Backend::Postgres(p) => postgres::claim_owner(p).await,
            Backend::MySql(p) => mysql::claim_owner(p).await,
            Backend::Mongo(db) => mongo::claim_owner(db).await,
        }
    }

    pub async fn health(&self) -> Result<HealthResult> {
        let start = std::time::Instant::now();
        let version = match self {
            Backend::Postgres(p) => postgres::server_version(p).await?,
            Backend::MySql(p) => mysql::server_version(p).await?,
            Backend::Mongo(db) => mongo::server_version(db).await?,
        };
        Ok(HealthResult {
            ok: true,
            server_version: version,
            latency_ms: start.elapsed().as_millis() as i64,
            error: String::new(),
        })
    }

    pub async fn provision(&self, tenant_id: &str) -> Result<ProvisionResult> {
        match self {
            Backend::Postgres(p) => postgres::provision(p, tenant_id).await,
            Backend::MySql(p) => mysql::provision(p, tenant_id).await,
            Backend::Mongo(db) => mongo::provision(db, tenant_id).await,
        }
    }

    pub async fn whoami(&self, tenant_id: &str) -> Result<WhoAmIResult> {
        match self {
            Backend::Postgres(p) => postgres::whoami(p, tenant_id).await,
            Backend::MySql(p) => mysql::whoami(p, tenant_id).await,
            Backend::Mongo(db) => mongo::whoami(db).await,
        }
    }

    pub async fn list_items(&self, limit: u32) -> Result<Vec<Item>> {
        match self {
            Backend::Postgres(p) => postgres::list_items(p, limit).await,
            Backend::MySql(p) => mysql::list_items(p, limit).await,
            Backend::Mongo(db) => mongo::list_items(db, limit).await,
        }
    }

    pub async fn insert_item(&self, name: &str, owner: &str, nonce: &str) -> Result<Item> {
        match self {
            Backend::Postgres(p) => postgres::insert_item(p, name, owner, nonce).await,
            Backend::MySql(p) => mysql::insert_item(p, name, owner, nonce).await,
            Backend::Mongo(db) => mongo::insert_item(db, name, owner, nonce).await,
        }
    }

    pub async fn create_user(&self, u: &NewUser<'_>) -> Result<TenantUser> {
        match self {
            Backend::Postgres(p) => postgres::create_user(p, u).await,
            Backend::MySql(p) => mysql::create_user(p, u).await,
            Backend::Mongo(db) => mongo::create_user(db, u).await,
        }
    }

    pub async fn user_by_email(&self, email: &str) -> Result<TenantUser> {
        match self {
            Backend::Postgres(p) => postgres::user_by_email(p, email).await,
            Backend::MySql(p) => mysql::user_by_email(p, email).await,
            Backend::Mongo(db) => mongo::user_by_email(db, email).await,
        }
    }

    pub async fn list_users(&self) -> Result<Vec<TenantUser>> {
        match self {
            Backend::Postgres(p) => postgres::list_users(p).await,
            Backend::MySql(p) => mysql::list_users(p).await,
            Backend::Mongo(db) => mongo::list_users(db).await,
        }
    }

    /// (size, idle) of the underlying pool. The Mongo driver manages its own
    /// pool internally and does not expose these numbers.
    pub fn stats(&self) -> (u32, u32) {
        match self {
            Backend::Postgres(p) => (p.size(), p.num_idle() as u32),
            Backend::MySql(p) => (p.size(), p.num_idle() as u32),
            Backend::Mongo(_) => (0, 0),
        }
    }

    pub async fn close(&self) {
        match self {
            Backend::Postgres(p) => p.close().await,
            Backend::MySql(p) => p.close().await,
            Backend::Mongo(db) => db.client().clone().shutdown().await,
        }
    }
}
