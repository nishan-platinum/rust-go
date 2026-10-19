//! Server-level operations for managed tenants, run with a database server's
//! admin credentials: create / drop a tenant database and its DB user.
//!
//! DDL cannot take bound parameters, so identifiers and passwords are
//! validated against a strict character set and then quoted.

use std::time::Duration;

use mongodb::Client;
use mongodb::bson::{Document, doc};
use sqlx::mysql::MySqlConnection;
use sqlx::postgres::PgConnection;
use sqlx::{AssertSqlSafe, Connection};

use crate::backend::{Login, mongo, mysql, postgres};
use crate::error::{EngineError, Result};
use crate::pb::{DbType, ServerConn};
use crate::pool::endpoint_db_type;

const ADMIN_APP: &str = "rust-engine/admin";

/// ^[a-z][a-z0-9_]{0,31}$ (fits MySQL's 32-char user name limit).
pub fn validate_ident(kind: &str, s: &str) -> Result<()> {
    let ok = !s.is_empty()
        && s.len() <= 32
        && s.starts_with(|c: char| c.is_ascii_lowercase())
        && s.chars()
            .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '_');
    if ok {
        Ok(())
    } else {
        Err(EngineError::Invalid(format!(
            "{kind} must match ^[a-z][a-z0-9_]{{0,31}}$"
        )))
    }
}

/// ^[A-Za-z0-9_-]{16,128}$, safe to embed in a quoted SQL literal.
fn validate_password(s: &str) -> Result<()> {
    let ok = (16..=128).contains(&s.len())
        && s.chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '-');
    if ok {
        Ok(())
    } else {
        Err(EngineError::Invalid(
            "password must match ^[A-Za-z0-9_-]{16,128}$".into(),
        ))
    }
}

fn db_type(s: &ServerConn) -> Result<DbType> {
    endpoint_db_type(&s.host, s.port, s.db_type)
}

/// Returns (database_created, user_created).
pub async fn create_database(
    s: &ServerConn,
    db: &str,
    user: &str,
    password: &str,
) -> Result<(bool, bool)> {
    validate_ident("database", db)?;
    validate_ident("username", user)?;
    validate_password(password)?;
    match db_type(s)? {
        DbType::Postgres => pg_create(s, db, user, password).await,
        DbType::Mysql | DbType::Mariadb => my_create(s, db, user, password).await,
        DbType::Mongodb => mongo_create(s, db, user, password).await,
        DbType::Unspecified => unreachable!(),
    }
}

pub async fn drop_database(s: &ServerConn, db: &str, user: &str) -> Result<()> {
    validate_ident("database", db)?;
    validate_ident("username", user)?;
    match db_type(s)? {
        DbType::Postgres => pg_drop(s, db, user).await,
        DbType::Mysql | DbType::Mariadb => my_drop(s, db, user).await,
        DbType::Mongodb => mongo_drop(s, db, user).await,
        DbType::Unspecified => unreachable!(),
    }
}

// Simple-query protocol: CREATE DATABASE cannot run in an implicit transaction.
async fn pg_exec(c: &mut PgConnection, sql: String) -> Result<()> {
    sqlx::raw_sql(AssertSqlSafe(sql)).execute(&mut *c).await?;
    Ok(())
}

async fn my_exec(c: &mut MySqlConnection, sql: String) -> Result<()> {
    sqlx::raw_sql(AssertSqlSafe(sql)).execute(&mut *c).await?;
    Ok(())
}

// ---- PostgreSQL -----------------------------------------------------------

async fn pg_admin(s: &ServerConn) -> Result<PgConnection> {
    let maintenance = s
        .params
        .get("maintenance_db")
        .map(String::as_str)
        .unwrap_or("postgres");
    let opts = postgres::options(&Login::admin(s), maintenance, ADMIN_APP)?;
    Ok(PgConnection::connect_with(&opts).await?)
}

async fn pg_create(s: &ServerConn, db: &str, user: &str, pw: &str) -> Result<(bool, bool)> {
    let mut c = pg_admin(s).await?;
    let role_exists: bool =
        sqlx::query_scalar("SELECT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = $1)")
            .bind(user)
            .fetch_one(&mut c)
            .await?;
    if role_exists {
        pg_exec(
            &mut c,
            format!(r#"ALTER ROLE "{user}" WITH LOGIN PASSWORD '{pw}'"#),
        )
        .await?;
    } else {
        pg_exec(
            &mut c,
            format!(r#"CREATE ROLE "{user}" LOGIN PASSWORD '{pw}'"#),
        )
        .await?;
    }
    let db_exists: bool =
        sqlx::query_scalar("SELECT EXISTS (SELECT 1 FROM pg_database WHERE datname = $1)")
            .bind(db)
            .fetch_one(&mut c)
            .await?;
    if !db_exists {
        pg_exec(&mut c, format!(r#"CREATE DATABASE "{db}" OWNER "{user}""#)).await?;
    }
    // Only the tenant's own user may even connect.
    pg_exec(
        &mut c,
        format!(r#"REVOKE CONNECT ON DATABASE "{db}" FROM PUBLIC"#),
    )
    .await?;
    c.close().await?;
    Ok((!db_exists, !role_exists))
}

async fn pg_drop(s: &ServerConn, db: &str, user: &str) -> Result<()> {
    let mut c = pg_admin(s).await?;
    pg_exec(
        &mut c,
        format!(r#"DROP DATABASE IF EXISTS "{db}" WITH (FORCE)"#),
    )
    .await?;
    pg_exec(&mut c, format!(r#"DROP ROLE IF EXISTS "{user}""#)).await?;
    c.close().await?;
    Ok(())
}

// ---- MySQL / MariaDB --------------------------------------------------------

async fn my_admin(s: &ServerConn) -> Result<MySqlConnection> {
    let opts = mysql::options(&Login::admin(s), None)?;
    Ok(MySqlConnection::connect_with(&opts).await?)
}

async fn my_create(s: &ServerConn, db: &str, user: &str, pw: &str) -> Result<(bool, bool)> {
    let mut c = my_admin(s).await?;
    let db_count: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM information_schema.SCHEMATA WHERE SCHEMA_NAME = ?",
    )
    .bind(db)
    .fetch_one(&mut c)
    .await?;
    let user_count: i64 =
        sqlx::query_scalar("SELECT COUNT(*) FROM mysql.user WHERE User = ? AND Host = '%'")
            .bind(user)
            .fetch_one(&mut c)
            .await?;
    my_exec(&mut c, format!("CREATE DATABASE IF NOT EXISTS `{db}`")).await?;
    my_exec(
        &mut c,
        format!("CREATE USER IF NOT EXISTS '{user}'@'%' IDENTIFIED BY '{pw}'"),
    )
    .await?;
    // Retry-safe: an existing user from a half-finished attempt gets the new password.
    my_exec(
        &mut c,
        format!("ALTER USER '{user}'@'%' IDENTIFIED BY '{pw}'"),
    )
    .await?;
    my_exec(
        &mut c,
        format!("GRANT ALL PRIVILEGES ON `{db}`.* TO '{user}'@'%'"),
    )
    .await?;
    c.close().await?;
    Ok((db_count == 0, user_count == 0))
}

async fn my_drop(s: &ServerConn, db: &str, user: &str) -> Result<()> {
    let mut c = my_admin(s).await?;
    my_exec(&mut c, format!("DROP DATABASE IF EXISTS `{db}`")).await?;
    my_exec(&mut c, format!("DROP USER IF EXISTS '{user}'@'%'")).await?;
    c.close().await?;
    Ok(())
}

// ---- MongoDB --------------------------------------------------------------

async fn mongo_admin(s: &ServerConn) -> Result<Client> {
    let auth_source = s
        .params
        .get("authSource")
        .map(String::as_str)
        .unwrap_or("admin");
    let opts = mongo::client_options(
        &Login::admin(s),
        auth_source,
        ADMIN_APP,
        Duration::from_secs(5),
    );
    Ok(Client::with_options(opts)?)
}

async fn mongo_create(s: &ServerConn, db: &str, user: &str, pw: &str) -> Result<(bool, bool)> {
    let client = mongo_admin(s).await?;
    let db_existed = client.list_database_names().await?.iter().any(|n| n == db);
    let handle = client.database(db);
    let info = handle.run_command(doc! { "usersInfo": user }).await?;
    let user_exists = info
        .get_array("users")
        .map(|u| !u.is_empty())
        .unwrap_or(false);
    let cmd: Document = if user_exists {
        doc! { "updateUser": user, "pwd": pw }
    } else {
        doc! { "createUser": user, "pwd": pw, "roles": [{ "role": "readWrite", "db": db }] }
    };
    handle.run_command(cmd).await?;
    client.shutdown().await;
    Ok((!db_existed, !user_exists))
}

async fn mongo_drop(s: &ServerConn, db: &str, user: &str) -> Result<()> {
    let client = mongo_admin(s).await?;
    let handle = client.database(db);
    if let Err(e) = handle.run_command(doc! { "dropUser": user }).await {
        // 11 = UserNotFound: already gone is fine.
        if !matches!(e.kind.as_ref(), mongodb::error::ErrorKind::Command(c) if c.code == 11) {
            return Err(e.into());
        }
    }
    handle.drop().await?;
    client.shutdown().await;
    Ok(())
}
