use futures::TryStreamExt;
use mongodb::bson::{DateTime, Document, doc, oid::ObjectId};
use mongodb::options::{ClientOptions, Credential, ReturnDocument, ServerAddress};
use mongodb::{Client, Database};

use std::time::Duration;

use super::{Login, NewUser, PoolSettings};
use crate::error::{EngineError, Result};
use crate::pb::{Item, ProvisionResult, TenantConn, TenantUser, WhoAmIResult};

/// Client options shared by tenant pools and server-admin connections.
pub fn client_options(l: &Login, auth_source: &str, app: &str, timeout: Duration) -> ClientOptions {
    let mut opts = ClientOptions::default();
    opts.hosts = vec![ServerAddress::Tcp {
        host: l.host.to_owned(),
        port: Some(l.port as u16),
    }];
    opts.credential = Some(
        Credential::builder()
            .username(l.user.to_owned())
            .password(l.password.to_owned())
            .source(auth_source.to_owned())
            .build(),
    );
    opts.app_name = Some(app.to_owned());
    opts.server_selection_timeout = Some(timeout);
    opts.connect_timeout = Some(timeout);
    opts.direct_connection = Some(l.params.get("directConnection").is_none_or(|v| v == "true"));
    opts
}

pub async fn connect(c: &TenantConn, s: &PoolSettings) -> Result<Database> {
    // A managed tenant's user lives in its own database.
    let auth_source = c.params.get("authSource").unwrap_or(&c.database);
    let app = format!("rust-engine/{}", c.tenant_id);
    let mut opts = client_options(&Login::tenant(c), auth_source, &app, s.acquire_timeout);
    opts.max_pool_size = Some(s.max_connections);
    opts.max_idle_time = Some(s.idle_timeout);

    let db = Client::with_options(opts)?.database(&c.database);
    // The driver connects lazily; ping now so bad credentials fail fast.
    db.run_command(doc! { "ping": 1 }).await?;
    Ok(db)
}

pub async fn claim_owner(db: &Database) -> Result<Option<String>> {
    let meta = db
        .collection::<Document>("tenant_meta")
        .find_one(doc! { "_id": 1 })
        .await?;
    Ok(meta.and_then(|d| d.get_str("tenant_id").ok().map(str::to_owned)))
}

pub async fn server_version(db: &Database) -> Result<String> {
    let info = db.run_command(doc! { "buildInfo": 1 }).await?;
    Ok(format!(
        "MongoDB {}",
        info.get_str("version").unwrap_or("?")
    ))
}

pub async fn provision(db: &Database, tenant_id: &str) -> Result<ProvisionResult> {
    // Upsert with $setOnInsert is atomic on _id: only the first caller claims.
    let before = db
        .collection::<Document>("tenant_meta")
        .find_one_and_update(
            doc! { "_id": 1 },
            doc! { "$setOnInsert": { "tenant_id": tenant_id, "claimed_at": DateTime::now() } },
        )
        .upsert(true)
        .return_document(ReturnDocument::Before)
        .await?;

    let owner = match &before {
        None => tenant_id.to_owned(),
        Some(d) => d.get_str("tenant_id").unwrap_or_default().to_owned(),
    };
    let result = super::claim_result(owner, tenant_id, before.is_none())?;
    db.collection::<Document>("items")
        .create_index(
            mongodb::IndexModel::builder()
                .keys(doc! { "nonce": 1 })
                .build(),
        )
        .await?;
    Ok(result)
}

pub async fn whoami(db: &Database) -> Result<WhoAmIResult> {
    let (marker, server_version) = tokio::try_join!(claim_owner(db), server_version(db))?;
    Ok(WhoAmIResult {
        marker_tenant_id: marker.ok_or(EngineError::NotProvisioned)?,
        database: db.name().to_owned(),
        server_version,
        // MongoDB has no per-connection session variables to leak; requests
        // are routed by the client to a Database handle instead.
        session_id: String::new(),
        session_tag: String::new(),
    })
}

fn to_item(d: &Document) -> Item {
    Item {
        id: d
            .get_object_id("_id")
            .map(|o| o.to_hex())
            .unwrap_or_default(),
        name: d.get_str("name").unwrap_or_default().to_owned(),
        owner: d.get_str("owner").unwrap_or_default().to_owned(),
        nonce: d.get_str("nonce").unwrap_or_default().to_owned(),
        created_at_unix: d
            .get_datetime("created_at")
            .map(|t| t.timestamp_millis() / 1000)
            .unwrap_or_default(),
    }
}

pub async fn list_items(db: &Database, limit: u32) -> Result<Vec<Item>> {
    let docs: Vec<Document> = db
        .collection::<Document>("items")
        .find(doc! {})
        .sort(doc! { "_id": -1 })
        .limit(limit as i64)
        .await?
        .try_collect()
        .await?;
    Ok(docs.iter().map(to_item).collect())
}

pub async fn insert_item(db: &Database, name: &str, owner: &str, nonce: &str) -> Result<Item> {
    let d = doc! {
        "_id": ObjectId::new(),
        "name": name,
        "owner": owner,
        "nonce": nonce,
        "created_at": DateTime::now(),
    };
    db.collection::<Document>("items").insert_one(&d).await?;
    Ok(to_item(&d))
}

// ---- tenant users ---------------------------------------------------------

fn to_user(d: &Document) -> TenantUser {
    TenantUser {
        id: d
            .get_object_id("_id")
            .map(|o| o.to_hex())
            .unwrap_or_default(),
        email: d.get_str("email").unwrap_or_default().to_owned(),
        name: d.get_str("name").unwrap_or_default().to_owned(),
        role: d.get_str("role").unwrap_or_default().to_owned(),
        password_hash: d.get_str("password_hash").unwrap_or_default().to_owned(),
        created_at_unix: d
            .get_datetime("created_at")
            .map(|t| t.timestamp_millis() / 1000)
            .unwrap_or_default(),
    }
}

fn is_duplicate(e: &mongodb::error::Error) -> bool {
    use mongodb::error::{ErrorKind, WriteFailure};
    matches!(e.kind.as_ref(), ErrorKind::Write(WriteFailure::WriteError(w)) if w.code == 11000)
}

pub async fn create_user(db: &Database, u: &NewUser<'_>) -> Result<TenantUser> {
    // Mongo creates collections lazily, so check provisioning explicitly.
    claim_owner(db).await?.ok_or(EngineError::NotProvisioned)?;
    let d = doc! {
        "_id": ObjectId::new(),
        "email": u.email,
        "name": u.name,
        "role": u.role,
        "password_hash": u.password_hash,
        "created_at": DateTime::now(),
    };
    match db
        .collection::<Document>("tenant_users")
        .insert_one(&d)
        .await
    {
        Ok(_) => Ok(to_user(&d)),
        Err(e) if is_duplicate(&e) => Err(super::duplicate_email()),
        Err(e) => Err(e.into()),
    }
}

pub async fn user_by_email(db: &Database, email: &str) -> Result<TenantUser> {
    db.collection::<Document>("tenant_users")
        .find_one(doc! { "email": email })
        .await?
        .map(|d| to_user(&d))
        .ok_or(EngineError::NotFound)
}

pub async fn list_users(db: &Database) -> Result<Vec<TenantUser>> {
    let docs: Vec<Document> = db
        .collection::<Document>("tenant_users")
        .find(doc! {})
        .sort(doc! { "_id": 1 })
        .await?
        .try_collect()
        .await?;
    Ok(docs.iter().map(to_user).collect())
}
