//! One connection pool per tenant, keyed by tenant id and guarded by the
//! tenant's config version.
//!
//! Isolation rules enforced here:
//! * a pool is only ever used for the tenant it was built for;
//! * a request with an older config version than the live pool is rejected
//!   (no silent downgrade to an old database);
//! * same version but different connection details is rejected (the control
//!   plane forgot to bump the version);
//! * a pool is never built against a database claimed by another tenant.

use std::collections::hash_map::DefaultHasher;
use std::collections::{BTreeMap, HashMap};
use std::hash::{Hash, Hasher};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, RwLock};
use std::time::Duration;

use tokio::sync::Mutex;
use tokio::time::Instant;

use crate::backend::{Backend, PoolSettings};
use crate::error::{EngineError, Result};
use crate::pb::{DbType, PoolStat, TenantConn};

pub struct TenantPool {
    pub tenant_id: String,
    pub version: i64,
    pub db_type: DbType,
    pub backend: Backend,
    fingerprint: u64,
    requests: AtomicU64,
    created_at: i64,
}

impl TenantPool {
    pub fn record_request(&self) {
        self.requests.fetch_add(1, Ordering::Relaxed);
    }
}

pub struct PoolManager {
    // std (not tokio) lock: it is never held across an await point.
    pools: RwLock<HashMap<String, Arc<TenantPool>>>,
    // Per-tenant build locks so a burst of first requests builds one pool,
    // while different tenants can still build in parallel.
    build_locks: Mutex<HashMap<String, Arc<Mutex<()>>>>,
    settings: PoolSettings,
}

/// Validates host/port and the wire db_type; shared by tenant and server requests.
pub fn endpoint_db_type(host: &str, port: u32, db_type: i32) -> Result<DbType> {
    if host.is_empty() {
        return Err(EngineError::Invalid("host is required".into()));
    }
    if port == 0 || port > u16::MAX as u32 {
        return Err(EngineError::Invalid("port out of range".into()));
    }
    match DbType::try_from(db_type) {
        Ok(DbType::Unspecified) | Err(_) => Err(EngineError::Invalid("unknown db_type".into())),
        Ok(t) => Ok(t),
    }
}

pub fn validate(conn: &TenantConn) -> Result<DbType> {
    if conn.tenant_id.trim().is_empty() {
        return Err(EngineError::Invalid("tenant_id is required".into()));
    }
    if conn.config_version <= 0 {
        return Err(EngineError::Invalid("config_version must be > 0".into()));
    }
    if conn.database.is_empty() {
        return Err(EngineError::Invalid("database is required".into()));
    }
    endpoint_db_type(&conn.host, conn.port, conn.db_type)
}

/// Closes a retired pool once in-flight requests have released it. Closing it
/// immediately would make a request that already holds the pool (but has not
/// checked out a connection yet) fail with "pool closed".
async fn drain_and_close(pool: Arc<TenantPool>, grace: Duration) {
    let deadline = Instant::now() + grace;
    while Arc::strong_count(&pool) > 1 && Instant::now() < deadline {
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    let (size, idle) = pool.backend.stats();
    tracing::info!(tenant = %pool.tenant_id, refs = Arc::strong_count(&pool), size, idle, "closing retired pool");
    pool.backend.close().await;
    tracing::info!(tenant = %pool.tenant_id, version = pool.version, "closed retired pool");
}

fn fingerprint(c: &TenantConn) -> u64 {
    let mut h = DefaultHasher::new();
    (
        c.db_type,
        &c.host,
        c.port,
        &c.username,
        &c.password,
        &c.database,
    )
        .hash(&mut h);
    c.params.iter().collect::<BTreeMap<_, _>>().hash(&mut h);
    h.finish()
}

impl PoolManager {
    pub fn new(settings: PoolSettings) -> Self {
        Self {
            pools: RwLock::default(),
            build_locks: Mutex::default(),
            settings,
        }
    }

    pub fn settings(&self) -> &PoolSettings {
        &self.settings
    }

    /// Returns the live pool for this tenant, building or replacing it if the
    /// request carries a newer config version.
    pub async fn get(&self, conn: &TenantConn) -> Result<Arc<TenantPool>> {
        let db_type = validate(conn)?;
        if let Some(p) = self.lookup(conn)? {
            return Ok(p);
        }

        let lock = {
            let mut locks = self.build_locks.lock().await;
            locks.entry(conn.tenant_id.clone()).or_default().clone()
        };
        let _guard = lock.lock().await;
        // Another task may have built it while we waited.
        if let Some(p) = self.lookup(conn)? {
            return Ok(p);
        }

        let backend = Backend::connect(conn, db_type, &self.settings).await?;
        if let Some(owner) = backend.claim_owner().await?
            && owner != conn.tenant_id
        {
            backend.close().await;
            return Err(EngineError::ClaimedByOther {
                owner,
                tenant: conn.tenant_id.clone(),
            });
        }

        let pool = Arc::new(TenantPool {
            tenant_id: conn.tenant_id.clone(),
            version: conn.config_version,
            db_type,
            backend,
            fingerprint: fingerprint(conn),
            requests: AtomicU64::new(0),
            created_at: chrono::Utc::now().timestamp(),
        });
        let old = self
            .pools
            .write()
            .unwrap()
            .insert(conn.tenant_id.clone(), pool.clone());
        if let Some(old) = old {
            tracing::info!(tenant = %conn.tenant_id, from = old.version, to = pool.version, "replaced tenant pool");
            tokio::spawn(drain_and_close(old, self.settings.drain_grace));
        } else {
            tracing::info!(tenant = %conn.tenant_id, version = pool.version, db = ?db_type, "created tenant pool");
        }
        Ok(pool)
    }

    fn lookup(&self, conn: &TenantConn) -> Result<Option<Arc<TenantPool>>> {
        let pools = self.pools.read().unwrap();
        let Some(p) = pools.get(&conn.tenant_id) else {
            return Ok(None);
        };
        if conn.config_version < p.version {
            return Err(EngineError::StaleVersion {
                tenant: conn.tenant_id.clone(),
                live: p.version,
                request: conn.config_version,
            });
        }
        if conn.config_version > p.version {
            return Ok(None);
        }
        if p.fingerprint != fingerprint(conn) {
            return Err(EngineError::ConfigMismatch(conn.tenant_id.clone()));
        }
        Ok(Some(p.clone()))
    }

    pub async fn evict(&self, tenant_id: &str) -> bool {
        let removed = self.pools.write().unwrap().remove(tenant_id);
        match removed {
            Some(p) => {
                tokio::spawn(drain_and_close(p, self.settings.drain_grace));
                true
            }
            None => false,
        }
    }

    pub fn stats(&self) -> Vec<PoolStat> {
        let pools = self.pools.read().unwrap();
        let mut out: Vec<PoolStat> = pools
            .values()
            .map(|p| {
                let (size, idle) = p.backend.stats();
                PoolStat {
                    tenant_id: p.tenant_id.clone(),
                    db_type: p.db_type as i32,
                    config_version: p.version,
                    size,
                    idle,
                    requests: p.requests.load(Ordering::Relaxed),
                    created_at_unix: p.created_at,
                }
            })
            .collect();
        out.sort_by(|a, b| a.tenant_id.cmp(&b.tenant_id));
        out
    }

    pub async fn close_all(&self) {
        let pools: Vec<_> = self
            .pools
            .write()
            .unwrap()
            .drain()
            .map(|(_, p)| p)
            .collect();
        for p in pools {
            p.backend.close().await;
        }
    }
}
