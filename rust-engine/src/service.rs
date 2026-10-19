use std::future::Future;
use std::sync::Arc;
use std::time::Duration;

use tonic::{Request, Response, Status};

use crate::admin;
use crate::backend::{Backend, NewUser};
use crate::error::{EngineError, Result};
use crate::pb::db_engine_server::DbEngine;
use crate::pb::*;
use crate::pool::{PoolManager, TenantPool, validate};

pub struct EngineService {
    pools: Arc<PoolManager>,
    op_timeout: Duration,
}

impl EngineService {
    pub fn new(pools: Arc<PoolManager>, op_timeout: Duration) -> Self {
        Self { pools, op_timeout }
    }

    async fn timed<T>(&self, fut: impl Future<Output = Result<T>>) -> Result<T> {
        tokio::time::timeout(self.op_timeout, fut)
            .await
            .unwrap_or(Err(
                EngineError::Timeout(self.op_timeout.as_millis() as u64),
            ))
    }

    async fn pool_for(&self, conn: Option<&TenantConn>) -> Result<Arc<TenantPool>> {
        let conn = conn.ok_or_else(|| EngineError::Invalid("conn is required".into()))?;
        let pool = self.timed(self.pools.get(conn)).await?;
        pool.record_request();
        Ok(pool)
    }
}

fn health_err(e: EngineError) -> HealthResult {
    HealthResult {
        ok: false,
        error: e.to_string(),
        ..Default::default()
    }
}

#[tonic::async_trait]
impl DbEngine for EngineService {
    async fn test_connection(
        &self,
        req: Request<TestConnectionRequest>,
    ) -> std::result::Result<Response<HealthResult>, Status> {
        let Some(conn) = req.into_inner().conn else {
            return Err(EngineError::Invalid("conn is required".into()).into());
        };
        let res = self
            .timed(async {
                let db_type = validate(&conn)?;
                // Throwaway pool: never cached, never shared with tenants.
                let backend = Backend::connect(&conn, db_type, self.pools.settings()).await?;
                let r = async {
                    let health = backend.health().await?;
                    // Refuse a target database that already belongs to someone else.
                    match backend.claim_owner().await? {
                        Some(owner) if owner != conn.tenant_id => {
                            Err(EngineError::ClaimedByOther {
                                owner,
                                tenant: conn.tenant_id.clone(),
                            })
                        }
                        _ => Ok(health),
                    }
                }
                .await;
                backend.close().await;
                r
            })
            .await;
        Ok(Response::new(res.unwrap_or_else(health_err)))
    }

    async fn provision(
        &self,
        req: Request<TenantRequest>,
    ) -> std::result::Result<Response<ProvisionResult>, Status> {
        let conn = req.into_inner().conn;
        let pool = self.pool_for(conn.as_ref()).await?;
        let res = self.timed(pool.backend.provision(&pool.tenant_id)).await?;
        tracing::info!(tenant = %pool.tenant_id, claimed_now = res.claimed_now, "provisioned");
        Ok(Response::new(res))
    }

    async fn health(
        &self,
        req: Request<TenantRequest>,
    ) -> std::result::Result<Response<HealthResult>, Status> {
        let conn = req.into_inner().conn;
        let res = async {
            let pool = self.pool_for(conn.as_ref()).await?;
            self.timed(pool.backend.health()).await
        }
        .await;
        Ok(Response::new(res.unwrap_or_else(health_err)))
    }

    async fn who_am_i(
        &self,
        req: Request<TenantRequest>,
    ) -> std::result::Result<Response<WhoAmIResult>, Status> {
        let conn = req.into_inner().conn;
        let pool = self.pool_for(conn.as_ref()).await?;
        let res = self.timed(pool.backend.whoami(&pool.tenant_id)).await?;
        if res.marker_tenant_id != pool.tenant_id {
            // Should be impossible given the claim check at pool build time;
            // log loudly if it ever happens.
            tracing::error!(tenant = %pool.tenant_id, marker = %res.marker_tenant_id, "TENANT MARKER MISMATCH");
        }
        Ok(Response::new(res))
    }

    async fn list_items(
        &self,
        req: Request<ListItemsRequest>,
    ) -> std::result::Result<Response<ListItemsResult>, Status> {
        let req = req.into_inner();
        let pool = self.pool_for(req.conn.as_ref()).await?;
        let limit = req.limit.clamp(1, 500);
        let items = self.timed(pool.backend.list_items(limit)).await?;
        Ok(Response::new(ListItemsResult { items }))
    }

    async fn insert_item(
        &self,
        req: Request<InsertItemRequest>,
    ) -> std::result::Result<Response<Item>, Status> {
        let req = req.into_inner();
        if req.name.is_empty() || req.name.len() > 255 {
            return Err(EngineError::Invalid("name must be 1..255 chars".into()).into());
        }
        let pool = self.pool_for(req.conn.as_ref()).await?;
        let item = self
            .timed(pool.backend.insert_item(&req.name, &req.owner, &req.nonce))
            .await?;
        Ok(Response::new(item))
    }

    async fn evict_tenant(
        &self,
        req: Request<EvictTenantRequest>,
    ) -> std::result::Result<Response<EvictTenantResult>, Status> {
        let evicted = self.pools.evict(&req.into_inner().tenant_id).await;
        Ok(Response::new(EvictTenantResult { evicted }))
    }

    async fn create_tenant_database(
        &self,
        req: Request<CreateTenantDatabaseRequest>,
    ) -> std::result::Result<Response<CreateTenantDatabaseResult>, Status> {
        let req = req.into_inner();
        let server = req
            .server
            .ok_or_else(|| EngineError::Invalid("server is required".into()))?;
        let (database_created, user_created) = self
            .timed(admin::create_database(
                &server,
                &req.database,
                &req.username,
                &req.password,
            ))
            .await?;
        tracing::info!(database = %req.database, database_created, user_created, "tenant database ready");
        Ok(Response::new(CreateTenantDatabaseResult {
            database_created,
            user_created,
        }))
    }

    async fn drop_tenant_database(
        &self,
        req: Request<DropTenantDatabaseRequest>,
    ) -> std::result::Result<Response<DropTenantDatabaseResult>, Status> {
        let req = req.into_inner();
        let server = req
            .server
            .ok_or_else(|| EngineError::Invalid("server is required".into()))?;
        self.timed(admin::drop_database(&server, &req.database, &req.username))
            .await?;
        tracing::warn!(database = %req.database, "tenant database dropped");
        Ok(Response::new(DropTenantDatabaseResult { dropped: true }))
    }

    async fn create_user(
        &self,
        req: Request<CreateUserRequest>,
    ) -> std::result::Result<Response<TenantUser>, Status> {
        let req = req.into_inner();
        if req.email.is_empty() || req.password_hash.is_empty() || req.role.is_empty() {
            return Err(
                EngineError::Invalid("email, role and password_hash are required".into()).into(),
            );
        }
        let pool = self.pool_for(req.conn.as_ref()).await?;
        let user = NewUser {
            email: &req.email,
            name: &req.name,
            role: &req.role,
            password_hash: &req.password_hash,
        };
        let mut u = self.timed(pool.backend.create_user(&user)).await?;
        u.password_hash.clear();
        Ok(Response::new(u))
    }

    async fn get_user_by_email(
        &self,
        req: Request<GetUserByEmailRequest>,
    ) -> std::result::Result<Response<TenantUser>, Status> {
        let req = req.into_inner();
        let pool = self.pool_for(req.conn.as_ref()).await?;
        let u = self.timed(pool.backend.user_by_email(&req.email)).await?;
        Ok(Response::new(u))
    }

    async fn list_users(
        &self,
        req: Request<ListUsersRequest>,
    ) -> std::result::Result<Response<ListUsersResult>, Status> {
        let pool = self.pool_for(req.into_inner().conn.as_ref()).await?;
        let mut users = self.timed(pool.backend.list_users()).await?;
        users.iter_mut().for_each(|u| u.password_hash.clear());
        Ok(Response::new(ListUsersResult { users }))
    }

    async fn pool_stats(
        &self,
        _req: Request<PoolStatsRequest>,
    ) -> std::result::Result<Response<PoolStatsResult>, Status> {
        Ok(Response::new(PoolStatsResult {
            pools: self.pools.stats(),
        }))
    }
}
