mod admin;
mod backend;
mod error;
mod pool;
mod service;

pub mod pb {
    tonic::include_proto!("dbengine.v1");
}

use std::sync::Arc;
use std::time::Duration;

use tonic::{Request, Status, metadata::MetadataValue, transport::Server};
use tracing_subscriber::EnvFilter;

use backend::PoolSettings;
use pb::db_engine_server::DbEngineServer;
use pool::PoolManager;
use service::EngineService;

fn env_or<T: std::str::FromStr>(key: &str, default: T) -> T {
    std::env::var(key)
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(default)
}

/// Constant-time comparison so the shared secret can't be guessed by timing.
fn ct_eq(a: &[u8], b: &[u8]) -> bool {
    a.len() == b.len() && a.iter().zip(b).fold(0u8, |acc, (x, y)| acc | (x ^ y)) == 0
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(EnvFilter::try_from_default_env().unwrap_or_else(|_| "info".into()))
        .init();

    let addr = std::env::var("ENGINE_ADDR")
        .unwrap_or_else(|_| "0.0.0.0:50051".into())
        .parse()?;
    let token = std::env::var("ENGINE_INTERNAL_TOKEN")
        .map_err(|_| anyhow::anyhow!("ENGINE_INTERNAL_TOKEN must be set"))?;
    if token.len() < 16 {
        anyhow::bail!("ENGINE_INTERNAL_TOKEN must be at least 16 characters");
    }
    let expected: MetadataValue<_> = format!("Bearer {token}").parse()?;

    let op_timeout = Duration::from_millis(env_or("OP_TIMEOUT_MS", 10_000));
    let settings = PoolSettings {
        max_connections: env_or("POOL_MAX_CONNS", 10),
        acquire_timeout: Duration::from_millis(env_or("POOL_ACQUIRE_TIMEOUT_MS", 3000)),
        idle_timeout: Duration::from_secs(env_or("POOL_IDLE_TIMEOUT_S", 300)),
        drain_grace: op_timeout,
    };
    tracing::info!(?settings, ?op_timeout, %addr, "starting rust-engine");

    let pools = Arc::new(PoolManager::new(settings));
    let svc = EngineService::new(pools.clone(), op_timeout);

    // Only the Go API may call the engine. In production replace/augment this
    // shared secret with mTLS between the services.
    let auth = move |req: Request<()>| match req.metadata().get("authorization") {
        Some(v) if ct_eq(v.as_bytes(), expected.as_bytes()) => Ok(req),
        _ => Err(Status::unauthenticated("invalid internal token")),
    };

    let shutdown = async {
        let ctrl_c = tokio::signal::ctrl_c();
        let mut term = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
            .expect("install SIGTERM handler");
        tokio::select! {
            _ = ctrl_c => {},
            _ = term.recv() => {},
        }
        tracing::info!("shutdown signal received");
    };

    Server::builder()
        .timeout(op_timeout + Duration::from_secs(5))
        .add_service(DbEngineServer::with_interceptor(svc, auth))
        .serve_with_shutdown(addr, shutdown)
        .await?;

    pools.close_all().await;
    tracing::info!("all tenant pools closed");
    Ok(())
}
