use tonic::{Code, Status};

#[derive(Debug, thiserror::Error)]
pub enum EngineError {
    #[error("invalid request: {0}")]
    Invalid(String),

    /// A request arrived with an older config version than the live pool.
    /// Serving it would silently downgrade the tenant to an old database.
    #[error("stale config version for tenant '{tenant}': live={live}, request={request}")]
    StaleVersion {
        tenant: String,
        live: i64,
        request: i64,
    },

    /// Same tenant + version but different connection details: the control
    /// plane changed the config without bumping the version.
    #[error("config for tenant '{0}' changed without a version bump")]
    ConfigMismatch(String),

    /// The target database belongs to another tenant.
    #[error("database is claimed by tenant '{owner}', refusing to serve tenant '{tenant}'")]
    ClaimedByOther { owner: String, tenant: String },

    #[error("tenant database is not provisioned (run Provision first)")]
    NotProvisioned,

    #[error("not found")]
    NotFound,

    #[error("already exists: {0}")]
    AlreadyExists(String),

    #[error("operation timed out after {0}ms")]
    Timeout(u64),

    #[error("database error: {0}")]
    Db(String),
}

impl From<sqlx::Error> for EngineError {
    fn from(e: sqlx::Error) -> Self {
        EngineError::Db(e.to_string())
    }
}

impl From<mongodb::error::Error> for EngineError {
    fn from(e: mongodb::error::Error) -> Self {
        EngineError::Db(e.to_string())
    }
}

impl From<EngineError> for Status {
    fn from(e: EngineError) -> Self {
        let code = match &e {
            EngineError::Invalid(_) => Code::InvalidArgument,
            EngineError::StaleVersion { .. } | EngineError::ConfigMismatch(_) => {
                Code::FailedPrecondition
            }
            EngineError::ClaimedByOther { .. } => Code::PermissionDenied,
            EngineError::NotProvisioned => Code::FailedPrecondition,
            EngineError::NotFound => Code::NotFound,
            EngineError::AlreadyExists(_) => Code::AlreadyExists,
            EngineError::Timeout(_) => Code::DeadlineExceeded,
            EngineError::Db(_) => Code::Unavailable,
        };
        Status::new(code, e.to_string())
    }
}

pub type Result<T> = std::result::Result<T, EngineError>;
