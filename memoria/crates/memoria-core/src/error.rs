use thiserror::Error;

#[derive(Debug, Error, Clone)]
pub enum MemoriaError {
    #[error("Invalid memory type: {0}")]
    InvalidMemoryType(String),

    #[error("Invalid trust tier: {0}")]
    InvalidTrustTier(String),

    #[error("Memory not found: {0}")]
    NotFound(String),

    #[error("Database error: {0}")]
    Database(String),

    #[error("Serialization error: {0}")]
    Serialization(String),

    #[error("Embedding error: {0}")]
    Embedding(String),

    #[error("Internal error: {0}")]
    Internal(String),

    #[error("Validation error: {0}")]
    Validation(String),

    #[error("Blocked: {0}")]
    Blocked(String),

    /// Apply was bound to a main head that is no longer current.
    ///
    /// `expected` is the base the client reviewed. `current` is the main head
    /// at apply time. Callers must not write main when this is returned.
    #[error("StaleBase: main head {current} does not match expected base {expected}")]
    StaleBase { expected: String, current: String },
}

impl From<serde_json::Error> for MemoriaError {
    fn from(e: serde_json::Error) -> Self {
        MemoriaError::Serialization(e.to_string())
    }
}
