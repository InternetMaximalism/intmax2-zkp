#[derive(Debug, thiserror::Error)]
pub enum HashChainError {
    #[error("Failed to prove inner: {0}")]
    InnerProofError(String),

    #[error("Failed to prove cyclic: {0}")]
    CyclicProofError(String),

    #[error("Failed to prove chain end: {0}")]
    ChainEndProofError(String),

    #[error("Invalid hash chain state: {0}")]
    InvalidState(String),

    #[error("Plonky2 error: {0}")]
    Plonky2Error(String),
}

// No direct From implementation for CircuitDataError since it doesn't exist

pub type Result<T> = std::result::Result<T, HashChainError>;
