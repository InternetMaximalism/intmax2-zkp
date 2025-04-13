#[derive(Debug, thiserror::Error)]
pub enum HashChainError {
    #[error("Invalid data: {0}")]
    InvalidData(String),

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

use crate::utils::error::Result as UtilsResult;

pub type Result<T> = UtilsResult<T>;
