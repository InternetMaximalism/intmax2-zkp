use thiserror::Error;

use crate::utils::hash_chain::error::HashChainError;

use super::trees::error::{IndexedMerkleTreeError, MerkleProofError};

/// Top-level error type for the utils module
#[derive(Debug, Error)]
pub enum UtilsError {
    #[error(transparent)]
    HashChain(#[from] HashChainError),

    #[error(transparent)]
    Serialize(#[from] SerializeError),

    #[error(transparent)]
    Cyclic(#[from] CyclicError),

    #[error(transparent)]
    PoseidonHashOut(#[from] PoseidonHashOutError),

    #[error(transparent)]
    Wrapper(#[from] WrapperError),

    #[error(transparent)]
    MerkleProofError(#[from] MerkleProofError),

    #[error(transparent)]
    IndexedMerkleTreeError(#[from] IndexedMerkleTreeError),
}

/// Result type alias for utils module
pub type Result<T> = std::result::Result<T, UtilsError>;

#[derive(Debug, Error)]
pub enum SerializeError {
    #[error("Failed to serialize verifier data: {0}")]
    SerializationFailed(String),

    #[error("Failed to deserialize verifier data: {0}")]
    DeserializationFailed(String),
}

#[derive(Debug, Error)]
pub enum CyclicError {
    #[error("Not enough public inputs")]
    NotEnoughPublicInputs,

    #[error("Invalid verifier data: {0}")]
    InvalidVerifierData(String),
}

#[derive(Debug, Error)]
pub enum PoseidonHashOutError {
    #[error("Failed to recover HashOut from Bytes32")]
    RecoveryFailed,

    #[error("Invalid hash value: {0}")]
    InvalidHashValue(String),
}

#[derive(Debug, Error)]
pub enum WrapperError {
    #[error("Failed to prove wrapper circuit: {0}")]
    ProofGenerationFailed(String),

    #[error("Invalid proof: {0}")]
    InvalidProof(String),
}
