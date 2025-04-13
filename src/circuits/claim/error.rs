use thiserror::Error;

#[derive(Debug, Error)]
pub enum ClaimError {
    #[error("Verification failed: {0}")]
    VerificationFailed(String),

    #[error("Invalid lock time: {0}")]
    InvalidLockTime(String),

    #[error("Invalid block number: {0}")]
    InvalidBlockNumber(String),

    #[error("Invalid input: {0}")]
    InvalidInput(String),

    #[error("Proof generation error: {0}")]
    ProofGenerationError(String),
}
