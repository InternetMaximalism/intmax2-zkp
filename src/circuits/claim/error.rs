use thiserror::Error;

#[derive(Debug, Error)]
pub enum ClaimError {
    #[error("Verification failed: {message}")]
    VerificationFailed { message: String },

    #[error("Invalid lock time: {message}")]
    InvalidLockTime { message: String },

    #[error("Invalid block number: {message}")]
    InvalidBlockNumber { message: String },

    #[error("Proof generation error: {0}")]
    ProofGenerationError(String),
}
