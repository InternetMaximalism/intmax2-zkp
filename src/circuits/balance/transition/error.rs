use thiserror::Error;

#[derive(Debug, Error)]
pub enum TransitionError {
    #[error("Verification failed: {0}")]
    VerificationFailed(String),

    #[error("Invalid value: {0}")]
    InvalidValue(String),

    #[error("Proof generation error: {0}")]
    ProofGenerationError(String),
}
