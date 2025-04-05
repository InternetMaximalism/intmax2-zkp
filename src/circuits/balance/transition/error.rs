use thiserror::Error;

#[derive(Debug, Error)]
pub enum TransitionError {
    #[error("Verification failed: {message}")]
    VerificationFailed { message: String },

    #[error("Invalid value: {message}")]
    InvalidValue { message: String },

    #[error("Proof generation error: {0}")]
    ProofGenerationError(String),
}
