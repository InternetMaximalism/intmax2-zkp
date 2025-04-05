use thiserror::Error;

#[derive(Debug, Error)]
pub enum ReceiveError {
    #[error("Verification failed: {message}")]
    VerificationFailed { message: String },

    #[error("Invalid input: {message}")]
    InvalidInput { message: String },

    #[error("Proof generation error: {0}")]
    ProofGenerationError(String),
}
