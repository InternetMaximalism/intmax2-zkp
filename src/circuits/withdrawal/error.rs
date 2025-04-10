use thiserror::Error;

#[derive(Debug, Error)]
pub enum WithdrawalError {
    #[error("Verification failed: {0}")]
    VerificationFailed(String),

    #[error("Invalid input: {0}")]
    InvalidInput(String),

    #[error("Proof generation error: {0}")]
    ProofGenerationError(String),
}
