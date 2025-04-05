use thiserror::Error;

#[derive(Debug, Error)]
pub enum ReceiveTargetsError {
    #[error("Verification failed: {0}")]
    VerificationFailed(String),

    #[error("Invalid input: {0}")]
    InvalidInput(String),
}
