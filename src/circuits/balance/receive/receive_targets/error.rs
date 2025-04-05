use thiserror::Error;

#[derive(Debug, Error)]
pub enum ReceiveTargetsError {
    #[error("Verification failed: {message}")]
    VerificationFailed { message: String },

    #[error("Invalid input: {message}")]
    InvalidInput { message: String },
}
