use thiserror::Error;

#[derive(Debug, Error)]
pub enum SignatureContentError {
    #[error("Invalid pubkeys length: expected {expected} but got {actual}")]
    InvalidPubkeysLength { expected: usize, actual: usize },
}
