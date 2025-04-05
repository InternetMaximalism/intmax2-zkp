use thiserror::Error;

use crate::circuits::balance::receive::error::ReceiveError;
use crate::circuits::balance::send::error::SendError;
use crate::circuits::balance::transition::error::TransitionError;

#[derive(Debug, Error)]
pub enum BalanceError {
    #[error("Transition error: {0}")]
    Transition(#[from] TransitionError),

    #[error("Receive error: {0}")]
    Receive(#[from] ReceiveError),

    #[error("Send error: {0}")]
    Send(#[from] SendError),

    #[error("Verification failed: {0}")]
    VerificationFailed(String),

    #[error("Invalid input: {0}")]
    InvalidInput(String),

    #[error("Circuit build error: {0}")]
    CircuitBuildError(String),

    #[error("Proof generation error: {0}")]
    ProofGenerationError(String),

    #[error("Other error: {0}")]
    Other(String),
}

impl From<anyhow::Error> for BalanceError {
    fn from(err: anyhow::Error) -> Self {
        BalanceError::Other(format!("{:?}", err))
    }
}
