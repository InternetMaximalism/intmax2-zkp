use super::{
    block_validation::error::BlockValidationError, transition::error::ValidityTransitionError,
};
use crate::utils::poseidon_hash_out::PoseidonHashOut;

#[derive(Debug, thiserror::Error)]
pub enum ValidityProverError {
    #[error("Transition processor error: {0}")]
    TransitionProcessorError(#[from] ValidityTransitionError),

    #[error("Block validation error: {0}")]
    BlockValidationError(#[from] BlockValidationError),

    #[error("Validity circuit proof generation error: {0}")]
    ValidityCircuitProofError(String),

    #[error("Previous account tree root mismatch: expected {expected:?}, got {actual:?}")]
    PrevAccountTreeRootMismatch {
        expected: PoseidonHashOut,
        actual: PoseidonHashOut,
    },

    #[error("Previous block tree root mismatch: expected {expected:?}, got {actual:?}")]
    PrevBlockTreeRootMismatch {
        expected: PoseidonHashOut,
        actual: PoseidonHashOut,
    },

    #[error("Plonky2 error: {0}")]
    Plonky2Error(String),
}

impl From<anyhow::Error> for ValidityProverError {
    fn from(err: anyhow::Error) -> Self {
        ValidityProverError::Plonky2Error(err.to_string())
    }
}
