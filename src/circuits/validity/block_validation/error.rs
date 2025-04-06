use crate::{ethereum_types::bytes32::Bytes32, utils::poseidon_hash_out::PoseidonHashOut};

#[derive(Debug, thiserror::Error)]
pub enum BlockValidationError {
    #[error("Plonky2 error: {0}")]
    Plonky2Error(String),
    #[error("AccountInclusionValue error: {0}")]
    AccountInclusionValue(String),

    #[error("AccountExclusionValue error: {0}")]
    AccountExclusionValue(String),

    // Format validation errors
    #[error("FormatValidation input length mismatch: expected {expected}, got {actual}")]
    FormatValidationInputLengthMismatch { expected: usize, actual: usize },

    // Aggregation errors
    #[error("Aggregation input length mismatch: expected {expected}, got {actual}")]
    AggregationInputLengthMismatch { expected: usize, actual: usize },

    // Main validation errors
    #[error("MainValidation input length mismatch: expected {expected}, got {actual}")]
    MainValidationInputLengthMismatch { expected: usize, actual: usize },

    #[error("Pubkey hash mismatch: expected {expected:?}, got {actual:?}")]
    PubkeyHashMismatch { expected: Bytes32, actual: Bytes32 },

    #[error("Signature hash mismatch: expected {expected:?}, got {actual:?}")]
    SignatureHashMismatch { expected: Bytes32, actual: Bytes32 },

    #[error("Sender tree root mismatch: expected {expected:?}, got {actual:?}")]
    SenderTreeRootMismatch {
        expected: PoseidonHashOut,
        actual: PoseidonHashOut,
    },

    #[error("Account tree root mismatch: expected {expected:?}, got {actual:?}")]
    AccountTreeRootMismatch {
        expected: PoseidonHashOut,
        actual: PoseidonHashOut,
    },

    #[error("Pubkey commitment mismatch: expected {expected:?}, got {actual:?}")]
    PubkeyCommitmentMismatch {
        expected: PoseidonHashOut,
        actual: PoseidonHashOut,
    },

    #[error("Signature commitment mismatch: expected {expected:?}, got {actual:?}")]
    SignatureCommitmentMismatch {
        expected: PoseidonHashOut,
        actual: PoseidonHashOut,
    },

    #[error("Account ID hash mismatch: expected {expected:?}, got {actual:?}")]
    AccountIdHashMismatch { expected: Bytes32, actual: Bytes32 },

    #[error("Account exclusion proof verification failed: {0}")]
    AccountExclusionProofVerificationFailed(String),

    #[error("Account inclusion proof verification failed: {0}")]
    AccountInclusionProofVerificationFailed(String),

    #[error("Format validation proof verification failed: {0}")]
    FormatValidationProofVerificationFailed(String),

    #[error("Aggregation proof verification failed: {0}")]
    AggregationProofVerificationFailed(String),

    #[error("Main validation proof generation failed: {0}")]
    MainValidationProofGenerationFailed(String),
}
