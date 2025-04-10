use crate::utils::poseidon_hash_out::PoseidonHashOut;

#[derive(Debug, thiserror::Error)]
pub enum ValidityTransitionError {
    // Account transition errors
    #[error("AccountTransition input length mismatch: expected {expected}, got {actual}")]
    AccountTransitionInputLengthMismatch { expected: usize, actual: usize },

    // Account registration errors
    #[error("Invalid number of sender leaves: expected {expected}, got {actual}")]
    InvalidSenderLeavesCount { expected: usize, actual: usize },

    #[error("Invalid number of account registration proofs: expected {expected}, got {actual}")]
    InvalidAccountRegistrationProofsCount { expected: usize, actual: usize },

    #[error("Invalid account registration proof: {0}")]
    InvalidAccountRegistrationProof(String),

    #[error("Account ID mismatch: expected {expected}, got {actual}")]
    AccountIdMismatch { expected: u64, actual: u64 },

    // Account update errors
    #[error("Invalid number of account update proofs: expected {expected}, got {actual}")]
    InvalidAccountUpdateProofsCount { expected: usize, actual: usize },

    #[error("Invalid account update proof: {0}")]
    InvalidAccountUpdateProof(String),

    // Transition errors
    #[error("Account registration proof is missing")]
    MissingAccountRegistrationProof,

    #[error("Account update proof is missing")]
    MissingAccountUpdateProof,

    #[error("Account registration proof is invalid: {0}")]
    InvalidAccountRegistrationProofVerification(String),

    #[error("Account update proof is invalid: {0}")]
    InvalidAccountUpdateProofVerification(String),

    #[error("Previous account tree root mismatch: expected {expected:?}, got {actual:?}")]
    PrevAccountTreeRootMismatch {
        expected: PoseidonHashOut,
        actual: PoseidonHashOut,
    },

    #[error("Previous next account ID mismatch: expected {expected}, got {actual}")]
    PrevNextAccountIdMismatch { expected: u64, actual: u64 },

    #[error("Sender tree root mismatch: expected {expected:?}, got {actual:?}")]
    SenderTreeRootMismatch {
        expected: PoseidonHashOut,
        actual: PoseidonHashOut,
    },

    #[error("Block number mismatch: expected {expected}, got {actual}")]
    BlockNumberMismatch { expected: u32, actual: u32 },

    #[error("Block hash merkle proof is invalid: {0}")]
    InvalidBlockHashMerkleProof(String),

    // Dummy wrapper errors
    #[error("Invalid validity witness: {0}")]
    InvalidValidityWitness(String),

    #[error("Block tree root mismatch: expected {expected:?}, got {actual:?}")]
    BlockTreeRootMismatch {
        expected: PoseidonHashOut,
        actual: PoseidonHashOut,
    },

    #[error("Proof generation error: {0}")]
    ProofGenerationError(String),
}
