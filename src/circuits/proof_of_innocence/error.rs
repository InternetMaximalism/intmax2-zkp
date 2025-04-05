use thiserror::Error;

use crate::ethereum_types::{address::Address, bytes32::Bytes32};

#[derive(Debug, Error)]
pub enum InnocenceError {
    #[error("Depositor {0} is not in the allow list")]
    DepositorNotInAllowList(Address),

    #[error("Depositor {0} is in the deny list")]
    DepositorInDenyList(Address),

    #[error("Corresponding deposit not found for nullifier {0}")]
    DepositNotFound(Bytes32),

    #[error("At least one deposit is required")]
    NoDeposits,

    #[error("Invalid nullifier tree root: expected {expected}, got {actual}")]
    InvalidNullifierTreeRoot {
        expected: String,
        actual: String,
    },

    #[error("Allow list membership proof verification failed: {0}")]
    AllowListMembershipProofVerificationFailed(String),

    #[error("Deny list membership proof verification failed: {0}")]
    DenyListMembershipProofVerificationFailed(String),

    #[error("Invalid nullifier merkle proof: {0}")]
    InvalidNullifierMerkleProof(String),

    #[error("Failed to create allow list tree: {0}")]
    AllowListTreeCreationFailed(String),

    #[error("Failed to create deny list tree: {0}")]
    DenyListTreeCreationFailed(String),

    #[error("Failed to prove and insert nullifier: {0}")]
    NullifierInsertionFailed(String),

    #[error("Failed to create innocence inner value: {0}")]
    InnocenceInnerValueCreationFailed(String),

    #[error("Failed to prove innocence circuit: {0}")]
    InnocenceCircuitProofFailed(String),

    #[error("Failed to prove innocence wrap circuit: {0}")]
    InnocenceWrapCircuitProofFailed(String),

    #[error("Failed to verify innocence wrap circuit: {0}")]
    InnocenceWrapCircuitVerificationFailed(String),

    #[error("use_allow_list is not equal to the expected value: expected {expected}, got {actual}")]
    UseAllowListMismatch { expected: bool, actual: bool },

    #[error("allow_list_tree_root is not equal to the expected value: expected {expected}, got {actual}")]
    AllowListTreeRootMismatch {
        expected: String,
        actual: String,
    },

    #[error("deny_list_tree_root is not equal to the expected value: expected {expected}, got {actual}")]
    DenyListTreeRootMismatch {
        expected: String,
        actual: String,
    },

    #[error("private_commitment is not equal to the expected value: expected {expected}, got {actual}")]
    PrivateCommitmentMismatch {
        expected: String,
        actual: String,
    },

    #[error(transparent)]
    Other(#[from] anyhow::Error),
}
