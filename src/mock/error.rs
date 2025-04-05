use thiserror::Error;

use crate::{circuits::validity::error::ValidityProverError, common::error::CommonError};

#[derive(Debug, Error)]
pub enum MockError {
    #[error("Block not found: {0}")]
    BlockNotFound(u32),

    #[error("Account tree not found for block number: {0}")]
    AccountTreeNotFound(u32),

    #[error("Block tree not found for block number: {0}")]
    BlockTreeNotFound(u32),

    #[error("Deposit tree not found for block number: {0}")]
    DepositTreeNotFound(u32),

    #[error("Previous validity proof not found for block number: {0}")]
    PrevValidityProofNotFound(u32),

    #[error("Failed to convert full block to block witness: {0}")]
    FullBlockConversionError(String),

    #[error("Failed to update trees: {0}")]
    TreeUpdateError(String),

    #[error("Failed to generate validity proof: {0}")]
    ValidityProofGenerationError(String),

    #[error("Failed to get block merkle proof: {0}")]
    BlockMerkleProofError(String),

    #[error("Failed to get account membership proof: {0}")]
    AccountMembershipProofError(String),

    #[error("Leaf block number should be smaller than or equal to root block number: leaf={leaf}, root={root}")]
    InvalidBlockNumberRelation { leaf: u32, root: u32 },

    #[error(transparent)]
    ValidityProverError(#[from] ValidityProverError),

    #[error(transparent)]
    CommonError(#[from] CommonError),

    #[error("Other error: {0}")]
    Other(String),
}
