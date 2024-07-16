use crate::{
    common::transfer::{Transfer, TransferTarget},
    utils::trees::incremental_merkle_tree::{
        IncrementalMerkleProof, IncrementalMerkleProofTarget, IncrementalMerkleTree,
    },
};

pub type TransferTree = IncrementalMerkleTree<Transfer>;
pub type TransferMerkleProof = IncrementalMerkleProof<Transfer>;
pub type TransferMerkleProofTarget = IncrementalMerkleProofTarget<TransferTarget>;
