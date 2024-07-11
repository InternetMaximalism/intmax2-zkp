use crate::{
    common::transfer::{Transfer, TransferTarget},
    utils::trees::merkle_tree_with_leaves::{
        MerkleProofWithLeaves, MerkleProofWithLeavesTarget, MerkleTreeWithLeaves,
    },
};

pub type TransferTree = MerkleTreeWithLeaves<Transfer>;
pub type TransferMerkleProof = MerkleProofWithLeaves<Transfer>;
pub type TransferMerkleProofTarget = MerkleProofWithLeavesTarget<TransferTarget>;
