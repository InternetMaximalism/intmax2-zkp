use crate::{
    common::transfer::Transfer,
    utils::trees::merkle_tree_with_leaves::{MerkleProofWithLeaves, MerkleTreeWithLeaves},
};

pub type TransferTree = MerkleTreeWithLeaves<Transfer>;
pub type TransferMerkleProof = MerkleProofWithLeaves<Transfer>;
