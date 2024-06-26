use crate::{
    common::tx::Tx,
    utils::trees::merkle_tree_with_leaves::{MerkleProofWithLeaves, MerkleTreeWithLeaves},
};

pub type TxTree = MerkleTreeWithLeaves<Tx>;
pub type TxMerkleProof = MerkleProofWithLeaves<Tx>;
