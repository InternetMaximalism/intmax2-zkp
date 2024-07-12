use crate::{
    common::tx::{Tx, TxTarget},
    utils::trees::merkle_tree_with_leaves::{
        MerkleProofWithLeaves, MerkleProofWithLeavesTarget, MerkleTreeWithLeaves,
    },
};

pub type TxTree = MerkleTreeWithLeaves<Tx>;
pub type TxMerkleProof = MerkleProofWithLeaves<Tx>;
pub type TxMerkleProofTarget = MerkleProofWithLeavesTarget<TxTarget>;

impl TxTree {
    pub fn get_tx_index(&self, tx: &Tx) -> Option<usize> {
        self.leaves().iter().position(|leaf| leaf == tx)
    }
}
