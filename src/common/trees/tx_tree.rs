use crate::{
    common::tx::{Tx, TxTarget},
    utils::trees::incremental_merkle_tree::{
        IncrementalMerkleProof, IncrementalMerkleProofTarget, IncrementalMerkleTree,
    },
};

pub type TxTree = IncrementalMerkleTree<Tx>;
pub type TxMerkleProof = IncrementalMerkleProof<Tx>;
pub type TxMerkleProofTarget = IncrementalMerkleProofTarget<TxTarget>;

impl TxTree {
    pub fn get_tx_index(&self, tx: &Tx) -> Option<usize> {
        self.leaves().iter().position(|leaf| leaf == tx)
    }
}
