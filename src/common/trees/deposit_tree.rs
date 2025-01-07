use crate::{
    common::deposit::{Deposit, DepositTarget},
    constants::DEPOSIT_TREE_HEIGHT,
    utils::trees::incremental_merkle_tree::{
        IncrementalMerkleProof, IncrementalMerkleProofTarget, IncrementalMerkleTree,
    },
};

pub type DepositTree = IncrementalMerkleTree<Deposit>;
pub type DepositMerkleProof = IncrementalMerkleProof<Deposit>;
pub type DepositMerkleProofTarget = IncrementalMerkleProofTarget<DepositTarget>;

impl DepositTree {
    pub fn initialize() -> Self {
        IncrementalMerkleTree::new(DEPOSIT_TREE_HEIGHT)
    }
}
