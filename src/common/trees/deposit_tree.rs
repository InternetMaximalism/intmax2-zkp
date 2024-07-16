use crate::{
    common::deposit::{Deposit, DepositTarget},
    utils::trees::incremental_merkle_tree::{
        IncrementalMerkleProof, IncrementalMerkleProofTarget, IncrementalMerkleTree,
    },
};

pub type DepositTree = IncrementalMerkleTree<Deposit>;
pub type DepositMerkleProof = IncrementalMerkleProof<Deposit>;
pub type DepositMerkleProofTarget = IncrementalMerkleProofTarget<DepositTarget>;
