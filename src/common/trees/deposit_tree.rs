use crate::{
    common::deposit::{Deposit, DepositTarget},
    utils::trees::merkle_tree_with_leaves::{
        MerkleProofWithLeaves, MerkleProofWithLeavesTarget, MerkleTreeWithLeaves,
    },
};

pub type DepositTree = MerkleTreeWithLeaves<Deposit>;
pub type DepositMerkleProof = MerkleProofWithLeaves<Deposit>;
pub type DepositMerkleProofTarget = MerkleProofWithLeavesTarget<DepositTarget>;
