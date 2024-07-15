

use crate::{
    ethereum_types::bytes32::{Bytes32, Bytes32Target},
    utils::trees::merkle_tree_with_leaves::{
        MerkleProofWithLeaves, MerkleProofWithLeavesTarget, MerkleTreeWithLeaves,
    },
};

pub type BlockHashTree = MerkleTreeWithLeaves<Bytes32>;
pub type BlockHashMerkleProof = MerkleProofWithLeaves<Bytes32>;
pub type BlockHashMerkleProofTarget = MerkleProofWithLeavesTarget<Bytes32Target>;
