use plonky2::iop::target::Target;

use crate::{
    ethereum_types::bytes32::Bytes32,
    utils::trees::merkle_tree_with_leaves::{
        MerkleProofWithLeaves, MerkleProofWithLeavesTarget, MerkleTreeWithLeaves,
    },
};

pub type BlockHashTree = MerkleTreeWithLeaves<Bytes32<u32>>;
pub type BlockHashMerkleProof = MerkleProofWithLeaves<Bytes32<u32>>;
pub type BlockHashMerkleProofTarget = MerkleProofWithLeavesTarget<Bytes32<Target>>;
