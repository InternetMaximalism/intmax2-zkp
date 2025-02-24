use crate::{
    common::block::Block,
    constants::BLOCK_HASH_TREE_HEIGHT,
    ethereum_types::bytes32::{Bytes32, Bytes32Target},
    utils::trees::incremental_merkle_tree::{
        IncrementalMerkleProof, IncrementalMerkleProofTarget, IncrementalMerkleTree,
    },
};

pub type BlockHashTree = IncrementalMerkleTree<Bytes32>;
pub type BlockHashMerkleProof = IncrementalMerkleProof<Bytes32>;
pub type BlockHashMerkleProofTarget = IncrementalMerkleProofTarget<Bytes32Target>;

impl BlockHashTree {
    pub fn initialize() -> Self {
        let mut tree = IncrementalMerkleTree::new(BLOCK_HASH_TREE_HEIGHT);
        tree.push(Block::genesis().hash());
        tree
    }
}
