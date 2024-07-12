pub mod insertion;
pub mod leaf;
pub mod membership;
pub mod update;

use anyhow::{anyhow, ensure};

use crate::{
    ethereum_types::u256::U256,
    utils::{
        poseidon_hash_out::PoseidonHashOut,
        trees::merkle_tree_with_leaves::{
            MerkleProofWithLeaves, MerkleProofWithLeavesTarget, MerkleTreeWithLeaves,
        },
    },
};
use anyhow::Result;
use leaf::{IndexedMerkleLeaf, IndexedMerkleLeafTarget};

#[derive(Debug, Clone)]
pub struct IndexedMerkleTree(MerkleTreeWithLeaves<IndexedMerkleLeaf>);
pub type IndexedMerkleProof = MerkleProofWithLeaves<IndexedMerkleLeaf>;
pub type IndexedMerkleProofTarget = MerkleProofWithLeavesTarget<IndexedMerkleLeafTarget>;

impl IndexedMerkleTree {
    pub fn new(height: usize) -> Self {
        let mut tree = MerkleTreeWithLeaves::<IndexedMerkleLeaf>::new(height);
        tree.push(IndexedMerkleLeaf::default());
        Self(tree)
    }

    pub fn get_root(&self) -> PoseidonHashOut {
        self.0.get_root()
    }

    pub fn get_leaf(&self, index: usize) -> IndexedMerkleLeaf {
        self.0.get_leaf(index)
    }

    pub fn prove(&self, index: usize) -> IndexedMerkleProof {
        self.0.prove(index)
    }

    pub(crate) fn low_index(&self, key: U256<u32>) -> Result<usize> {
        let low_leaf_candidates = self
            .0
            .leaves()
            .into_iter()
            .enumerate()
            .filter(|(_, leaf)| {
                (leaf.key < key) && (key < leaf.next_key || leaf.next_key == U256::default())
            })
            .collect::<Vec<_>>();
        ensure!(0 < low_leaf_candidates.len(), "key already exists");
        assert!(
            low_leaf_candidates.len() == 1,
            "low_index; too many candidates"
        );
        let (low_leaf_index, _) = low_leaf_candidates[0];
        Ok(low_leaf_index)
    }

    pub(crate) fn index(&self, key: U256<u32>) -> Option<usize> {
        let leaf_candidates = self
            .0
            .leaves()
            .into_iter()
            .enumerate()
            .filter(|(_, leaf)| leaf.key == key)
            .collect::<Vec<_>>();
        if leaf_candidates.is_empty() {
            return None;
        }
        assert!(
            leaf_candidates.len() == 1,
            "find_index; too many candidates"
        );
        let (leaf_index, _) = leaf_candidates[0];
        Some(leaf_index)
    }

    pub fn key(&self, index: usize) -> U256<u32> {
        self.0.get_leaf(index).key
    }

    pub fn update(&mut self, key: U256<u32>, value: u64) -> Result<()> {
        let index = self
            .index(key)
            .ok_or_else(|| anyhow!("Error: key doesn't exist"))?;
        let mut leaf = self.0.get_leaf(index);
        leaf.value = value;
        self.0.update(index, leaf);
        Ok(())
    }
}
