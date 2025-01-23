pub mod insertion;
pub mod leaf;
pub mod membership;
pub mod update;

use anyhow::{anyhow, ensure};
use serde::{Deserialize, Serialize};

use crate::{
    ethereum_types::u256::U256,
    utils::{
        poseidon_hash_out::PoseidonHashOut,
        trees::incremental_merkle_tree::{
            IncrementalMerkleProof, IncrementalMerkleProofTarget, IncrementalMerkleTree,
        },
    },
};
use anyhow::Result;
use leaf::{IndexedMerkleLeaf, IndexedMerkleLeafTarget};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IndexedMerkleTree(IncrementalMerkleTree<IndexedMerkleLeaf>);
pub type IndexedMerkleProof = IncrementalMerkleProof<IndexedMerkleLeaf>;
pub type IndexedMerkleProofTarget = IncrementalMerkleProofTarget<IndexedMerkleLeafTarget>;

impl IndexedMerkleTree {
    pub fn new(height: usize) -> Self {
        let mut tree = IncrementalMerkleTree::<IndexedMerkleLeaf>::new(height);
        tree.push(IndexedMerkleLeaf::default());
        Self(tree)
    }

    pub fn get_root(&self) -> PoseidonHashOut {
        self.0.get_root()
    }

    pub fn get_leaf(&self, index: u64) -> IndexedMerkleLeaf {
        self.0.get_leaf(index)
    }

    pub fn prove(&self, index: u64) -> IndexedMerkleProof {
        self.0.prove(index)
    }

    pub(crate) fn low_index(&self, key: U256) -> Result<u64> {
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
        ensure!(
            low_leaf_candidates.len() == 1,
            "low_index: too many candidates"
        );
        let (low_leaf_index, _) = low_leaf_candidates[0];
        Ok(low_leaf_index as u64)
    }

    pub fn index(&self, key: U256) -> Option<u64> {
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
            "find_index: too many candidates"
        );
        let (leaf_index, _) = leaf_candidates[0];
        Some(leaf_index as u64)
    }

    pub fn key(&self, index: u64) -> U256 {
        self.0.get_leaf(index).key
    }

    pub fn update(&mut self, key: U256, value: u64) -> Result<()> {
        let index = self
            .index(key)
            .ok_or_else(|| anyhow!("Error: key doesn't exist"))?;
        let mut leaf = self.0.get_leaf(index);
        leaf.value = value;
        self.0.update(index, leaf);
        Ok(())
    }

    pub fn len(&self) -> usize {
        self.0.len()
    }
}
