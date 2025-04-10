pub mod insertion;
pub mod leaf;
pub mod membership;
pub mod update;

use serde::{Deserialize, Serialize};

use crate::{
    ethereum_types::u256::U256,
    utils::{
        poseidon_hash_out::PoseidonHashOut,
        trees::{
            error::IndexedMerkleTreeError,
            incremental_merkle_tree::{
                IncrementalMerkleProof, IncrementalMerkleProofTarget, IncrementalMerkleTree,
            },
        },
    },
};
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

    pub(crate) fn low_index(&self, key: U256) -> Result<u64, IndexedMerkleTreeError> {
        let low_leaf_candidates = self
            .0
            .leaves()
            .into_iter()
            .enumerate()
            .filter(|(_, leaf)| {
                (leaf.key < key) && (key < leaf.next_key || leaf.next_key == U256::default())
            })
            .collect::<Vec<_>>();
        if low_leaf_candidates.is_empty() {
            return Err(IndexedMerkleTreeError::KeyAlreadyExists(key.to_string()));
        }
        if low_leaf_candidates.len() != 1 {
            return Err(IndexedMerkleTreeError::TooManyCandidates(
                "low_index".to_string(),
            ));
        }
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
        if leaf_candidates.len() != 1 {
            panic!("find_index: too many candidates");
        }
        let (leaf_index, _) = leaf_candidates[0];
        Some(leaf_index as u64)
    }

    pub fn key(&self, index: u64) -> U256 {
        self.0.get_leaf(index).key
    }

    pub fn update(&mut self, key: U256, value: u64) -> Result<(), IndexedMerkleTreeError> {
        let index = self
            .index(key)
            .ok_or_else(|| IndexedMerkleTreeError::KeyDoesNotExist(key.to_string()))?;
        let mut leaf = self.0.get_leaf(index);
        leaf.value = value;
        self.0.update(index, leaf);
        Ok(())
    }

    pub fn leaves(&self) -> Vec<IndexedMerkleLeaf> {
        self.0.leaves()
    }

    pub fn len(&self) -> usize {
        self.leaves().len()
    }

    pub fn is_empty(&self) -> bool {
        self.leaves().is_empty()
    }
}

#[cfg(test)]
mod tests {
    use plonky2::{
        field::{goldilocks_field::GoldilocksField, types::Field},
        iop::witness::PartialWitness,
        plonk::{
            circuit_builder::CircuitBuilder, circuit_data::CircuitConfig,
            config::PoseidonGoldilocksConfig,
        },
    };
    use rand::Rng;

    use crate::{
        ethereum_types::{
            u256::{U256Target, U256},
            u32limb_trait::U32LimbTargetTrait,
        },
        utils::{poseidon_hash_out::PoseidonHashOutTarget, trees::error::IndexedMerkleTreeError},
    };

    use super::{update::UpdateProofTarget, IndexedMerkleTree};

    type F = GoldilocksField;
    const D: usize = 2;
    type C = PoseidonGoldilocksConfig;

    #[test]
    fn test_indexed_merkle_tree_update_error_cases() {
        let height = 40;
        let mut tree = IndexedMerkleTree::new(height);
        let rng = &mut rand::thread_rng();

        // Try to update a non-existent key
        let non_existent_key = U256::rand(rng);
        let result = tree.update(non_existent_key, 123);
        assert!(matches!(
            result,
            Err(IndexedMerkleTreeError::KeyDoesNotExist(_))
        ));

        // Try to prove and update a non-existent key
        let result = tree.prove_and_update(non_existent_key, 123);
        assert!(matches!(
            result,
            Err(IndexedMerkleTreeError::KeyDoesNotExist(_))
        ));

        // Insert a key and then try to update it
        let key = U256::rand(rng);
        let value: u64 = rng.gen();
        tree.insert(key, value).unwrap();

        // Now update should work
        tree.update(key, 456).unwrap();
        assert_eq!(tree.get_leaf(tree.index(key).unwrap()).value, 456);

        // Test UpdateProof verification with mismatched values
        let prev_value = 456;
        let new_value = 789;
        let prev_root = tree.get_root();
        let proof = tree.prove_and_update(key, new_value).unwrap();
        let new_root = tree.get_root();

        // Correct verification
        proof
            .verify(key, prev_value, new_value, prev_root, new_root)
            .unwrap();

        // Incorrect previous value
        let result = proof.verify(key, prev_value + 1, new_value, prev_root, new_root);
        if let Err(IndexedMerkleTreeError::ValueMismatch { expected, actual }) = result {
            assert_eq!(expected, prev_value + 1);
            assert_eq!(actual, prev_value);
        } else {
            panic!("Expected ValueMismatch error");
        }

        // Incorrect key
        let wrong_key = U256::rand(rng);
        let result = proof.verify(wrong_key, prev_value, new_value, prev_root, new_root);
        if let Err(IndexedMerkleTreeError::KeyMismatch { expected, actual }) = result {
            assert_eq!(expected, wrong_key.to_string());
            assert_eq!(actual, key.to_string());
        } else {
            panic!("Expected KeyMismatch error");
        }

        // Incorrect previous root
        let wrong_root = tree.get_root(); // This is now the new root, not the previous one
        let result = proof.verify(key, prev_value, new_value, wrong_root, new_root);
        if let Err(IndexedMerkleTreeError::MerkleProofError(_)) = result {
            // Test passed
        } else {
            panic!("Expected MerkleProofError");
        }

        // Incorrect new root
        let result = proof.verify(key, prev_value, new_value, prev_root, prev_root);
        if let Err(IndexedMerkleTreeError::NewRootMismatch { expected, actual }) = result {
            assert_eq!(expected.to_string(), new_root.to_string());
            assert_eq!(actual.to_string(), prev_root.to_string());
        } else {
            panic!("Expected NewRootMismatch error");
        }
    }

    #[test]
    fn test_indexed_merkle_tree_get_new_root() {
        let height = 40;
        let mut tree = IndexedMerkleTree::new(height);
        let rng = &mut rand::thread_rng();

        // Insert a key
        let key = U256::rand(rng);
        let value: u64 = rng.gen();
        tree.insert(key, value).unwrap();

        // Get the current root
        let prev_root = tree.get_root();

        // Create an update proof
        let new_value = value + 1;
        let proof = tree.prove_and_update(key, new_value).unwrap();

        // Get the new root
        let new_root = tree.get_root();

        // Verify that get_new_root returns the same root
        let calculated_new_root = proof
            .get_new_root(key, value, new_value, prev_root)
            .unwrap();
        assert_eq!(calculated_new_root, new_root);

        // Test with incorrect previous value
        let result = proof.get_new_root(key, value + 1, new_value, prev_root);
        if let Err(IndexedMerkleTreeError::ValueMismatch { expected, actual }) = result {
            assert_eq!(expected, value + 1);
            assert_eq!(actual, value);
        } else {
            panic!("Expected ValueMismatch error");
        }

        // Test with incorrect key
        let wrong_key = U256::rand(rng);
        let result = proof.get_new_root(wrong_key, value, new_value, prev_root);
        if let Err(IndexedMerkleTreeError::KeyMismatch { expected, actual }) = result {
            assert_eq!(expected, wrong_key.to_string());
            assert_eq!(actual, key.to_string());
        } else {
            panic!("Expected KeyMismatch error");
        }

        // Test with incorrect previous root
        let result = proof.get_new_root(key, value, new_value, new_root);
        if let Err(IndexedMerkleTreeError::MerkleProofError(_)) = result {
            // Test passed
        } else {
            panic!("Expected MerkleProofError");
        }
    }

    #[test]
    fn test_indexed_merkle_tree_update_target_circuit() {
        let height = 40;
        let mut tree = IndexedMerkleTree::new(height);
        let rng = &mut rand::thread_rng();

        // Insert a key
        let key = U256::rand(rng);
        let value: u64 = rng.gen();
        tree.insert(key, value).unwrap();

        // Create an update proof
        let prev_root = tree.get_root();
        let new_value = value + 1;
        let proof = tree.prove_and_update(key, new_value).unwrap();
        let new_root = tree.get_root();

        // Create a circuit to verify the update proof
        let mut builder = CircuitBuilder::<F, D>::new(CircuitConfig::default());

        // Create targets for the proof verification
        let key_t = U256Target::constant(&mut builder, key);
        let prev_value_t = builder.constant(F::from_canonical_u64(value));
        let new_value_t = builder.constant(F::from_canonical_u64(new_value));
        let prev_root_t = PoseidonHashOutTarget::constant(&mut builder, prev_root);
        let new_root_t = PoseidonHashOutTarget::constant(&mut builder, new_root);

        // Create a target for the update proof
        let proof_t = UpdateProofTarget::constant(&mut builder, &proof);

        // Verify the proof in the circuit
        proof_t.verify::<F, C, D>(
            &mut builder,
            key_t,
            prev_value_t,
            new_value_t,
            prev_root_t,
            new_root_t,
        );

        // Build and prove the circuit
        let circuit = builder.build::<C>();
        let pw = PartialWitness::new();
        let proof_result = circuit.prove(pw);
        assert!(proof_result.is_ok());
    }

    #[test]
    fn test_indexed_merkle_tree_update_target_get_new_root() {
        let height = 40;
        let mut tree = IndexedMerkleTree::new(height);
        let rng = &mut rand::thread_rng();

        // Insert a key
        let key = U256::rand(rng);
        let value: u64 = rng.gen();
        tree.insert(key, value).unwrap();

        // Create an update proof
        let prev_root = tree.get_root();
        let new_value = value + 1;
        let proof = tree.prove_and_update(key, new_value).unwrap();
        let new_root = tree.get_root();

        // Create a circuit to test get_new_root
        let mut builder = CircuitBuilder::<F, D>::new(CircuitConfig::default());

        // Create targets
        let key_t = U256Target::constant(&mut builder, key);
        let prev_value_t = builder.constant(F::from_canonical_u64(value));
        let new_value_t = builder.constant(F::from_canonical_u64(new_value));
        let prev_root_t = PoseidonHashOutTarget::constant(&mut builder, prev_root);

        // Create a target for the update proof
        let proof_t = UpdateProofTarget::constant(&mut builder, &proof);

        // Get the new root using the circuit
        let calculated_new_root_t = proof_t.get_new_root::<F, C, D>(
            &mut builder,
            key_t,
            prev_value_t,
            new_value_t,
            prev_root_t,
        );

        // Create a target for the expected new root
        let expected_new_root_t = PoseidonHashOutTarget::constant(&mut builder, new_root);

        // Assert that the calculated new root matches the expected new root
        calculated_new_root_t.connect(&mut builder, expected_new_root_t);

        // Build and prove the circuit
        let circuit = builder.build::<C>();
        let pw = PartialWitness::new();
        let proof_result = circuit.prove(pw);
        assert!(proof_result.is_ok());
    }

    #[test]
    fn test_indexed_merkle_tree_empty() {
        let height = 40;
        let tree = IndexedMerkleTree::new(height);

        // A new tree should have one default leaf
        assert_eq!(tree.len(), 1);
        assert!(!tree.is_empty());

        // The default leaf should have default values
        let default_leaf = tree.get_leaf(0);
        assert_eq!(default_leaf.key, U256::default());
        assert_eq!(default_leaf.next_key, U256::default());
        assert_eq!(default_leaf.next_index, 0);
        assert_eq!(default_leaf.value, 0);
    }

    #[test]
    fn test_indexed_merkle_tree_multiple_insertions() {
        let height = 40;
        let mut tree = IndexedMerkleTree::new(height);
        let rng = &mut rand::thread_rng();

        // Insert multiple keys in random order
        let mut keys = Vec::new();
        for _ in 0..10 {
            let key = U256::rand(rng);
            let value: u64 = rng.gen();
            tree.insert(key, value).unwrap();
            keys.push((key, value));
        }

        // Verify all keys are in the tree with correct values
        for (key, value) in &keys {
            let index = tree.index(*key).unwrap();
            let leaf = tree.get_leaf(index);
            assert_eq!(leaf.key, *key);
            assert_eq!(leaf.value, *value);
        }

        // Verify the tree maintains the correct relationships between keys
        let leaves = tree.leaves();
        for i in 0..leaves.len() {
            let leaf = &leaves[i];
            if leaf.key != U256::default() && leaf.next_index < leaves.len() as u64 {
                let next_leaf = &leaves[leaf.next_index as usize];
                assert_eq!(leaf.next_key, next_leaf.key);
            }
        }
    }

    #[test]
    fn test_indexed_merkle_tree_key_already_exists() {
        let height = 40;
        let mut tree = IndexedMerkleTree::new(height);
        let rng = &mut rand::thread_rng();

        // Insert a key
        let key = U256::rand(rng);
        let value: u64 = rng.gen();
        tree.insert(key, value).unwrap();

        // Try to insert the same key again
        let result = tree.insert(key, value + 1);
        assert!(matches!(
            result,
            Err(IndexedMerkleTreeError::KeyAlreadyExists(_))
        ));

        // Try to prove and insert the same key again
        let result = tree.prove_and_insert(key, value + 1);
        assert!(matches!(
            result,
            Err(IndexedMerkleTreeError::KeyAlreadyExists(_))
        ));
    }

    #[test]
    fn test_indexed_merkle_tree_prove_dummy() {
        let height = 40;
        let tree = IndexedMerkleTree::new(height);

        // Get a dummy proof
        let dummy_proof = tree.prove_dummy();

        // Verify the dummy proof has the expected structure
        assert_eq!(dummy_proof.index, 0);
        assert_eq!(dummy_proof.low_leaf_index, 0);

        // The prev_low_leaf should be the default leaf
        let default_leaf = tree.get_leaf(0);
        assert_eq!(dummy_proof.prev_low_leaf, default_leaf);
    }
}
