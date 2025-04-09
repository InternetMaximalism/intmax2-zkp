use hashbrown::HashMap;
use plonky2::{
    field::{extension::Extendable, types::Field},
    hash::hash_types::RichField,
    iop::{target::Target, witness::WitnessWrite},
    plonk::{
        circuit_builder::CircuitBuilder,
        config::{AlgebraicHasher, GenericConfig},
    },
};
use serde::{Deserialize, Deserializer, Serialize, Serializer};

use super::{
    error::MerkleProofError,
    merkle_tree::{HashOut, HashOutTarget, MerkleProof, MerkleProofTarget, MerkleTree},
};
use crate::utils::leafable::{Leafable, LeafableTarget};

// Merkle Tree that holds leaves as a vec. It is suitable for handling indexed
// leaves.
#[derive(Debug, Clone)]
pub struct SparseMerkleTree<V: Leafable> {
    merkle_tree: MerkleTree<V>,
    leaves: HashMap<u64, V>,
}

impl<V: Leafable> SparseMerkleTree<V> {
    pub fn new(height: usize) -> Self {
        let merkle_tree = MerkleTree::new(height);
        let leaves = HashMap::new();
        Self {
            merkle_tree,
            leaves,
        }
    }

    pub fn height(&self) -> usize {
        self.merkle_tree.height()
    }

    pub fn get_leaf(&self, index: u64) -> V {
        match self.leaves.get(&index) {
            Some(leaf) => leaf.clone(),
            None => V::empty_leaf(),
        }
    }

    pub fn get_root(&self) -> HashOut<V> {
        self.merkle_tree.get_root()
    }

    pub fn leaves(&self) -> HashMap<u64, V> {
        self.leaves.clone()
    }

    pub fn len(&self) -> usize {
        self.leaves.len()
    }

    pub fn is_empty(&self) -> bool {
        self.leaves.is_empty()
    }

    pub fn update(&mut self, index: u64, leaf: V) {
        self.merkle_tree.update_leaf(index, leaf.hash());
        self.leaves.insert(index, leaf);
    }

    pub fn prove(&self, index: u64) -> SparseMerkleProof<V> {
        SparseMerkleProof(self.merkle_tree.prove(index))
    }
}

#[derive(Debug, Clone)]
pub struct SparseMerkleProof<V: Leafable>(pub(crate) MerkleProof<V>);

impl<V: Leafable> SparseMerkleProof<V> {
    pub fn get_root(&self, leaf_data: &V, index: u64) -> HashOut<V> {
        self.0.get_root(leaf_data, index)
    }

    pub fn verify(
        &self,
        leaf_data: &V,
        index: u64,
        merkle_root: HashOut<V>,
    ) -> Result<(), MerkleProofError> {
        self.0.verify(leaf_data, index, merkle_root)
    }

    pub fn from_siblings(siblings: Vec<HashOut<V>>) -> Self {
        Self(MerkleProof { siblings })
    }
}

impl<V: Leafable> Serialize for SparseMerkleProof<V>
where
    HashOut<V>: Serialize,
{
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        self.0.siblings.serialize(serializer)
    }
}

impl<'de, V: Leafable> Deserialize<'de> for SparseMerkleProof<V>
where
    HashOut<V>: Deserialize<'de>,
{
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let siblings = Vec::<HashOut<V>>::deserialize(deserializer)?;
        Ok(SparseMerkleProof(MerkleProof { siblings }))
    }
}

#[derive(Debug, Clone)]
pub struct SparseMerkleProofTarget<VT: LeafableTarget>(pub(crate) MerkleProofTarget<VT>);

impl<VT: LeafableTarget> SparseMerkleProofTarget<VT> {
    pub fn new<F: RichField + Extendable<D>, const D: usize>(
        builder: &mut CircuitBuilder<F, D>,
        height: usize,
    ) -> Self {
        Self(MerkleProofTarget::new(builder, height))
    }

    pub fn constant<F: RichField + Extendable<D>, const D: usize>(
        builder: &mut CircuitBuilder<F, D>,
        value: &SparseMerkleProof<VT::Leaf>,
    ) -> Self {
        Self(MerkleProofTarget::constant(builder, &value.0))
    }

    pub fn set_witness<F: Field, W: WitnessWrite<F>>(
        &self,
        pw: &mut W,
        merkle_proof: &SparseMerkleProof<VT::Leaf>,
    ) {
        self.0.set_witness(pw, &merkle_proof.0)
    }
}

impl<VT: LeafableTarget> SparseMerkleProofTarget<VT> {
    pub fn get_root<
        F: RichField + Extendable<D>,
        C: GenericConfig<D, F = F> + 'static,
        const D: usize,
    >(
        &self,
        builder: &mut CircuitBuilder<F, D>,
        leaf_data: &VT,
        index: Target,
    ) -> HashOutTarget<VT>
    where
        <C as GenericConfig<D>>::Hasher: AlgebraicHasher<F>,
    {
        self.0.get_root::<F, C, D>(builder, leaf_data, index)
    }

    pub fn verify<
        F: RichField + Extendable<D>,
        C: GenericConfig<D, F = F> + 'static,
        const D: usize,
    >(
        &self,
        builder: &mut CircuitBuilder<F, D>,
        leaf_data: &VT,
        index: Target,
        merkle_root: HashOutTarget<VT>,
    ) where
        <C as GenericConfig<D>>::Hasher: AlgebraicHasher<F>,
    {
        self.0
            .verify::<F, C, D>(builder, leaf_data, index, merkle_root)
    }
}

// serialization
#[derive(Debug, Clone, Serialize, Deserialize)]
struct SparseMerkleTreePacked<V: Leafable> {
    height: usize,
    leaves: Vec<(u64, V)>,
}

impl<V: Leafable> SparseMerkleTree<V> {
    fn pack(&self) -> SparseMerkleTreePacked<V> {
        SparseMerkleTreePacked {
            height: self.height(),
            leaves: self.leaves().into_iter().collect(),
        }
    }

    fn unpack(packed: SparseMerkleTreePacked<V>) -> SparseMerkleTree<V> {
        let mut tree = SparseMerkleTree::new(packed.height);
        for (index, leaf) in packed.leaves {
            tree.update(index, leaf);
        }
        tree
    }
}

impl<V: Leafable> Serialize for SparseMerkleTree<V>
where
    V: Serialize,
{
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        self.pack().serialize(serializer)
    }
}

impl<'de, V: Leafable> Deserialize<'de> for SparseMerkleTree<V>
where
    V: Deserialize<'de>,
{
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        SparseMerkleTreePacked::<V>::deserialize(deserializer).map(SparseMerkleTree::unpack)
    }
}

#[cfg(test)]
mod tests {
    use crate::{
        ethereum_types::{
            bytes32::{Bytes32, Bytes32Target},
            u32limb_trait::{U32LimbTargetTrait, U32LimbTrait as _},
        },
        utils::{
            leafable_hasher::LeafableHasher, poseidon_hash_out::PoseidonHashOutTarget,
            trees::merkle_tree::HasherFromTarget,
        },
    };

    use super::*;
    use plonky2::{
        field::types::Field,
        iop::witness::{PartialWitness, WitnessWrite},
        plonk::{
            circuit_data::CircuitConfig,
            config::{GenericConfig, PoseidonGoldilocksConfig},
        },
    };
    use rand::Rng;
    use serde_json;

    const D: usize = 2;
    type C = PoseidonGoldilocksConfig;
    type F = <C as GenericConfig<D>>::F;

    #[test]
    fn test_sparse_merkle_tree_basic() {
        let mut rng = rand::thread_rng();
        let height = 5;

        type V = Bytes32;
        let mut tree = SparseMerkleTree::<V>::new(height);

        for i in 0..10 {
            let new_leaf = Bytes32::rand(&mut rng);
            tree.update(i, new_leaf);
        }

        for _ in 0..10 {
            let index = rng.gen_range(0..1 << height);
            let leaf = tree.get_leaf(index);
            let proof = tree.prove(index);
            assert_eq!(tree.get_leaf(index), leaf.clone());
            proof.verify(&leaf, index, tree.get_root()).unwrap();
        }
    }

    #[test]
    fn test_sparse_merkle_tree_circuit() {
        let mut rng = rand::thread_rng();
        let height = 5;

        type V = Bytes32;
        type VT = Bytes32Target;
        let mut tree = SparseMerkleTree::<V>::new(height);
        for i in 0..1 << height {
            let new_leaf = V::rand(&mut rng);
            tree.update(i, new_leaf);
        }

        let index = rng.gen_range(0..1 << height);
        let leaf = tree.get_leaf(index);
        let proof = tree.prove(index);

        let mut builder = CircuitBuilder::<F, D>::new(CircuitConfig::default());
        let proof_t = SparseMerkleProofTarget::<VT>::new(&mut builder, height);
        let leaf_t = VT::new(&mut builder, false);
        let root_t = PoseidonHashOutTarget::new(&mut builder);
        let index_t = builder.add_virtual_target();
        proof_t.verify::<F, C, D>(&mut builder, &leaf_t, index_t, root_t);

        let data = builder.build::<C>();
        let mut pw = PartialWitness::<F>::new();
        leaf_t.set_witness(&mut pw, leaf);
        root_t.set_witness(&mut pw, tree.get_root());
        pw.set_target(index_t, F::from_canonical_u64(index));
        proof_t.set_witness(&mut pw, &proof);
        data.prove(pw).unwrap();
    }

    #[test]
    fn test_sparse_merkle_tree_serialization() {
        let mut rng = rand::thread_rng();
        let height = 10;

        type V = Bytes32;
        let mut tree = SparseMerkleTree::<V>::new(height);

        for _ in 0..100 {
            let new_leaf = Bytes32::rand(&mut rng);
            let index = rng.gen_range(0..1 << height);
            tree.update(index, new_leaf);
        }

        // Test direct serialization/deserialization
        let serialized = serde_json::to_string(&tree).unwrap();
        let deserialized: SparseMerkleTree<V> = serde_json::from_str(&serialized).unwrap();

        assert_eq!(tree.get_root(), deserialized.get_root());
        assert_eq!(tree.height(), deserialized.height());
        assert_eq!(tree.len(), deserialized.len());

        // Check all leaves match
        for (index, leaf) in &tree.leaves() {
            assert_eq!(deserialized.get_leaf(*index), leaf.clone());
        }

        // Test packed serialization/deserialization
        let packed = SparseMerkleTreePacked {
            height,
            leaves: tree.leaves().into_iter().collect(),
        };
        let packed_str = serde_json::to_string(&packed).unwrap();
        let packed_deserialized: SparseMerkleTreePacked<V> = serde_json::from_str(&packed_str)
            .expect("failed to deserialize SparseMerkleTreePacked");
        let tree_deserialized = SparseMerkleTree::<V>::unpack(packed_deserialized);

        assert_eq!(tree.get_root(), tree_deserialized.get_root());
    }

    #[test]
    fn test_sparse_merkle_tree_new() {
        // Test with different heights
        let heights = [1, 5, 10, 20];
        for height in heights {
            let tree = SparseMerkleTree::<Bytes32>::new(height);
            assert_eq!(tree.height(), height);
            assert_eq!(tree.len(), 0);
            assert!(tree.is_empty());
            assert!(tree.leaves().is_empty());
        }
    }

    #[test]
    fn test_sparse_merkle_tree_height() {
        let height = 10;
        let tree = SparseMerkleTree::<Bytes32>::new(height);
        assert_eq!(tree.height(), height);
    }

    #[test]
    fn test_sparse_merkle_tree_get_leaf() {
        let mut rng = rand::thread_rng();
        let height = 5;

        type V = Bytes32;
        let mut tree = SparseMerkleTree::<V>::new(height);

        // Empty tree should return empty leaf for any index
        for i in 0..10 {
            assert_eq!(tree.get_leaf(i), V::empty_leaf());
        }

        // Add some leaves
        let mut leaves = HashMap::new();
        for i in 0..5 {
            let new_leaf = V::rand(&mut rng);
            leaves.insert(i, new_leaf);
            tree.update(i, new_leaf);
        }

        // Check existing leaves
        for (i, leaf) in &leaves {
            assert_eq!(tree.get_leaf(*i), *leaf);
        }

        // Check non-existent leaves
        for i in 5..10 {
            assert_eq!(tree.get_leaf(i), V::empty_leaf());
        }
    }

    #[test]
    fn test_sparse_merkle_tree_get_root() {
        let mut rng = rand::thread_rng();
        let height = 5;

        type V = Bytes32;
        let mut tree = SparseMerkleTree::<V>::new(height);

        // Empty tree root
        let empty_root = tree.get_root();

        // Add a leaf and check that root changes
        let leaf = V::rand(&mut rng);
        tree.update(0, leaf);
        let root_with_one_leaf = tree.get_root();
        assert_ne!(empty_root, root_with_one_leaf);

        // Add another leaf and check that root changes again
        let leaf2 = V::rand(&mut rng);
        tree.update(1, leaf2);
        let root_with_two_leaves = tree.get_root();
        assert_ne!(root_with_one_leaf, root_with_two_leaves);
    }

    #[test]
    fn test_sparse_merkle_tree_leaves() {
        let mut rng = rand::thread_rng();
        let height = 5;

        type V = Bytes32;
        let mut tree = SparseMerkleTree::<V>::new(height);
        assert!(tree.leaves().is_empty());

        // Add some leaves
        let mut expected_leaves = HashMap::new();
        for i in 0..5 {
            let new_leaf = V::rand(&mut rng);
            expected_leaves.insert(i, new_leaf);
            tree.update(i, new_leaf);
        }

        // Check leaves() returns all leaves
        let leaves = tree.leaves();
        assert_eq!(leaves.len(), expected_leaves.len());
        for (index, leaf) in &expected_leaves {
            assert_eq!(leaves.get(index), Some(leaf));
        }
    }

    #[test]
    fn test_sparse_merkle_tree_len_and_is_empty() {
        let mut rng = rand::thread_rng();
        let height = 5;

        type V = Bytes32;
        let mut tree = SparseMerkleTree::<V>::new(height);
        assert_eq!(tree.len(), 0);
        assert!(tree.is_empty());

        // Add some leaves
        for i in 0..5 {
            let new_leaf = V::rand(&mut rng);
            tree.update(i, new_leaf);

            // Verify length increases
            assert_eq!(tree.len(), i as usize + 1);
            assert!(!tree.is_empty());
        }

        // Update existing leaf shouldn't change length
        let new_leaf = V::rand(&mut rng);
        tree.update(0, new_leaf);
        assert_eq!(tree.len(), 5);
    }

    #[test]
    fn test_sparse_merkle_tree_update() {
        let mut rng = rand::thread_rng();
        let height = 5;

        type V = Bytes32;
        let mut tree = SparseMerkleTree::<V>::new(height);

        // Add a new leaf
        let leaf1 = V::rand(&mut rng);
        tree.update(0, leaf1);
        assert_eq!(tree.get_leaf(0), leaf1);

        // Update the leaf
        let leaf2 = V::rand(&mut rng);
        let root_before = tree.get_root();
        tree.update(0, leaf2);

        // Verify the leaf was updated
        assert_eq!(tree.get_leaf(0), leaf2);

        // Verify the root changed
        let root_after = tree.get_root();
        assert_ne!(root_before, root_after);
    }

    #[test]
    fn test_sparse_merkle_tree_prove() {
        let mut rng = rand::thread_rng();
        let height = 5;

        type V = Bytes32;
        let mut tree = SparseMerkleTree::<V>::new(height);

        // Add some leaves
        for i in 0..5 {
            let new_leaf = V::rand(&mut rng);
            tree.update(i, new_leaf);
        }

        // Generate proofs for existing leaves
        for i in 0..5 {
            let leaf = tree.get_leaf(i);
            let proof = tree.prove(i);

            // Verify the proof
            assert!(proof.verify(&leaf, i, tree.get_root()).is_ok());
        }

        // Generate proof for non-existent leaf
        let index = 10;
        let leaf = tree.get_leaf(index); // Should be empty leaf
        let proof = tree.prove(index);

        // Verify the proof for empty leaf
        assert!(proof.verify(&leaf, index, tree.get_root()).is_ok());
    }

    #[test]
    fn test_sparse_merkle_proof_from_siblings() {
        let mut rng = rand::thread_rng();
        let height = 5;

        // Create random siblings
        let siblings: Vec<HashOut<Bytes32>> = (0..height)
            .map(|_| Bytes32::rand(&mut rng).hash())
            .collect();

        // Create proof from siblings
        let proof = SparseMerkleProof::<Bytes32>::from_siblings(siblings.clone());

        // Check that siblings match
        assert_eq!(proof.0.siblings.len(), siblings.len());
        for (a, b) in proof.0.siblings.iter().zip(siblings.iter()) {
            assert_eq!(a, b);
        }
    }

    #[test]
    fn test_sparse_merkle_proof_get_root() {
        let mut rng = rand::thread_rng();
        let height = 5;

        type V = Bytes32;
        let mut tree = SparseMerkleTree::<V>::new(height);

        // Add a leaf
        let index = 3;
        let leaf = V::rand(&mut rng);
        tree.update(index, leaf);

        // Generate a proof
        let proof = tree.prove(index);

        // Calculate root using the proof
        let calculated_root = proof.get_root(&leaf, index);

        // Verify it matches the tree's root
        assert_eq!(calculated_root, tree.get_root());
    }

    #[test]
    fn test_sparse_merkle_proof_verify() {
        let mut rng = rand::thread_rng();
        let height = 5;

        type V = Bytes32;
        let mut tree = SparseMerkleTree::<V>::new(height);

        // Add a leaf
        let index = 3;
        let leaf = V::rand(&mut rng);
        tree.update(index, leaf);

        // Generate a proof
        let proof = tree.prove(index);
        let root = tree.get_root();

        // Verification should succeed with correct parameters
        assert!(proof.verify(&leaf, index, root).is_ok());

        // Verification should fail with incorrect leaf
        let wrong_leaf = V::rand(&mut rng);
        assert!(proof.verify(&wrong_leaf, index, root).is_err());

        // Verification should fail with incorrect index
        let wrong_index = (index + 1) % (1 << height);
        assert!(proof.verify(&leaf, wrong_index, root).is_err());

        // Verification should fail with incorrect root
        let wrong_root = V::rand(&mut rng).hash();
        assert!(proof.verify(&leaf, index, wrong_root).is_err());
    }

    #[test]
    fn test_sparse_merkle_proof_serialization() {
        let mut rng = rand::thread_rng();
        let height = 5;

        type V = Bytes32;
        let mut tree = SparseMerkleTree::<V>::new(height);

        // Add a leaf
        let index = 3;
        let leaf = V::rand(&mut rng);
        tree.update(index, leaf);

        // Generate a proof
        let proof = tree.prove(index);

        // Serialize the proof
        let serialized = serde_json::to_string(&proof).unwrap();

        // Deserialize the proof
        let deserialized: SparseMerkleProof<V> = serde_json::from_str(&serialized).unwrap();

        // Verify the deserialized proof works correctly
        assert!(deserialized.verify(&leaf, index, tree.get_root()).is_ok());
    }

    #[test]
    fn test_sparse_merkle_proof_target_constant() {
        let mut rng = rand::thread_rng();
        let height = 5;

        type V = Bytes32;
        type VT = Bytes32Target;
        let mut tree = SparseMerkleTree::<V>::new(height);

        // Add a leaf
        let index = 3;
        let leaf = V::rand(&mut rng);
        tree.update(index, leaf);

        // Generate a proof
        let proof = tree.prove(index);

        // Create a constant proof target
        let mut builder = CircuitBuilder::<F, D>::new(CircuitConfig::default());
        let proof_t = SparseMerkleProofTarget::<VT>::constant(&mut builder, &proof);

        // Verify the constant proof target has the correct structure
        assert_eq!(proof_t.0.siblings.len(), height);
    }

    #[test]
    fn test_sparse_merkle_proof_target_get_root() {
        let mut rng = rand::thread_rng();
        let height = 5;

        type V = Bytes32;
        type VT = Bytes32Target;
        let mut tree = SparseMerkleTree::<V>::new(height);

        // Add a leaf
        let index = 3;
        let leaf = V::rand(&mut rng);
        tree.update(index, leaf);

        // Generate a proof
        let proof = tree.prove(index);
        let expected_root = tree.get_root();

        // Create a circuit to calculate the root
        let mut builder = CircuitBuilder::<F, D>::new(CircuitConfig::default());
        let proof_t = SparseMerkleProofTarget::<VT>::new(&mut builder, height);
        let leaf_t = VT::new(&mut builder, false);
        let index_t = builder.add_virtual_target();

        // Calculate the root in the circuit
        let root_t = proof_t.get_root::<F, C, D>(&mut builder, &leaf_t, index_t);

        // Add a public output for the root
        let expected_root_t = PoseidonHashOutTarget::new(&mut builder);
        HasherFromTarget::<VT>::connect_hash(&mut builder, &root_t, &expected_root_t);

        let data = builder.build::<C>();
        let mut pw = PartialWitness::<F>::new();

        // Set the witness values
        leaf_t.set_witness(&mut pw, leaf);
        pw.set_target(index_t, F::from_canonical_u64(index));
        proof_t.set_witness(&mut pw, &proof);
        expected_root_t.set_witness(&mut pw, expected_root);

        // Prove the circuit
        data.prove(pw).unwrap();
    }

    #[test]
    fn test_sparse_merkle_tree_edge_cases() {
        let mut rng = rand::thread_rng();

        // Test with minimum height
        let min_height = 1;
        let tree_min = SparseMerkleTree::<Bytes32>::new(min_height);
        assert_eq!(tree_min.height(), min_height);

        // Test empty tree
        let empty_tree = SparseMerkleTree::<Bytes32>::new(10);
        assert_eq!(empty_tree.len(), 0);
        assert!(empty_tree.is_empty());

        // Test tree with a single leaf
        let mut single_leaf_tree = SparseMerkleTree::<Bytes32>::new(10);
        let leaf = Bytes32::rand(&mut rng);
        single_leaf_tree.update(0, leaf);
        assert_eq!(single_leaf_tree.len(), 1);
        assert_eq!(single_leaf_tree.get_leaf(0), leaf);

        // Test with boundary indices
        let height = 5;
        let mut tree = SparseMerkleTree::<Bytes32>::new(height);

        // Test with index 0
        let index_min: u64 = 0;
        let leaf_min = Bytes32::rand(&mut rng);
        tree.update(index_min, leaf_min);
        let proof_min = tree.prove(index_min);
        assert!(proof_min
            .verify(&leaf_min, index_min, tree.get_root())
            .is_ok());

        // Test with max index
        let index_max: u64 = (1 << height) - 1;
        let leaf_max = Bytes32::rand(&mut rng);
        tree.update(index_max, leaf_max);
        let proof_max = tree.prove(index_max);
        assert!(proof_max
            .verify(&leaf_max, index_max, tree.get_root())
            .is_ok());

        // Test with sparse indices (large gaps between indices)
        let mut sparse_tree = SparseMerkleTree::<Bytes32>::new(height);
        let indices = [0, 7, 15, 23, 31];
        let mut leaves = HashMap::new();

        for &idx in &indices {
            let leaf = Bytes32::rand(&mut rng);
            leaves.insert(idx, leaf);
            sparse_tree.update(idx, leaf);
        }

        for (&idx, leaf) in &leaves {
            let proof = sparse_tree.prove(idx);
            assert!(proof.verify(leaf, idx, sparse_tree.get_root()).is_ok());
        }
    }
}
