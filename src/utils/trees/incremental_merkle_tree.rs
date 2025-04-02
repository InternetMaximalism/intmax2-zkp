use plonky2::{
    field::{extension::Extendable, types::Field},
    hash::hash_types::RichField,
    iop::{
        target::{BoolTarget, Target},
        witness::WitnessWrite,
    },
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

#[derive(Debug, Clone)]
pub struct IncrementalMerkleTree<V: Leafable> {
    merkle_tree: MerkleTree<V>,
    leaves: Vec<V>,
}

impl<V: Leafable> IncrementalMerkleTree<V> {
    pub fn new(height: usize) -> Self {
        let merkle_tree = MerkleTree::new(height);
        let leaves = vec![];

        Self {
            merkle_tree,
            leaves,
        }
    }

    pub fn height(&self) -> usize {
        self.merkle_tree.height()
    }

    pub fn get_leaf(&self, index: u64) -> V {
        match self.leaves.get(index as usize) {
            Some(leaf) => leaf.clone(),
            None => V::empty_leaf(),
        }
    }

    pub fn get_root(&self) -> HashOut<V> {
        self.merkle_tree.get_root()
    }

    pub fn leaves(&self) -> Vec<V> {
        self.leaves.clone()
    }

    pub fn len(&self) -> usize {
        self.leaves.len()
    }

    pub fn update(&mut self, index: u64, leaf: V) {
        self.merkle_tree.update_leaf(index, leaf.hash());
        self.leaves[index as usize] = leaf;
    }

    pub fn push(&mut self, leaf: V) {
        let index = self.leaves.len() as u64;
        assert!(index < (1u64 << (self.height() as u64)));
        let leaf_hash = leaf.hash();
        self.leaves.push(leaf);
        self.merkle_tree.update_leaf(index, leaf_hash);
    }

    pub fn prove(&self, index: u64) -> IncrementalMerkleProof<V> {
        IncrementalMerkleProof(self.merkle_tree.prove(index))
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct IncrementalMerkleProof<V: Leafable>(pub MerkleProof<V>);

impl<V: Leafable> IncrementalMerkleProof<V> {
    pub fn dummy(height: usize) -> Self {
        Self(MerkleProof::dummy(height))
    }

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

#[derive(Debug, Clone)]
pub struct IncrementalMerkleProofTarget<VT: LeafableTarget>(pub(crate) MerkleProofTarget<VT>);

impl<VT: LeafableTarget> IncrementalMerkleProofTarget<VT> {
    pub fn new<F: RichField + Extendable<D>, const D: usize>(
        builder: &mut CircuitBuilder<F, D>,
        height: usize,
    ) -> Self {
        Self(MerkleProofTarget::new(builder, height))
    }

    pub fn constant<F: RichField + Extendable<D>, const D: usize>(
        builder: &mut CircuitBuilder<F, D>,
        value: &IncrementalMerkleProof<VT::Leaf>,
    ) -> Self {
        Self(MerkleProofTarget::constant(builder, &value.0))
    }

    pub fn set_witness<F: Field, W: WitnessWrite<F>>(
        &self,
        pw: &mut W,
        merkle_proof: &IncrementalMerkleProof<VT::Leaf>,
    ) {
        self.0.set_witness(pw, &merkle_proof.0)
    }
}

impl<VT: LeafableTarget> IncrementalMerkleProofTarget<VT> {
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

    pub fn conditional_verify<
        F: RichField + Extendable<D>,
        C: GenericConfig<D, F = F> + 'static,
        const D: usize,
    >(
        &self,
        builder: &mut CircuitBuilder<F, D>,
        condition: BoolTarget,
        leaf_data: &VT,
        index: Target,
        merkle_root: HashOutTarget<VT>,
    ) where
        <C as GenericConfig<D>>::Hasher: AlgebraicHasher<F>,
    {
        self.0
            .conditional_verify::<F, C, D>(builder, condition, leaf_data, index, merkle_root)
    }
}

// Serialization and Deserialization
#[derive(Debug, Clone, Serialize, Deserialize)]
struct IncrementalMerkleTreePacked<V: Leafable> {
    height: usize,
    leaves: Vec<V>,
}

impl<V: Leafable> IncrementalMerkleTree<V> {
    fn pack(&self) -> IncrementalMerkleTreePacked<V> {
        IncrementalMerkleTreePacked {
            height: self.height(),
            leaves: self.leaves(),
        }
    }

    fn unpack(packed: IncrementalMerkleTreePacked<V>) -> Self {
        let mut tree = IncrementalMerkleTree::new(packed.height);
        for leaf in packed.leaves {
            tree.push(leaf);
        }
        tree
    }
}

impl<V: Leafable + Serialize> Serialize for IncrementalMerkleTree<V> {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        self.pack().serialize(serializer)
    }
}

impl<'de, V: Leafable + Deserialize<'de>> Deserialize<'de> for IncrementalMerkleTree<V> {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let packed = IncrementalMerkleTreePacked::deserialize(deserializer)?;
        Ok(Self::unpack(packed))
    }
}

#[cfg(test)]
mod tests {
    use crate::{
        ethereum_types::{
            bytes32::{Bytes32, Bytes32Target},
            u32limb_trait::{U32LimbTargetTrait, U32LimbTrait as _},
        },
        utils::poseidon_hash_out::PoseidonHashOutTarget,
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
    fn test_incremental_merkle_tree_with_leaves() {
        let mut rng = rand::thread_rng();
        let height = 5;

        type V = Bytes32;
        let mut tree = IncrementalMerkleTree::<V>::new(height);

        for _ in 0..10 {
            let new_leaf = Bytes32::rand(&mut rng);
            tree.push(new_leaf);
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
    fn test_incremental_merkle_tree_with_leaves_circuit() {
        let mut rng = rand::thread_rng();
        let height = 5;

        type V = Bytes32;
        type VT = Bytes32Target;
        let mut tree = IncrementalMerkleTree::<V>::new(height);
        for _ in 0..1 << height {
            let new_leaf = V::rand(&mut rng);
            tree.push(new_leaf);
        }

        let index = rng.gen_range(0..1 << height);
        let leaf = tree.get_leaf(index);
        let proof = tree.prove(index);

        let mut builder = CircuitBuilder::<F, D>::new(CircuitConfig::default());
        let proof_t = IncrementalMerkleProofTarget::<VT>::new(&mut builder, height);
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
    fn test_incremental_merkle_tree_new() {
        // Test with different heights
        let heights = [1, 5, 10, 20];
        for height in heights {
            let tree = IncrementalMerkleTree::<Bytes32>::new(height);
            assert_eq!(tree.height(), height);
            assert_eq!(tree.leaves().len(), 0);
            assert_eq!(tree.len(), 0);
        }
    }

    #[test]
    fn test_incremental_merkle_tree_update() {
        let mut rng = rand::thread_rng();
        let height = 5;

        type V = Bytes32;
        let mut tree = IncrementalMerkleTree::<V>::new(height);

        // Add some leaves first
        let mut leaves = Vec::new();
        for _ in 0..10 {
            let new_leaf = V::rand(&mut rng);
            leaves.push(new_leaf.clone());
            tree.push(new_leaf);
        }

        // Update some leaves
        for i in 0..5 {
            let new_leaf = V::rand(&mut rng);
            let old_root = tree.get_root();
            tree.update(i, new_leaf.clone());
            
            // Verify the leaf was updated
            assert_eq!(tree.get_leaf(i), new_leaf);
            
            // Verify the root changed
            assert_ne!(tree.get_root(), old_root);
            
            // Verify the proof works for the updated leaf
            let proof = tree.prove(i);
            proof.verify(&new_leaf, i, tree.get_root()).unwrap();
        }
    }

    #[test]
    fn test_incremental_merkle_tree_len_and_leaves() {
        let mut rng = rand::thread_rng();
        let height = 5;

        type V = Bytes32;
        let mut tree = IncrementalMerkleTree::<V>::new(height);
        assert_eq!(tree.len(), 0);
        assert_eq!(tree.leaves().len(), 0);

        // Add some leaves
        let mut leaves = Vec::new();
        for i in 0..10 {
            let new_leaf = V::rand(&mut rng);
            leaves.push(new_leaf.clone());
            tree.push(new_leaf);
            
            // Verify length increases
            assert_eq!(tree.len(), i + 1);
            
            // Verify leaves() returns all leaves
            assert_eq!(tree.leaves().len(), i + 1);
            for j in 0..=i {
                assert_eq!(tree.leaves()[j], leaves[j]);
            }
        }
    }

    #[test]
    fn test_incremental_merkle_tree_get_root() {
        let mut rng = rand::thread_rng();
        let height = 5;

        type V = Bytes32;
        let mut tree = IncrementalMerkleTree::<V>::new(height);
        
        // Empty tree root
        let empty_root = tree.get_root();
        
        // Add a leaf and check that root changes
        let leaf = V::rand(&mut rng);
        tree.push(leaf.clone());
        let root_with_one_leaf = tree.get_root();
        assert_ne!(empty_root, root_with_one_leaf);
        
        // Add another leaf and check that root changes again
        let leaf2 = V::rand(&mut rng);
        tree.push(leaf2.clone());
        let root_with_two_leaves = tree.get_root();
        assert_ne!(root_with_one_leaf, root_with_two_leaves);
    }

    #[test]
    fn test_incremental_merkle_tree_get_leaf() {
        let mut rng = rand::thread_rng();
        let height = 5;

        type V = Bytes32;
        let mut tree = IncrementalMerkleTree::<V>::new(height);
        
        // Empty tree should return empty leaf for any index
        for i in 0..10 {
            assert_eq!(tree.get_leaf(i), V::empty_leaf());
        }
        
        // Add some leaves
        let mut leaves = Vec::new();
        for _ in 0..5 {
            let new_leaf = V::rand(&mut rng);
            leaves.push(new_leaf.clone());
            tree.push(new_leaf);
        }
        
        // Check existing leaves
        for i in 0..5 {
            assert_eq!(tree.get_leaf(i as u64), leaves[i]);
        }
        
        // Check non-existent leaves
        for i in 5..10 {
            assert_eq!(tree.get_leaf(i as u64), V::empty_leaf());
        }
    }

    #[test]
    fn test_incremental_merkle_proof_dummy() {
        let height = 10;
        
        // Create a dummy proof
        let dummy_proof = IncrementalMerkleProof::<Bytes32>::dummy(height);
        
        // Check that it has the right height
        assert_eq!(dummy_proof.0.siblings.len(), height);
        
        // Check that all siblings are default values
        for sibling in &dummy_proof.0.siblings {
            assert_eq!(*sibling, HashOut::<Bytes32>::default());
        }
    }

    #[test]
    fn test_incremental_merkle_proof_from_siblings() {
        let mut rng = rand::thread_rng();
        let height = 5;
        
        // Create random siblings
        let siblings: Vec<HashOut<Bytes32>> = (0..height)
            .map(|_| Bytes32::rand(&mut rng).hash())
            .collect();
        
        // Create proof from siblings
        let proof = IncrementalMerkleProof::<Bytes32>::from_siblings(siblings.clone());
        
        // Check that siblings match
        assert_eq!(proof.0.siblings.len(), siblings.len());
        for (a, b) in proof.0.siblings.iter().zip(siblings.iter()) {
            assert_eq!(a, b);
        }
    }

    #[test]
    fn test_incremental_merkle_tree_edge_cases() {
        let mut rng = rand::thread_rng();
        
        // Test with minimum height
        let min_height = 1;
        let tree_min = IncrementalMerkleTree::<Bytes32>::new(min_height);
        assert_eq!(tree_min.height(), min_height);
        
        // Test empty tree
        let empty_tree = IncrementalMerkleTree::<Bytes32>::new(10);
        assert_eq!(empty_tree.len(), 0);
        assert_eq!(empty_tree.leaves().len(), 0);
        
        // Test tree with a single leaf
        let mut single_leaf_tree = IncrementalMerkleTree::<Bytes32>::new(10);
        let leaf = Bytes32::rand(&mut rng);
        single_leaf_tree.push(leaf.clone());
        assert_eq!(single_leaf_tree.len(), 1);
        assert_eq!(single_leaf_tree.get_leaf(0), leaf);
        
        // Test with boundary indices
        let height = 5;
        let mut tree = IncrementalMerkleTree::<Bytes32>::new(height);
        
        // Fill the tree to capacity
        for _ in 0..(1 << height) {
            let new_leaf = Bytes32::rand(&mut rng);
            tree.push(new_leaf);
        }
        
        // Verify the tree is full
        assert_eq!(tree.len(), 1 << height);
        
        // Test with index 0
        let index_min: u64 = 0;
        let leaf_min = Bytes32::rand(&mut rng);
        tree.update(index_min, leaf_min.clone());
        let proof_min = tree.prove(index_min);
        proof_min.verify(&leaf_min, index_min, tree.get_root()).unwrap();
        
        // Test with max index
        let index_max: u64 = (1 << height) - 1;
        let leaf_max = Bytes32::rand(&mut rng);
        tree.update(index_max, leaf_max.clone());
        let proof_max = tree.prove(index_max);
        proof_max.verify(&leaf_max, index_max, tree.get_root()).unwrap();
    }

    #[test]
    fn test_incremental_merkle_tree_serialization() {
        let mut rng = rand::thread_rng();
        let height = 5;
        
        type V = Bytes32;
        let mut tree = IncrementalMerkleTree::<V>::new(height);
        
        // Add some leaves
        for _ in 0..10 {
            let new_leaf = V::rand(&mut rng);
            tree.push(new_leaf);
        }
        
        // Serialize the tree
        let serialized = serde_json::to_string(&tree).unwrap();
        
        // Deserialize the tree
        let deserialized: IncrementalMerkleTree<V> = serde_json::from_str(&serialized).unwrap();
        
        // Verify the deserialized tree matches the original
        assert_eq!(deserialized.height(), tree.height());
        assert_eq!(deserialized.len(), tree.len());
        assert_eq!(deserialized.get_root(), tree.get_root());
        
        // Check all leaves match
        for i in 0..tree.len() {
            assert_eq!(deserialized.get_leaf(i as u64), tree.get_leaf(i as u64));
        }
        
        // Verify proofs still work after serialization/deserialization
        for i in 0..tree.len() {
            let index = i as u64;
            let leaf = tree.get_leaf(index);
            let proof = deserialized.prove(index);
            proof.verify(&leaf, index, deserialized.get_root()).unwrap();
        }
    }

    #[test]
    fn test_incremental_merkle_proof_serialization() {
        let mut rng = rand::thread_rng();
        let height = 5;
        
        type V = Bytes32;
        let mut tree = IncrementalMerkleTree::<V>::new(height);
        
        // Add some leaves
        for _ in 0..10 {
            let new_leaf = V::rand(&mut rng);
            tree.push(new_leaf);
        }
        
        // Generate a proof
        let index = 5;
        let leaf = tree.get_leaf(index);
        let proof = tree.prove(index);
        
        // Serialize the proof
        let serialized = serde_json::to_string(&proof).unwrap();
        
        // Deserialize the proof
        let deserialized: IncrementalMerkleProof<V> = serde_json::from_str(&serialized).unwrap();
        
        // Verify the deserialized proof works correctly
        deserialized.verify(&leaf, index, tree.get_root()).unwrap();
    }

    #[test]
    fn test_incremental_merkle_proof_verification_failure() {
        let mut rng = rand::thread_rng();
        let height = 5;
        
        type V = Bytes32;
        let mut tree = IncrementalMerkleTree::<V>::new(height);
        
        // Add some leaves
        for _ in 0..10 {
            let new_leaf = V::rand(&mut rng);
            tree.push(new_leaf);
        }
        
        // Generate a proof
        let index = 5;
        let leaf = tree.get_leaf(index);
        let proof = tree.prove(index);
        
        // Verification should succeed with correct parameters
        assert!(proof.verify(&leaf, index, tree.get_root()).is_ok());
        
        // Verification should fail with incorrect leaf
        let wrong_leaf = V::rand(&mut rng);
        assert!(proof.verify(&wrong_leaf, index, tree.get_root()).is_err());
        
        // Verification should fail with incorrect index
        let wrong_index = (index + 1) % 10;
        assert!(proof.verify(&leaf, wrong_index, tree.get_root()).is_err());
        
        // Verification should fail with incorrect root
        let wrong_root = V::rand(&mut rng).hash();
        assert!(proof.verify(&leaf, index, wrong_root).is_err());
    }

    #[test]
    fn test_incremental_merkle_proof_target_conditional_verify() {
        let mut rng = rand::thread_rng();
        let height = 5;

        type V = Bytes32;
        type VT = Bytes32Target;
        let mut tree = IncrementalMerkleTree::<V>::new(height);
        
        // Add some leaves
        for _ in 0..10 {
            let new_leaf = V::rand(&mut rng);
            tree.push(new_leaf);
        }

        let index = 5;
        let leaf = tree.get_leaf(index);
        let proof = tree.prove(index);

        // Test conditional_verify with condition=true
        let mut builder = CircuitBuilder::<F, D>::new(CircuitConfig::default());
        let proof_t = IncrementalMerkleProofTarget::<VT>::new(&mut builder, height);
        let leaf_t = VT::new(&mut builder, false);
        let root_t = PoseidonHashOutTarget::new(&mut builder);
        let index_t = builder.add_virtual_target();
        let condition_true = builder.constant_bool(true);

        proof_t.conditional_verify::<F, C, D>(
            &mut builder,
            condition_true,
            &leaf_t,
            index_t,
            root_t,
        );

        let data = builder.build::<C>();
        let mut pw = PartialWitness::<F>::new();
        leaf_t.set_witness(&mut pw, leaf);
        root_t.set_witness(&mut pw, tree.get_root());
        pw.set_target(index_t, F::from_canonical_u64(index));
        proof_t.set_witness(&mut pw, &proof);

        data.prove(pw).unwrap();

        // Test conditional_verify with condition=false (should not verify)
        let mut builder = CircuitBuilder::<F, D>::new(CircuitConfig::default());
        let proof_t = IncrementalMerkleProofTarget::<VT>::new(&mut builder, height);
        let leaf_t = VT::new(&mut builder, false);
        let root_t = PoseidonHashOutTarget::new(&mut builder);
        let index_t = builder.add_virtual_target();
        let condition_false = builder.constant_bool(false);

        proof_t.conditional_verify::<F, C, D>(
            &mut builder,
            condition_false,
            &leaf_t,
            index_t,
            root_t,
        );

        let data = builder.build::<C>();
        let mut pw = PartialWitness::<F>::new();
        leaf_t.set_witness(&mut pw, leaf);

        // With condition=false, we can provide an incorrect root and it should still work
        let wrong_root = V::rand(&mut rng).hash();
        root_t.set_witness(&mut pw, wrong_root);

        pw.set_target(index_t, F::from_canonical_u64(index));
        proof_t.set_witness(&mut pw, &proof);

        data.prove(pw).unwrap();
    }
}
