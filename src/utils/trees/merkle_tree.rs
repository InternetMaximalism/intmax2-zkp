use std::collections::HashMap;

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

use crate::utils::{
    leafable::{Leafable, LeafableTarget},
    leafable_hasher::LeafableHasher,
};

use super::{bit_path::BitPath, error::{MerkleProofError, Result, TreesError}};

pub type Hasher<V> = <V as Leafable>::LeafableHasher;
pub type HashOut<V> = <Hasher<V> as LeafableHasher>::HashOut;
pub type HasherFromTarget<VT> = <<VT as LeafableTarget>::Leaf as Leafable>::LeafableHasher;
pub type HashOutTarget<VT> = <HasherFromTarget<VT> as LeafableHasher>::HashOutTarget;

/// A Merkle tree that only keeps non-zero nodes. It has zero_hashes that hold the hash of each
/// level of empty leaves.
#[derive(Clone, Debug)]
pub(crate) struct MerkleTree<V: Leafable> {
    height: usize,
    node_hashes: HashMap<BitPath, HashOut<V>>,
    zero_hashes: Vec<HashOut<V>>,
}

impl<V: Leafable> MerkleTree<V> {
    pub(crate) fn new(height: usize) -> Self {
        // zero_hashes = reverse([H(zero_leaf), H(H(zero_leaf), H(zero_leaf)), ...])
        let mut zero_hashes = vec![];
        let mut h = V::empty_leaf().hash();
        zero_hashes.push(h);
        for _ in 0..height {
            h = Hasher::<V>::two_to_one(h, h);
            zero_hashes.push(h);
        }
        zero_hashes.reverse();
        Self {
            height,
            node_hashes: HashMap::new(),
            zero_hashes,
        }
    }

    pub(crate) fn height(&self) -> usize {
        self.height
    }

    fn get_node_hash(&self, path: BitPath) -> HashOut<V> {
        match self.node_hashes.get(&path) {
            Some(h) => *h,
            None => self.zero_hashes[path.len() as usize],
        }
    }

    pub(crate) fn get_root(&self) -> HashOut<V> {
        self.get_node_hash(BitPath::default())
    }

    pub(crate) fn update_leaf(&mut self, index: u64, leaf_hash: HashOut<V>) {
        let mut path = BitPath::new(self.height as u32, index);
        path.reverse();
        let mut h = leaf_hash;
        self.node_hashes.insert(path, h);
        while !path.is_empty() {
            let sibling = self.get_node_hash(path.sibling());
            h = if path.pop().unwrap() {
                Hasher::<V>::two_to_one(sibling, h)
            } else {
                Hasher::<V>::two_to_one(h, sibling)
            };
            self.node_hashes.insert(path, h);
        }
    }

    pub(crate) fn prove(&self, index: u64) -> MerkleProof<V> {
        let mut path = BitPath::new(self.height as u32, index);
        path.reverse();
        let mut siblings = vec![];
        while !path.is_empty() {
            siblings.push(self.get_node_hash(path.sibling()));
            path.pop();
        }
        MerkleProof { siblings }
    }
}

#[derive(Clone, Debug)]
pub struct MerkleProof<V: Leafable> {
    pub siblings: Vec<HashOut<V>>,
}

impl<V: Leafable> Serialize for MerkleProof<V>
where
    HashOut<V>: Serialize,
{
    fn serialize<S>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        self.siblings.serialize(serializer)
    }
}

impl<'de, V: Leafable> Deserialize<'de> for MerkleProof<V>
where
    HashOut<V>: Deserialize<'de>,
{
    fn deserialize<D>(deserializer: D) -> std::result::Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let siblings = Vec::<HashOut<V>>::deserialize(deserializer)?;
        Ok(MerkleProof { siblings })
    }
}

impl<V: Leafable> MerkleProof<V> {
    pub fn dummy(height: usize) -> Self {
        Self {
            siblings: vec![HashOut::<V>::default(); height],
        }
    }

    pub fn height(&self) -> usize {
        self.siblings.len()
    }

    pub fn get_root(&self, leaf_data: &V, index: u64) -> HashOut<V> {
        let path = BitPath::new(self.height() as u32, index);
        let mut state = leaf_data.hash();
        for (&bit, sibling) in path.to_bits_le().iter().zip(self.siblings.iter()) {
            state = if bit {
                Hasher::<V>::two_to_one(*sibling, state)
            } else {
                Hasher::<V>::two_to_one(state, *sibling)
            }
        }
        state
    }

    pub fn verify(
        &self,
        leaf_data: &V,
        index: u64,
        merkle_root: HashOut<V>,
    ) -> Result<()> {
        let proof_root = self.get_root(leaf_data, index);
        if proof_root != merkle_root {
            return Err(TreesError::MerkleProof(MerkleProofError::VerificationFailed(format!(
                "Merkle proof verification failed: root from proof: {:?}, expected root: {:?}",
                proof_root, merkle_root
            ))));
        }
        Ok(())
    }
}

#[derive(Clone, Debug)]
pub(crate) struct MerkleProofTarget<VT: LeafableTarget> {
    pub siblings: Vec<HashOutTarget<VT>>,
}

impl<VT: LeafableTarget> MerkleProofTarget<VT> {
    pub(crate) fn new<F: RichField + Extendable<D>, const D: usize>(
        builder: &mut CircuitBuilder<F, D>,
        height: usize,
    ) -> Self {
        let siblings = (0..height)
            .map(|_| {
                <<VT::Leaf as Leafable>::LeafableHasher as LeafableHasher>::hash_out_target(builder)
            })
            .collect::<Vec<_>>();
        Self { siblings }
    }

    pub(crate) fn constant<F: RichField + Extendable<D>, const D: usize>(
        builder: &mut CircuitBuilder<F, D>,
        input: &MerkleProof<VT::Leaf>,
    ) -> Self {
        Self {
            siblings: input
                .siblings
                .iter()
                .map(|sibling| <<VT::Leaf as Leafable>::LeafableHasher as LeafableHasher>::constant_hash_out_target(builder, *sibling))
                .collect(),
        }
    }

    pub(crate) fn set_witness<F: Field, W: WitnessWrite<F>>(
        &self,
        pw: &mut W,
        merkle_proof: &MerkleProof<VT::Leaf>,
    ) {
        assert_eq!(self.siblings.len(), merkle_proof.siblings.len());
        for (sibling_t, sibling) in self.siblings.iter().zip(merkle_proof.siblings.iter()) {
            <<VT::Leaf as Leafable>::LeafableHasher as LeafableHasher>::set_hash_out_target(
                sibling_t, pw, *sibling,
            );
        }
    }
}

impl<VT: LeafableTarget> MerkleProofTarget<VT> {
    pub(crate) fn get_root<
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
        let index_bits = builder.split_le(index, self.height());
        let mut state = leaf_data.hash::<F, C, D>(builder);
        for (bit, sibling) in index_bits.iter().zip(&self.siblings) {
            state = HasherFromTarget::<VT>::two_to_one_swapped::<F, C, D>(
                builder, &state, sibling, *bit,
            );
        }
        state
    }

    pub(crate) fn verify<
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
        let state = self.get_root::<F, C, D>(builder, leaf_data, index);
        HasherFromTarget::<VT>::connect_hash(builder, &state, &merkle_root);
    }

    pub(crate) fn conditional_verify<
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
        let state = self.get_root::<F, C, D>(builder, leaf_data, index);
        HasherFromTarget::<VT>::conditional_assert_eq_hash(
            builder,
            condition,
            &state,
            &merkle_root,
        );
    }

    pub(crate) fn height(&self) -> usize {
        self.siblings.len()
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
    fn test_merkle_tree_new() {
        // Test with different heights
        let heights = [1, 5, 10, 20];
        for height in heights {
            let tree = MerkleTree::<Bytes32>::new(height);
            assert_eq!(tree.height(), height);
            assert_eq!(tree.zero_hashes.len(), height + 1);
            assert!(tree.node_hashes.is_empty());
        }
    }

    #[test]
    fn test_merkle_tree_get_root() {
        let height = 10;
        let tree = MerkleTree::<Bytes32>::new(height);

        // Root of empty tree should match the top zero hash
        assert_eq!(tree.get_root(), tree.zero_hashes[0]);

        // After updates, root should change
        let mut tree = MerkleTree::<Bytes32>::new(height);
        let mut rng = rand::thread_rng();
        let index: u64 = rng.gen_range(0..1 << height);
        let new_leaf = Bytes32::rand(&mut rng);
        let leaf_hash = new_leaf.hash();

        let empty_root = tree.get_root();
        tree.update_leaf(index, leaf_hash);
        let updated_root = tree.get_root();

        assert_ne!(empty_root, updated_root);
    }

    #[test]
    fn test_merkle_tree_update_prove_verify() {
        let mut rng = rand::thread_rng();
        let height = 10;
        let mut tree = MerkleTree::<Bytes32>::new(height);

        for _ in 0..100 {
            let index: u64 = rng.gen_range(0..1 << height);
            let new_leaf = Bytes32::rand(&mut rng);
            let leaf_hash = new_leaf.hash();
            tree.update_leaf(index, leaf_hash);
            let proof = tree.prove(index);
            proof.verify(&new_leaf, index, tree.get_root()).unwrap();
        }
    }

    #[test]
    fn test_merkle_tree_proof_methods() {
        let mut rng = rand::thread_rng();
        let height = 10;

        // Test dummy proof
        let dummy_proof = MerkleProof::<Bytes32>::dummy(height);
        assert_eq!(dummy_proof.height(), height);
        assert_eq!(dummy_proof.siblings.len(), height);

        // Test get_root and verify
        let mut tree = MerkleTree::<Bytes32>::new(height);
        let index: u64 = rng.gen_range(0..1 << height);
        let leaf = Bytes32::rand(&mut rng);
        let leaf_hash = leaf.hash();
        tree.update_leaf(index, leaf_hash);

        let proof = tree.prove(index);
        let calculated_root = proof.get_root(&leaf, index);
        assert_eq!(calculated_root, tree.get_root());

        // Verify should succeed with correct root
        assert!(proof.verify(&leaf, index, tree.get_root()).is_ok());

        // Verify should fail with incorrect root
        let wrong_root = Bytes32::rand(&mut rng).hash();
        assert!(proof.verify(&leaf, index, wrong_root).is_err());

        // Verify should fail with incorrect leaf
        let wrong_leaf = Bytes32::rand(&mut rng);
        assert!(proof.verify(&wrong_leaf, index, tree.get_root()).is_err());

        // Verify should fail with incorrect index
        let wrong_index = (index + 1) % (1 << height);
        assert!(proof.verify(&leaf, wrong_index, tree.get_root()).is_err());
    }

    #[test]
    fn test_merkle_tree_proof_target_methods() {
        type V = Bytes32;
        type VT = Bytes32Target;

        let mut rng = rand::thread_rng();
        let height = 10;

        // Create a tree and update a leaf
        let mut tree = MerkleTree::<V>::new(height);
        let index = rng.gen_range(0..1 << height);
        let leaf = V::rand(&mut rng);
        let leaf_hash = leaf.hash();
        tree.update_leaf(index, leaf_hash);
        let proof = tree.prove(index);

        // Test new
        let mut builder = CircuitBuilder::<F, D>::new(CircuitConfig::default());
        let proof_t = MerkleProofTarget::<VT>::new(&mut builder, height);
        assert_eq!(proof_t.siblings.len(), height);

        // Test constant
        let mut builder = CircuitBuilder::<F, D>::new(CircuitConfig::default());
        let proof_t = MerkleProofTarget::<VT>::constant(&mut builder, &proof);
        assert_eq!(proof_t.siblings.len(), height);

        // Test get_root
        let mut builder = CircuitBuilder::<F, D>::new(CircuitConfig::default());
        let proof_t = MerkleProofTarget::<VT>::new(&mut builder, height);
        let leaf_t = VT::new(&mut builder, false);
        let index_t = builder.add_virtual_target();
        let _root_t = proof_t.get_root::<F, C, D>(&mut builder, &leaf_t, index_t);

        // Test verify
        let mut builder = CircuitBuilder::<F, D>::new(CircuitConfig::default());
        let proof_t = MerkleProofTarget::<VT>::new(&mut builder, height);
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
    fn test_merkle_tree_conditional_verify() {
        type V = Bytes32;
        type VT = Bytes32Target;

        let mut rng = rand::thread_rng();
        let height = 10;

        // Create a tree and update a leaf
        let mut tree = MerkleTree::<V>::new(height);
        let index = rng.gen_range(0..1 << height);
        let leaf = V::rand(&mut rng);
        let leaf_hash = leaf.hash();
        tree.update_leaf(index, leaf_hash);
        let proof = tree.prove(index);

        // Test conditional_verify with condition=true
        let mut builder = CircuitBuilder::<F, D>::new(CircuitConfig::default());
        let proof_t = MerkleProofTarget::<VT>::new(&mut builder, height);
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
        let proof_t = MerkleProofTarget::<VT>::new(&mut builder, height);
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

    #[test]
    fn test_merkle_tree_edge_cases() {
        // Test with minimum height
        let min_height = 1;
        let tree_min = MerkleTree::<Bytes32>::new(min_height);
        assert_eq!(tree_min.height(), min_height);

        // Test with boundary indices
        let mut rng = rand::thread_rng();
        let height = 10;
        let mut tree = MerkleTree::<Bytes32>::new(height);

        // Test with index 0
        let index_min: u64 = 0;
        let leaf_min = Bytes32::rand(&mut rng);
        tree.update_leaf(index_min, leaf_min.hash());
        let proof_min = tree.prove(index_min);
        proof_min
            .verify(&leaf_min, index_min, tree.get_root())
            .unwrap();

        // Test with max index
        let index_max: u64 = (1 << height) - 1;
        let leaf_max = Bytes32::rand(&mut rng);
        tree.update_leaf(index_max, leaf_max.hash());
        let proof_max = tree.prove(index_max);
        proof_max
            .verify(&leaf_max, index_max, tree.get_root())
            .unwrap();
    }

    #[test]
    fn test_merkle_tree_proof_serialization() {
        type V = Bytes32;

        let mut rng = rand::thread_rng();
        let height = 10;
        let mut tree = MerkleTree::<V>::new(height);

        // Create a tree with a few leaves
        let index = rng.gen_range(0..1 << height);
        let leaf = V::rand(&mut rng);
        let leaf_hash = leaf.hash();
        tree.update_leaf(index, leaf_hash);

        // Generate a proof
        let proof = tree.prove(index);
        let root = tree.get_root();

        // Serialize the proof to JSON
        let serialized = serde_json::to_string(&proof).unwrap();

        // Deserialize the proof
        let deserialized: MerkleProof<V> = serde_json::from_str(&serialized).unwrap();

        // Verify the deserialized proof works correctly
        assert_eq!(proof.siblings.len(), deserialized.siblings.len());
        for (original, deserialized) in proof.siblings.iter().zip(deserialized.siblings.iter()) {
            assert_eq!(original, deserialized);
        }

        // Verify the proof still works after serialization/deserialization
        let calculated_root = deserialized.get_root(&leaf, index);
        assert_eq!(calculated_root, root);

        // Verify should succeed with the correct root
        assert!(deserialized.verify(&leaf, index, root).is_ok());
    }

    #[test]
    fn test_merkle_tree_proof_target() {
        type V = Bytes32;
        type VT = Bytes32Target;

        let mut rng = rand::thread_rng();
        let height = 10;

        let mut tree = MerkleTree::<V>::new(height);

        let index = rng.gen_range(0..1 << height);
        let leaf = Bytes32::rand(&mut rng);
        let leaf_hash = leaf.hash();
        tree.update_leaf(index, leaf_hash);
        let proof = tree.prove(index);

        let mut builder = CircuitBuilder::<F, D>::new(CircuitConfig::default());
        let proof_t = MerkleProofTarget::<VT>::new(&mut builder, height);
        let leaf_t = Bytes32Target::new(&mut builder, false);
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
}
