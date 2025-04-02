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

    const D: usize = 2;
    type C = PoseidonGoldilocksConfig;
    type F = <C as GenericConfig<D>>::F;

    #[test]
    fn merkle_tree_with_leaves() {
        let mut rng = rand::thread_rng();
        let height = 10;

        type V = Bytes32;
        let mut tree = IncrementalMerkleTree::<V>::new(height);

        for _ in 0..100 {
            let new_leaf = Bytes32::rand(&mut rng);
            tree.push(new_leaf);
        }

        for _ in 0..100 {
            let index = rng.gen_range(0..1 << height);
            let leaf = tree.get_leaf(index);
            let proof = tree.prove(index);
            assert_eq!(tree.get_leaf(index), leaf.clone());
            proof.verify(&leaf, index, tree.get_root()).unwrap();
        }
    }

    #[test]
    fn merkle_tree_with_leaves_circuit() {
        let mut rng = rand::thread_rng();
        let height = 10;

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
}
