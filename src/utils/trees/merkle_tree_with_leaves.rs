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

use super::merkle_tree::{MerkleProof, MerkleProofTarget, MerkleTree};
use crate::utils::{
    leafable::{Leafable, LeafableTarget},
    leafable_hasher::LeafableHasher,
    trees::merkle_tree::usize_le_bits,
};

// Merkle Tree that holds leaves as a vec. It is suitable for handling indexed
// leaves.
#[derive(Debug, Clone)]
pub struct MerkleTreeWithLeaves<V: Leafable> {
    merkle_tree: MerkleTree<V>,
    leaves: Vec<V>,
}

impl<V: Leafable> MerkleTreeWithLeaves<V> {
    pub fn new(height: usize) -> Self {
        let merkle_tree = MerkleTree::new(height, V::empty_leaf().hash());
        let leaves = vec![];

        Self {
            merkle_tree,
            leaves,
        }
    }

    pub fn height(&self) -> usize {
        self.merkle_tree.height()
    }

    // NOTICE: `None` and `V::empty_leaf()` are treated equivalently.
    pub fn get_leaf(&self, index: usize) -> V {
        match self.leaves.get(index) {
            Some(leaf) => leaf.clone(),
            None => V::empty_leaf(),
        }
    }

    pub fn get_root(&self) -> <V::LeafableHasher as LeafableHasher>::HashOut {
        self.merkle_tree.get_root()
    }

    pub fn leaves(&self) -> Vec<V> {
        self.leaves.clone()
    }

    pub fn len(&self) -> usize {
        self.leaves.len()
    }

    pub fn is_empty(&self) -> bool {
        self.leaves.is_empty()
    }

    pub fn update(&mut self, index: usize, leaf: V) {
        let index_bits = usize_le_bits(index, self.height());
        self.merkle_tree.update_leaf(index_bits, leaf.hash());
        self.leaves[index] = leaf;
    }

    pub fn push(&mut self, leaf: V) {
        let index = self.leaves.len();
        assert!(index < (1 << self.height()));
        let leaf_hash = leaf.hash();
        self.leaves.push(leaf);
        let index_bits = usize_le_bits(index, self.height());
        self.merkle_tree.update_leaf(index_bits, leaf_hash);
    }

    pub fn pop(&mut self) {
        assert!(!self.leaves.is_empty());
        self.leaves.pop();
        let index = self.leaves.len();
        let leaf = V::empty_leaf();
        let index_bits = usize_le_bits(index, self.height());
        self.merkle_tree.update_leaf(index_bits, leaf.hash());
    }

    pub fn prove(&self, index: usize) -> MerkleProofWithLeaves<V> {
        let index_bits = usize_le_bits(index, self.height());
        MerkleProofWithLeaves(self.merkle_tree.prove(index_bits))
    }
}

#[derive(Debug, Clone)]
pub struct MerkleProofWithLeaves<V: Leafable>(pub(crate) MerkleProof<V>);

impl<V: Leafable> MerkleProofWithLeaves<V> {
    pub fn dummy(height: usize) -> Self {
        Self(MerkleProof::dummy(height))
    }

    pub fn get_root(
        &self,
        leaf_data: &V,
        index: usize,
    ) -> <V::LeafableHasher as LeafableHasher>::HashOut {
        let height = self.0.height();
        let index_bits = usize_le_bits(index, height);
        self.0.get_root(leaf_data, index_bits)
    }

    pub fn verify(
        &self,
        leaf_data: &V,
        index: usize,
        merkle_root: <V::LeafableHasher as LeafableHasher>::HashOut,
    ) -> anyhow::Result<()> {
        let height = self.0.height();
        let index_bits = usize_le_bits(index, height);
        self.0.verify(leaf_data, index_bits, merkle_root)
    }
}

#[derive(Debug, Clone)]
pub struct MerkleProofWithLeavesTarget<VT: LeafableTarget>(MerkleProofTarget<VT>);

impl<VT: LeafableTarget> MerkleProofWithLeavesTarget<VT> {
    pub fn new<F: RichField + Extendable<D>, const D: usize>(
        builder: &mut CircuitBuilder<F, D>,
        height: usize,
    ) -> Self {
        Self(MerkleProofTarget::new(builder, height))
    }

    pub fn constant<F: RichField + Extendable<D>, const D: usize>(
        builder: &mut CircuitBuilder<F, D>,
        value: &MerkleProofWithLeaves<VT::Leaf>,
    ) -> Self {
        Self(MerkleProofTarget::constant(builder, &value.0))
    }

    pub fn set_witness<F: Field, W: WitnessWrite<F>>(
        &self,
        pw: &mut W,
        merkle_proof: &MerkleProofWithLeaves<VT::Leaf>,
    ) {
        self.0.set_witness(pw, &merkle_proof.0)
    }
}

impl<VT: LeafableTarget> MerkleProofWithLeavesTarget<VT> {
    pub fn get_root<
        F: RichField + Extendable<D>,
        C: GenericConfig<D, F = F> + 'static,
        const D: usize,
    >(
        &self,
        builder: &mut CircuitBuilder<F, D>,
        leaf_data: &VT,
        index: Target,
    ) -> <<VT::Leaf as Leafable>::LeafableHasher as LeafableHasher>::HashOutTarget
    where
        <C as GenericConfig<D>>::Hasher: AlgebraicHasher<F>,
    {
        let index_bits = builder.split_le(index, self.0.height());
        self.0.get_root::<F, C, D>(builder, leaf_data, index_bits)
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
        merkle_root: <<VT::Leaf as Leafable>::LeafableHasher as LeafableHasher>::HashOutTarget,
    ) where
        <C as GenericConfig<D>>::Hasher: AlgebraicHasher<F>,
    {
        let height = self.0.height();
        let index_bits = builder.split_le(index, height);
        self.0
            .verify::<F, C, D>(builder, leaf_data, index_bits, merkle_root)
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
        merkle_root: <<VT::Leaf as Leafable>::LeafableHasher as LeafableHasher>::HashOutTarget,
    ) where
        <C as GenericConfig<D>>::Hasher: AlgebraicHasher<F>,
    {
        let height = self.0.height();
        let index_bits = builder.split_le(index, height);
        self.0
            .conditional_verify::<F, C, D>(builder, condition, leaf_data, index_bits, merkle_root)
    }
}

#[cfg(test)]
mod tests {
    use crate::{
        ethereum_types::{
            bytes32::Bytes32,
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

        type V = Bytes32<u32>;
        let mut tree = MerkleTreeWithLeaves::<V>::new(height);

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

        type V = Bytes32<u32>;
        type VT = Bytes32<Target>;
        let mut tree = MerkleTreeWithLeaves::<V>::new(height);
        for _ in 0..1 << height {
            let new_leaf = V::rand(&mut rng);
            tree.push(new_leaf);
        }

        let index = rng.gen_range(0..1 << height);
        let leaf = tree.get_leaf(index);
        let proof = tree.prove(index);

        let mut builder = CircuitBuilder::<F, D>::new(CircuitConfig::default());
        let proof_t = MerkleProofWithLeavesTarget::<VT>::new(&mut builder, height);
        let leaf_t = VT::new(&mut builder, false);
        let root_t = PoseidonHashOutTarget::new(&mut builder);
        let index_t = builder.add_virtual_target();
        proof_t.verify::<F, C, D>(&mut builder, &leaf_t, index_t, root_t);

        let data = builder.build::<C>();
        let mut pw = PartialWitness::<F>::new();
        leaf_t.set_witness(&mut pw, leaf);
        root_t.set_witness(&mut pw, tree.get_root());
        pw.set_target(index_t, F::from_canonical_usize(index));
        proof_t.set_witness(&mut pw, &proof);
        data.prove(pw).unwrap();
    }
}
