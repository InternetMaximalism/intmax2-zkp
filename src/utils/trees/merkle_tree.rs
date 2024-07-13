use std::collections::HashMap;

use plonky2::{
    field::{extension::Extendable, types::Field},
    hash::hash_types::RichField,
    iop::{target::BoolTarget, witness::WitnessWrite},
    plonk::{
        circuit_builder::CircuitBuilder,
        config::{AlgebraicHasher, GenericConfig},
    },
};

use crate::utils::{
    leafable::{Leafable, LeafableTarget},
    leafable_hasher::LeafableHasher,
};

// `MekleTree`` is a structure of Merkle Tree used for `MerkleTreeWithLeaves`
// and `SparseMerkleTreeWithLeaves`. It only holds non-zero nodes.
// All nodes are specified by path: Vec<bool>. The path is big endian.
// Note that this is different from the original plonky2 Merkle Tree which
// uses little endian path.
#[derive(Clone, Debug)]
pub(crate) struct MerkleTree<V: Leafable> {
    height: usize,
    node_hashes: HashMap<Vec<bool>, <V::LeafableHasher as LeafableHasher>::HashOut>,
    zero_hashes: Vec<<V::LeafableHasher as LeafableHasher>::HashOut>,
}

impl<V: Leafable> MerkleTree<V> {
    pub(crate) fn new(
        height: usize,
        empty_leaf_hash: <V::LeafableHasher as LeafableHasher>::HashOut,
    ) -> Self {
        // zero_hashes = reverse([H(zero_leaf), H(H(zero_leaf), H(zero_leaf)), ...])
        let mut zero_hashes = vec![];
        let mut h = empty_leaf_hash;
        zero_hashes.push(h.clone());
        for _ in 0..height {
            h = <V::LeafableHasher as LeafableHasher>::two_to_one(h, h);
            zero_hashes.push(h.clone());
        }
        zero_hashes.reverse();

        let node_hashes: HashMap<Vec<bool>, <V::LeafableHasher as LeafableHasher>::HashOut> =
            HashMap::new();

        Self {
            height,
            node_hashes,
            zero_hashes,
        }
    }

    pub(crate) fn height(&self) -> usize {
        self.height
    }

    pub(crate) fn get_node_hash(
        &self,
        path: &Vec<bool>,
    ) -> <V::LeafableHasher as LeafableHasher>::HashOut {
        assert!(path.len() <= self.height);
        match self.node_hashes.get(path) {
            Some(h) => h.clone(),
            None => self.zero_hashes[path.len()].clone(),
        }
    }

    pub(crate) fn get_root(&self) -> <V::LeafableHasher as LeafableHasher>::HashOut {
        self.get_node_hash(&vec![])
    }

    fn get_sibling_hash(&self, path: &Vec<bool>) -> <V::LeafableHasher as LeafableHasher>::HashOut {
        assert!(!path.is_empty());
        let mut path = path.clone();
        let last = path.len() - 1;
        path[last] = !path[last];
        self.get_node_hash(&path)
    }

    // index_bits is little endian
    pub(crate) fn update_leaf(
        &mut self,
        index_bits: Vec<bool>,
        leaf_hash: <V::LeafableHasher as LeafableHasher>::HashOut,
    ) {
        assert_eq!(index_bits.len(), self.height);
        let mut path = index_bits;
        path.reverse(); // path is big endian

        let mut h = leaf_hash;
        self.node_hashes.insert(path.clone(), h.clone());

        while !path.is_empty() {
            let sibling = self.get_sibling_hash(&path);
            h = if path.pop().unwrap() {
                <V::LeafableHasher as LeafableHasher>::two_to_one(sibling, h)
            } else {
                <V::LeafableHasher as LeafableHasher>::two_to_one(h, sibling)
            };
            self.node_hashes.insert(path.clone(), h.clone());
        }
    }

    pub(crate) fn prove(&self, index_bits: Vec<bool>) -> MerkleProof<V> {
        assert_eq!(index_bits.len(), self.height);
        let mut path = index_bits;
        path.reverse(); // path is big endian

        let mut siblings = vec![];
        while !path.is_empty() {
            siblings.push(self.get_sibling_hash(&path));
            path.pop();
        }
        MerkleProof { siblings }
    }
}

#[derive(Clone, Debug)]
pub(crate) struct MerkleProof<V: Leafable> {
    pub(crate) siblings: Vec<<V::LeafableHasher as LeafableHasher>::HashOut>,
}

impl<V: Leafable> MerkleProof<V> {
    pub fn dummy(height: usize) -> Self {
        Self {
            siblings: vec![<V::LeafableHasher as LeafableHasher>::HashOut::default(); height],
        }
    }

    pub fn height(&self) -> usize {
        self.siblings.len()
    }

    pub fn get_root(
        &self,
        leaf_data: &V,
        index_bits: Vec<bool>,
    ) -> <V::LeafableHasher as LeafableHasher>::HashOut {
        let mut state = leaf_data.hash();
        for (&bit, sibling) in index_bits.iter().zip(self.siblings.iter()) {
            state = if bit {
                <V::LeafableHasher as LeafableHasher>::two_to_one(*sibling, state)
            } else {
                <V::LeafableHasher as LeafableHasher>::two_to_one(state, *sibling)
            }
        }
        state
    }

    pub fn verify(
        &self,
        leaf_data: &V,
        index_bits: Vec<bool>, // little endian
        merkle_root: <V::LeafableHasher as LeafableHasher>::HashOut,
    ) -> anyhow::Result<()> {
        anyhow::ensure!(
            self.get_root(leaf_data, index_bits) == merkle_root,
            "Merkle proof verification failed"
        );
        Ok(())
    }
}

#[derive(Clone, Debug)]
pub(crate) struct MerkleProofTarget<VT: LeafableTarget> {
    siblings: Vec<<<VT::Leaf as Leafable>::LeafableHasher as LeafableHasher>::HashOutTarget>,
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
        index_bits: Vec<BoolTarget>,
    ) -> <<VT::Leaf as Leafable>::LeafableHasher as LeafableHasher>::HashOutTarget
    where
        <C as GenericConfig<D>>::Hasher: AlgebraicHasher<F>,
    {
        let mut state = leaf_data.hash::<F, C, D>(builder);
        assert_eq!(index_bits.len(), self.siblings.len());
        for (bit, sibling) in index_bits.iter().zip(&self.siblings) {
            state = <<VT::Leaf as Leafable>::LeafableHasher as LeafableHasher>::two_to_one_swapped::<
                F,
                C,
                D,
            >(builder, &state, sibling, *bit);
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
        index_bits: Vec<BoolTarget>,
        merkle_root: <<VT::Leaf as Leafable>::LeafableHasher as LeafableHasher>::HashOutTarget,
    ) where
        <C as GenericConfig<D>>::Hasher: AlgebraicHasher<F>,
    {
        let state = self.get_root::<F, C, D>(builder, leaf_data, index_bits);
        <<VT::Leaf as Leafable>::LeafableHasher as LeafableHasher>::connect_hash(
            builder,
            &state,
            &merkle_root,
        );
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
        index_bits: Vec<BoolTarget>,
        merkle_root: <<VT::Leaf as Leafable>::LeafableHasher as LeafableHasher>::HashOutTarget,
    ) where
        <C as GenericConfig<D>>::Hasher: AlgebraicHasher<F>,
    {
        let state = self.get_root::<F, C, D>(builder, leaf_data, index_bits);
        <<VT::Leaf as Leafable>::LeafableHasher as LeafableHasher>::conditional_assert_eq_hash(
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

pub fn usize_le_bits(num: usize, length: usize) -> Vec<bool> {
    let mut result = Vec::with_capacity(length);
    let mut n = num;
    for _ in 0..length {
        result.push(n & 1 == 1);
        n >>= 1;
    }
    result
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
        iop::{
            target::Target,
            witness::{PartialWitness, WitnessWrite},
        },
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
    fn merkle_tree_update_prove_verify() {
        type V = Bytes32<u32>;

        let mut rng = rand::thread_rng();
        let height = 10;
        let empty_leaf_hash = V::default().hash();
        let mut tree = MerkleTree::<Bytes32<u32>>::new(height, empty_leaf_hash);

        for _ in 0..100 {
            let index = rng.gen_range(0..1 << height);
            let new_leaf = Bytes32::rand(&mut rng);
            let leaf_hash = new_leaf.hash();
            let index_bits = usize_le_bits(index, height);
            tree.update_leaf(index_bits.clone(), leaf_hash);
            let proof = tree.prove(index_bits.clone());
            proof
                .verify(&new_leaf, index_bits, tree.get_root())
                .unwrap();
        }
    }

    #[test]
    fn merkle_proof_target() {
        type V = Bytes32<u32>;
        type VT = Bytes32<Target>;

        let mut rng = rand::thread_rng();
        let height = 10;

        let empty_leaf_hash = V::default().hash();
        let mut tree = MerkleTree::<V>::new(height, empty_leaf_hash);

        let index = rng.gen_range(0..1 << height);
        let leaf = Bytes32::rand(&mut rng);
        let leaf_hash = leaf.hash();
        let index_bits = usize_le_bits(index, height);
        tree.update_leaf(index_bits.clone(), leaf_hash);
        let proof = tree.prove(index_bits.clone());

        let mut builder = CircuitBuilder::<F, D>::new(CircuitConfig::default());
        let proof_t = MerkleProofTarget::<VT>::new(&mut builder, height);
        let leaf_t = Bytes32::new(&mut builder, false);
        let root_t = PoseidonHashOutTarget::new(&mut builder);
        let index_t = builder.add_virtual_target();
        let index_bits_t = builder.split_le(index_t, height);
        proof_t.verify::<F, C, D>(&mut builder, &leaf_t, index_bits_t, root_t);

        let data = builder.build::<C>();
        let mut pw = PartialWitness::<F>::new();
        leaf_t.set_witness(&mut pw, leaf);
        root_t.set_witness(&mut pw, tree.get_root());
        pw.set_target(index_t, F::from_canonical_usize(index));
        proof_t.set_witness(&mut pw, &proof);

        data.prove(pw).unwrap();
    }
}
