use anyhow::{ensure, Result};
use plonky2::{
    field::extension::Extendable,
    hash::hash_types::RichField,
    iop::{target::Target, witness::Witness},
    plonk::{
        circuit_builder::CircuitBuilder,
        config::{AlgebraicHasher, GenericConfig},
    },
};

use crate::{
    ethereum_types::{u256::U256, u32limb_trait::U32LimbTargetTrait as _},
    utils::poseidon_hash_out::{PoseidonHashOut, PoseidonHashOutTarget},
};

use super::{
    leaf::{IndexedMerkleLeaf, IndexedMerkleLeafTarget},
    IndexedMerkleProof, IndexedMerkleProofTarget, IndexedMerkleTree,
};

/// Proof of membership/non-membership of indexed merkle tree
#[derive(Clone, Debug)]
pub struct UpdateProof {
    pub leaf_proof: IndexedMerkleProof,
    pub leaf_index: usize,
    pub prev_leaf: IndexedMerkleLeaf,
}

/// Target version of MembershipProof
#[derive(Clone, Debug)]
pub struct UpdateProofTarget {
    pub leaf_proof: IndexedMerkleProofTarget,
    pub leaf_index: Target,
    pub prev_leaf: IndexedMerkleLeafTarget,
}

impl IndexedMerkleTree {
    /// Prove update of a key
    pub fn prove_and_update(&mut self, key: U256<u32>, new_value: u64) -> UpdateProof {
        let index = self.index(key).expect("key does not exist");
        let prev_leaf = self.0.get_leaf(index);
        let new_leaf = IndexedMerkleLeaf {
            value: new_value,
            ..prev_leaf
        };
        self.0.update(index, new_leaf);
        UpdateProof {
            leaf_proof: self.0.prove(index),
            leaf_index: index,
            prev_leaf,
        }
    }
}

impl UpdateProof {
    pub fn get_new_root(
        &self,
        key: U256<u32>,
        prev_value: u64,
        new_value: u64,
        prev_root: PoseidonHashOut,
    ) -> Result<PoseidonHashOut> {
        ensure!(self.prev_leaf.value == prev_value, "value mismatch");
        ensure!(self.prev_leaf.key == key, "key mismatch");
        self.leaf_proof
            .verify(&self.prev_leaf, self.leaf_index, prev_root)?;
        let new_leaf = IndexedMerkleLeaf {
            value: new_value,
            ..self.prev_leaf
        };
        let new_root = self.leaf_proof.get_root(&new_leaf, self.leaf_index);
        Ok(new_root)
    }

    pub fn verify(
        &self,
        key: U256<u32>,
        prev_value: u64,
        new_value: u64,
        prev_root: PoseidonHashOut,
        new_root: PoseidonHashOut,
    ) -> Result<()> {
        let expected_new_root = self.get_new_root(key, prev_value, new_value, prev_root)?;
        ensure!(new_root == expected_new_root, "new_root mismatch");
        Ok(())
    }
}

impl UpdateProofTarget {
    pub fn new<F: RichField + Extendable<D>, const D: usize>(
        builder: &mut CircuitBuilder<F, D>,
        height: usize,
        is_checked: bool,
    ) -> Self {
        Self {
            leaf_proof: IndexedMerkleProofTarget::new(builder, height),
            leaf_index: builder.add_virtual_target(),
            prev_leaf: IndexedMerkleLeafTarget::new(builder, is_checked),
        }
    }

    pub fn constant<F: RichField + Extendable<D>, const D: usize>(
        builder: &mut CircuitBuilder<F, D>,
        value: &UpdateProof,
    ) -> Self {
        Self {
            leaf_proof: IndexedMerkleProofTarget::constant(builder, &value.leaf_proof),
            leaf_index: builder.constant(F::from_canonical_usize(value.leaf_index)),
            prev_leaf: IndexedMerkleLeafTarget::constant(builder, &value.prev_leaf),
        }
    }

    pub fn set_witness<F: RichField, W: Witness<F>>(&self, witness: &mut W, value: &UpdateProof) {
        self.leaf_proof.set_witness(witness, &value.leaf_proof);
        witness.set_target(self.leaf_index, F::from_canonical_usize(value.leaf_index));
        self.prev_leaf.set_witness(witness, &value.prev_leaf);
    }

    pub fn get_new_root<
        F: RichField + Extendable<D>,
        C: GenericConfig<D, F = F> + 'static,
        const D: usize,
    >(
        &self,
        builder: &mut CircuitBuilder<F, D>,
        key: U256<Target>,
        prev_value: Target,
        new_value: Target,
        prev_root: PoseidonHashOutTarget,
    ) -> PoseidonHashOutTarget
    where
        <C as GenericConfig<D>>::Hasher: AlgebraicHasher<F>,
    {
        key.connect(builder, self.prev_leaf.key);
        builder.connect(prev_value, self.prev_leaf.value);
        self.leaf_proof
            .verify::<F, C, D>(builder, &self.prev_leaf, self.leaf_index, prev_root);
        let new_leaf = IndexedMerkleLeafTarget {
            value: new_value,
            ..self.prev_leaf
        };
        self.leaf_proof
            .get_root::<F, C, D>(builder, &new_leaf, self.leaf_index)
    }

    pub fn verify<
        F: RichField + Extendable<D>,
        C: GenericConfig<D, F = F> + 'static,
        const D: usize,
    >(
        &self,
        builder: &mut CircuitBuilder<F, D>,
        key: U256<Target>,
        prev_value: Target,
        new_value: Target,
        prev_root: PoseidonHashOutTarget,
        new_root: PoseidonHashOutTarget,
    ) where
        <C as GenericConfig<D>>::Hasher: AlgebraicHasher<F>,
    {
        let expected_new_root =
            self.get_new_root::<F, C, D>(builder, key, prev_value, new_value, prev_root);
        new_root.connect(builder, expected_new_root);
    }
}

#[cfg(test)]
mod tests {
    use plonky2::{
        field::{goldilocks_field::GoldilocksField, types::Field},
        iop::{target::Target, witness::PartialWitness},
        plonk::{
            circuit_builder::CircuitBuilder, circuit_data::CircuitConfig,
            config::PoseidonGoldilocksConfig,
        },
    };
    use rand::Rng;

    use crate::{
        ethereum_types::{u256::U256, u32limb_trait::U32LimbTargetTrait},
        utils::poseidon_hash_out::PoseidonHashOutTarget,
    };

    use super::{IndexedMerkleTree, UpdateProofTarget};

    type F = GoldilocksField;
    const D: usize = 2;
    type C = PoseidonGoldilocksConfig;

    #[test]
    fn indexed_merkle_tree_update() {
        let height = 40;
        let mut tree = IndexedMerkleTree::new(height);
        let rng = &mut rand::thread_rng();
        let mut keys = vec![];

        // tree construction
        for _ in 0..10 {
            let key = U256::rand(rng);
            let value: u64 = rng.gen();
            tree.insert(key, value).unwrap();
            keys.push(key);
        }

        let mut proofs = vec![];
        for key in keys.into_iter() {
            let index = tree.index(key).unwrap();
            let prev_leaf = tree.0.get_leaf(index);
            let prev_value = prev_leaf.value;
            let new_value = rng.gen();
            let prev_root = tree.0.get_root();
            let proof = tree.prove_and_update(key, new_value);
            let new_root = tree.0.get_root();
            proof
                .verify(key, prev_value, new_value, prev_root, new_root)
                .unwrap();
            proofs.push((key, prev_value, new_value, prev_root, new_root, proof))
        }

        let mut builder = CircuitBuilder::<F, D>::new(CircuitConfig::default());

        for (key, prev_value, new_value, prev_root, new_root, proof) in proofs {
            let key_t = U256::<Target>::constant(&mut builder, key);
            let prev_value_t = builder.constant(F::from_canonical_u64(prev_value));
            let new_value_t = builder.constant(F::from_canonical_u64(new_value));
            let prev_root_t = PoseidonHashOutTarget::constant(&mut builder, prev_root);
            let new_root_t = PoseidonHashOutTarget::constant(&mut builder, new_root);
            let proof_t = UpdateProofTarget::constant(&mut builder, &proof);
            proof_t.verify::<F, C, D>(
                &mut builder,
                key_t,
                prev_value_t,
                new_value_t,
                prev_root_t,
                new_root_t,
            );
        }
        let circuit = builder.build::<C>();
        let _ = circuit.prove(PartialWitness::new()).unwrap();
    }
}
