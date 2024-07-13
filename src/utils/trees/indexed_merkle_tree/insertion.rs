use anyhow::{ensure, Result};
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

use crate::{
    ethereum_types::{u256::U256, u32limb_trait::U32LimbTargetTrait as _},
    utils::{
        leafable::{Leafable, LeafableTarget},
        poseidon_hash_out::{PoseidonHashOut, PoseidonHashOutTarget},
    },
};

use super::{
    leaf::{IndexedMerkleLeaf, IndexedMerkleLeafTarget},
    IndexedMerkleProof, IndexedMerkleProofTarget, IndexedMerkleTree,
};

#[derive(Clone, Debug)]
pub struct IndexedInsertionProof {
    pub index: usize,
    pub low_leaf_proof: IndexedMerkleProof,
    pub leaf_proof: IndexedMerkleProof,
    pub low_leaf_index: usize,
    pub prev_low_leaf: IndexedMerkleLeaf,
}

#[derive(Clone, Debug)]
pub struct IndexedInsertionProofTarget {
    pub index: Target,
    pub low_leaf_proof: IndexedMerkleProofTarget,
    pub leaf_proof: IndexedMerkleProofTarget,
    pub low_leaf_index: Target,
    pub prev_low_leaf: IndexedMerkleLeafTarget,
}

impl IndexedMerkleTree {
    pub fn insert(&mut self, key: U256<u32>, value: u64) -> Result<()> {
        let index = self.0.leaves().len();
        let low_index = self.low_index(key)?;
        let prev_low_leaf = self.0.get_leaf(low_index);
        let new_low_leaf = IndexedMerkleLeaf {
            next_index: index,
            next_key: key,
            ..prev_low_leaf
        };
        let leaf = IndexedMerkleLeaf {
            next_index: prev_low_leaf.next_index,
            key,
            next_key: prev_low_leaf.next_key,
            value,
        };
        self.0.update(low_index, new_low_leaf);
        self.0.push(leaf);
        Ok(())
    }

    pub fn prove_and_insert(
        &mut self,
        key: U256<u32>,
        value: u64,
    ) -> Result<IndexedInsertionProof> {
        let index = self.0.leaves().len();
        let low_index = self.low_index(key)?;
        let prev_low_leaf = self.0.get_leaf(low_index);
        let new_low_leaf = IndexedMerkleLeaf {
            next_index: index,
            next_key: key,
            ..prev_low_leaf
        };
        let leaf = IndexedMerkleLeaf {
            next_index: prev_low_leaf.next_index,
            key,
            next_key: prev_low_leaf.next_key,
            value,
        };
        let low_leaf_proof = self.0.prove(low_index);
        self.0.update(low_index, new_low_leaf);
        self.0.push(leaf);
        let leaf_proof = self.0.prove(index);
        Ok(IndexedInsertionProof {
            index,
            low_leaf_proof,
            leaf_proof,
            low_leaf_index: low_index,
            prev_low_leaf,
        })
    }

    pub fn prove_dummy(&self) -> IndexedInsertionProof {
        let dummy_low_index = 0;
        let prev_low_leaf = self.0.get_leaf(dummy_low_index);
        let dummy_proof = self.0.prove(dummy_low_index);
        IndexedInsertionProof {
            index: 0,
            low_leaf_proof: dummy_proof.clone(),
            leaf_proof: dummy_proof,
            low_leaf_index: dummy_low_index,
            prev_low_leaf,
        }
    }
}

impl IndexedInsertionProof {
    pub fn dummy(height: usize) -> Self {
        Self {
            index: 0,
            low_leaf_proof: IndexedMerkleProof::dummy(height),
            leaf_proof: IndexedMerkleProof::dummy(height),
            low_leaf_index: 0,
            prev_low_leaf: IndexedMerkleLeaf::default(),
        }
    }

    pub fn get_new_root(
        &self,
        key: U256<u32>,
        value: u64,
        prev_root: PoseidonHashOut,
    ) -> Result<PoseidonHashOut> {
        ensure!(self.prev_low_leaf.key < key, "key is not lower-bounded");
        ensure!(
            key < self.prev_low_leaf.next_key || self.prev_low_leaf.next_key == U256::default(),
            "key is not upper-bounded"
        );
        self.low_leaf_proof
            .verify(&self.prev_low_leaf, self.low_leaf_index, prev_root)?;
        let new_low_leaf = IndexedMerkleLeaf {
            next_index: self.index,
            next_key: key,
            ..self.prev_low_leaf
        };
        let temp_root = self
            .low_leaf_proof
            .get_root(&new_low_leaf, self.low_leaf_index);
        self.leaf_proof.verify(
            &<IndexedMerkleLeaf as Leafable>::empty_leaf(),
            self.index,
            temp_root,
        )?;
        let leaf = IndexedMerkleLeaf {
            next_index: self.prev_low_leaf.next_index,
            key,
            next_key: self.prev_low_leaf.next_key,
            value,
        };
        Ok(self.leaf_proof.get_root(&leaf, self.index))
    }

    pub fn conditional_get_new_root(
        &self,
        condition: bool,
        key: U256<u32>,
        value: u64,
        prev_root: PoseidonHashOut,
    ) -> Result<PoseidonHashOut> {
        if condition {
            self.get_new_root(key, value, prev_root)
        } else {
            Ok(prev_root)
        }
    }

    pub fn verify(
        &self,
        key: U256<u32>,
        value: u64,
        prev_root: PoseidonHashOut, // merkle root before insertion
        new_root: PoseidonHashOut,  // merkle root after insertion
    ) -> Result<()> {
        let expected_new_root = self.get_new_root(key, value, prev_root)?;
        ensure!(
            new_root == expected_new_root,
            "new root is not equal to the expected new root"
        );
        Ok(())
    }
}

impl IndexedInsertionProofTarget {
    pub fn new<F: RichField + Extendable<D>, const D: usize>(
        builder: &mut CircuitBuilder<F, D>,
        height: usize,
        is_checked: bool,
    ) -> Self {
        Self {
            index: builder.add_virtual_target(),
            low_leaf_proof: IndexedMerkleProofTarget::new(builder, height),
            leaf_proof: IndexedMerkleProofTarget::new(builder, height),
            low_leaf_index: builder.add_virtual_target(),
            prev_low_leaf: IndexedMerkleLeafTarget::new(builder, is_checked),
        }
    }

    pub fn constant<F: RichField + Extendable<D>, const D: usize>(
        builder: &mut CircuitBuilder<F, D>,
        value: &IndexedInsertionProof,
    ) -> Self {
        Self {
            index: builder.constant(F::from_canonical_usize(value.index)),
            low_leaf_proof: IndexedMerkleProofTarget::constant(builder, &value.low_leaf_proof),
            leaf_proof: IndexedMerkleProofTarget::constant(builder, &value.leaf_proof),
            low_leaf_index: builder.constant(F::from_canonical_usize(value.low_leaf_index)),
            prev_low_leaf: IndexedMerkleLeafTarget::constant(builder, &value.prev_low_leaf),
        }
    }

    pub fn set_witness<F: Field, W: WitnessWrite<F>>(
        &self,
        witness: &mut W,
        value: &IndexedInsertionProof,
    ) {
        witness.set_target(self.index, F::from_canonical_usize(value.index));
        self.low_leaf_proof
            .set_witness(witness, &value.low_leaf_proof);
        self.leaf_proof.set_witness(witness, &value.leaf_proof);
        witness.set_target(
            self.low_leaf_index,
            F::from_canonical_usize(value.low_leaf_index),
        );
        self.prev_low_leaf
            .set_witness(witness, &value.prev_low_leaf);
    }

    pub fn verify<
        F: RichField + Extendable<D>,
        C: GenericConfig<D, F = F> + 'static,
        const D: usize,
    >(
        &self,
        builder: &mut CircuitBuilder<F, D>,
        key: U256<Target>,
        value: Target,
        prev_root: PoseidonHashOutTarget,
        new_root: PoseidonHashOutTarget,
    ) where
        <C as GenericConfig<D>>::Hasher: AlgebraicHasher<F>,
    {
        let expected_new_root = self.get_new_root::<F, C, D>(builder, key, value, prev_root);
        expected_new_root.connect(builder, new_root);
    }

    pub fn get_new_root<
        F: RichField + Extendable<D>,
        C: GenericConfig<D, F = F> + 'static,
        const D: usize,
    >(
        &self,
        builder: &mut CircuitBuilder<F, D>,
        key: U256<Target>,
        value: Target,
        prev_root: PoseidonHashOutTarget,
    ) -> PoseidonHashOutTarget
    where
        <C as GenericConfig<D>>::Hasher: AlgebraicHasher<F>,
    {
        // assert self.prev_low_leaf.key < key
        let is_key_lower_bounded = self.prev_low_leaf.key.is_lt(builder, &key);
        builder.assert_one(is_key_lower_bounded.target);
        // assert key < self.prev_low_leaf.next_key || self.prev_low_leaf.next_key ==
        // U256::default()
        let is_key_upper_bounded = key.is_lt(builder, &self.prev_low_leaf.next_key);
        let is_next_key_zero = self
            .prev_low_leaf
            .next_key
            .is_zero::<F, D, U256<u32>>(builder);
        let is_key_upper_bounded_or_next_key_zero =
            builder.or(is_key_upper_bounded, is_next_key_zero);
        builder.assert_one(is_key_upper_bounded_or_next_key_zero.target);

        self.low_leaf_proof.verify::<F, C, D>(
            builder,
            &self.prev_low_leaf,
            self.low_leaf_index,
            prev_root,
        );
        let new_low_leaf = IndexedMerkleLeafTarget {
            next_index: self.index,
            next_key: key,
            ..self.prev_low_leaf
        };
        let temp_root =
            self.low_leaf_proof
                .get_root::<F, C, D>(builder, &new_low_leaf, self.low_leaf_index);
        let emtpy_leaf = <IndexedMerkleLeafTarget as LeafableTarget>::empty_leaf(builder);
        self.leaf_proof
            .verify::<F, C, D>(builder, &emtpy_leaf, self.index, temp_root);
        let leaf = IndexedMerkleLeafTarget {
            next_index: self.prev_low_leaf.next_index,
            key,
            next_key: self.prev_low_leaf.next_key,
            value,
        };
        self.leaf_proof
            .get_root::<F, C, D>(builder, &leaf, self.index)
    }

    pub fn conditional_get_new_root<
        F: RichField + Extendable<D>,
        C: GenericConfig<D, F = F> + 'static,
        const D: usize,
    >(
        &self,
        builder: &mut CircuitBuilder<F, D>,
        condition: BoolTarget,
        key: U256<Target>,
        value: Target,
        prev_root: PoseidonHashOutTarget,
    ) -> PoseidonHashOutTarget
    where
        <C as GenericConfig<D>>::Hasher: AlgebraicHasher<F>,
    {
        let one = builder.one();
        // assert self.prev_low_leaf.key < key
        let is_key_lower_bounded = self.prev_low_leaf.key.is_lt(builder, &key);
        builder.conditional_assert_eq(condition.target, is_key_lower_bounded.target, one);
        // assert key < self.prev_low_leaf.next_key
        // || self.prev_low_leaf.next_key == U256::default()
        let is_key_upper_bounded = key.is_lt(builder, &self.prev_low_leaf.next_key);
        let is_next_key_zero = self
            .prev_low_leaf
            .next_key
            .is_zero::<F, D, U256<u32>>(builder);
        let is_key_upper_bounded_or_next_key_zero =
            builder.or(is_key_upper_bounded, is_next_key_zero);
        builder.conditional_assert_eq(
            condition.target,
            is_key_upper_bounded_or_next_key_zero.target,
            one,
        );
        self.low_leaf_proof.conditional_verify::<F, C, D>(
            builder,
            condition,
            &self.prev_low_leaf,
            self.low_leaf_index,
            prev_root,
        );
        let new_low_leaf = IndexedMerkleLeafTarget {
            next_index: self.index,
            next_key: key,
            ..self.prev_low_leaf
        };
        let temp_root =
            self.low_leaf_proof
                .get_root::<F, C, D>(builder, &new_low_leaf, self.low_leaf_index);
        let emtpy_leaf = <IndexedMerkleLeafTarget as LeafableTarget>::empty_leaf(builder);
        self.leaf_proof.conditional_verify::<F, C, D>(
            builder,
            condition,
            &emtpy_leaf,
            self.index,
            temp_root,
        );
        let leaf = IndexedMerkleLeafTarget {
            next_index: self.prev_low_leaf.next_index,
            key,
            next_key: self.prev_low_leaf.next_key,
            value,
        };
        let new_root = self
            .leaf_proof
            .get_root::<F, C, D>(builder, &leaf, self.index);
        PoseidonHashOutTarget::select(builder, condition, new_root, prev_root)
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
        ethereum_types::{
            u256::U256,
            u32limb_trait::{U32LimbTargetTrait, U32LimbTrait as _},
        },
        utils::poseidon_hash_out::PoseidonHashOutTarget,
    };

    use super::{IndexedInsertionProof, IndexedInsertionProofTarget, IndexedMerkleTree};

    type F = GoldilocksField;
    const D: usize = 2;
    type C = PoseidonGoldilocksConfig;

    #[test]
    fn indexed_merkle_tree_insertion() {
        let height = 40;
        let mut tree = IndexedMerkleTree::new(height);
        let rng = &mut rand::thread_rng();
        let mut info = vec![];
        for _ in 0..10 {
            let key = U256::rand(rng);
            let value: u64 = rng.gen();
            let prev_root = tree.0.get_root();
            let proof = tree.prove_and_insert(key, value).unwrap();
            let new_root = tree.0.get_root();
            proof.verify(key, value, prev_root, new_root).unwrap();
            info.push((key, value, prev_root, new_root, proof));
        }

        let mut builder = CircuitBuilder::<F, D>::new(CircuitConfig::default());
        for (key, value, prev_root, new_root, proof) in info {
            let key_t = U256::<Target>::constant(&mut builder, key);
            let value_t = builder.constant(F::from_canonical_u64(value));
            let prev_root_t = PoseidonHashOutTarget::constant(&mut builder, prev_root);
            let new_root_t = PoseidonHashOutTarget::constant(&mut builder, new_root);
            let proof_t = IndexedInsertionProofTarget::constant(&mut builder, &proof);
            proof_t.verify::<F, C, D>(&mut builder, key_t, value_t, prev_root_t, new_root_t);
        }
        let circuit = builder.build::<C>();
        let _ = circuit.prove(PartialWitness::new()).unwrap();
    }

    #[test]
    fn test_dummy_insertion() {
        let height = 40;
        let mut tree = IndexedMerkleTree::new(height);
        tree.prove_and_insert(U256::<u32>::one(), 0).unwrap();

        let prev_root = tree.get_root();
        let dummy = IndexedInsertionProof::dummy(height);
        dummy
            .conditional_get_new_root(false, U256::<u32>::one(), 0, prev_root)
            .unwrap();

        let mut builder = CircuitBuilder::<F, D>::new(CircuitConfig::default());
        let dummy_t = IndexedInsertionProofTarget::constant(&mut builder, &dummy);
        let key_t = U256::<Target>::constant(&mut builder, U256::<u32>::one());
        let value_t = builder.constant(F::from_canonical_u64(0));
        let prev_root_t = PoseidonHashOutTarget::constant(&mut builder, prev_root);
        let condition = builder._false();
        dummy_t.conditional_get_new_root::<F, C, D>(
            &mut builder,
            condition,
            key_t,
            value_t,
            prev_root_t,
        );

        let circuit = builder.build::<C>();
        let _ = circuit.prove(PartialWitness::new()).unwrap();
    }
}
