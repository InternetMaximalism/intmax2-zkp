use anyhow::{ensure, Result};
use plonky2::{
    field::extension::Extendable,
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
        logic::BuilderLogic,
        poseidon_hash_out::{PoseidonHashOut, PoseidonHashOutTarget},
        trees::merkle_tree_with_leaves::MerkleProofWithLeavesTarget,
    },
};

use super::{
    leaf::{IndexedMerkleLeaf, IndexedMerkleLeafTarget},
    IndexedMerkleProof, IndexedMerkleProofTarget, IndexedMerkleTree,
};

/// Proof of membership/non-membership of indexed merkle tree
#[derive(Clone, Debug)]
pub struct MembershipProof {
    pub is_included: bool,
    pub leaf_proof: IndexedMerkleProof,
    pub leaf_index: usize,
    pub leaf: IndexedMerkleLeaf,
}

/// Target version of MembershipProof
#[derive(Clone, Debug)]
pub struct MembershipProofTarget {
    pub is_included: BoolTarget,
    pub leaf_proof: IndexedMerkleProofTarget,
    pub leaf_index: Target,
    pub leaf: IndexedMerkleLeafTarget,
}

impl IndexedMerkleTree {
    /// Prove membership or non-membership of a key
    pub fn prove_membership(&self, key: U256<u32>) -> MembershipProof {
        if let Some(index) = self.index(key) {
            // inclusion proof
            return MembershipProof {
                is_included: true,
                leaf_index: index,
                leaf: self.0.get_leaf(index),
                leaf_proof: self.0.prove(index),
            };
        } else {
            // exclusion proof
            let low_index = self.low_index(key).unwrap(); // unwrap is safe here
            return MembershipProof {
                is_included: false,
                leaf_index: low_index,
                leaf: self.0.get_leaf(low_index),
                leaf_proof: self.0.prove(low_index),
            };
        }
    }
}

impl MembershipProof {
    /// Verify the membership/non-membership proof
    pub fn verify(&self, key: U256<u32>, root: PoseidonHashOut) -> Result<()> {
        self.leaf_proof.verify(&self.leaf, self.leaf_index, root)?;
        if self.is_included {
            ensure!(self.leaf.key == key);
        } else {
            ensure!(
                self.leaf.key < key
                    && (key < self.leaf.next_key || self.leaf.next_key == U256::default())
            );
        }
        Ok(())
    }

    // get value if the key is included, return 0 otherwise
    pub fn get_value(&self) -> u64 {
        if self.is_included {
            self.leaf.value
        } else {
            0
        }
    }
}

impl MembershipProofTarget {
    pub fn new<F: RichField + Extendable<D>, const D: usize>(
        builder: &mut CircuitBuilder<F, D>,
        height: usize,
        is_checked: bool,
    ) -> Self {
        let is_included = builder.add_virtual_bool_target_unsafe();
        if is_checked {
            builder.assert_bool(is_included);
        }
        Self {
            is_included,
            leaf_proof: MerkleProofWithLeavesTarget::new(builder, height),
            leaf_index: builder.add_virtual_target(),
            leaf: IndexedMerkleLeafTarget::new(builder, is_checked),
        }
    }

    pub fn constant<F: RichField + Extendable<D>, const D: usize>(
        builder: &mut CircuitBuilder<F, D>,
        value: &MembershipProof,
    ) -> Self {
        Self {
            is_included: builder.constant_bool(value.is_included),
            leaf_proof: IndexedMerkleProofTarget::constant(builder, &value.leaf_proof),
            leaf_index: builder.constant(F::from_canonical_usize(value.leaf_index)),
            leaf: IndexedMerkleLeafTarget::constant(builder, &value.leaf),
        }
    }

    pub fn set_witness<F: RichField, W: WitnessWrite<F>>(
        &self,
        witness: &mut W,
        value: &MembershipProof,
    ) {
        witness.set_bool_target(self.is_included, value.is_included);
        self.leaf_proof.set_witness(witness, &value.leaf_proof);
        witness.set_target(self.leaf_index, F::from_canonical_usize(value.leaf_index));
        self.leaf.set_witness(witness, &value.leaf);
    }

    pub fn verify<
        F: RichField + Extendable<D>,
        C: GenericConfig<D, F = F> + 'static,
        const D: usize,
    >(
        &self,
        builder: &mut CircuitBuilder<F, D>,
        key: U256<Target>,
        root: PoseidonHashOutTarget,
    ) where
        <C as GenericConfig<D>>::Hasher: AlgebraicHasher<F>,
    {
        self.leaf_proof
            .verify::<F, C, D>(builder, &self.leaf, self.leaf_index, root);

        // inclusion case
        self.leaf
            .key
            .conditional_assert_eq(builder, key, self.is_included);

        // exclusion case
        let is_exclusion = builder.not(self.is_included);
        let key_lt = self.leaf.key.is_lt(builder, &key);
        let is_next_key_zero = self.leaf.next_key.is_zero::<F, D, U256<u32>>(builder);
        let is_key_lt_or_next_key_zero = builder.or(key_lt, is_next_key_zero);
        builder.conditional_assert_true(is_exclusion, is_key_lt_or_next_key_zero);
    }

    pub fn get_value<F: RichField + Extendable<D>, const D: usize>(
        &self,
        builder: &mut CircuitBuilder<F, D>,
    ) -> Target {
        let zero = builder.zero();
        builder.select(self.is_included, self.leaf.value, zero)
    }
}

#[cfg(test)]
mod tests {
    use plonky2::{
        field::goldilocks_field::GoldilocksField,
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

    use super::{IndexedMerkleTree, MembershipProofTarget};

    type F = GoldilocksField;
    const D: usize = 2;
    type C = PoseidonGoldilocksConfig;

    #[test]
    fn indexed_merkle_tree_membership() {
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

        // random inclusion and exclusion proofs
        let root = tree.0.get_root();
        let mut keys_and_proofs = vec![];
        for (i, key) in keys.into_iter().enumerate() {
            if i % 2 == 0 {
                // inclusion proof
                let proof = tree.prove_membership(key);
                proof.verify(key, root).unwrap();
                assert!(proof.is_included);
                keys_and_proofs.push((key, proof));
            } else {
                // exclusion proof
                let key = U256::rand(rng);
                let proof = tree.prove_membership(key);
                proof.verify(key, root).unwrap();
                assert!(!proof.is_included);
                keys_and_proofs.push((key, proof));
            }
        }

        let mut builder = CircuitBuilder::<F, D>::new(CircuitConfig::default());

        let root_t = PoseidonHashOutTarget::constant(&mut builder, root);
        for (key, proof) in keys_and_proofs {
            let key_t = U256::<Target>::constant(&mut builder, key);
            let proof_t = MembershipProofTarget::constant(&mut builder, &proof);
            proof_t.verify::<F, C, D>(&mut builder, key_t, root_t);
        }
        let circuit = builder.build::<C>();
        let _ = circuit.prove(PartialWitness::new()).unwrap();
    }
}
