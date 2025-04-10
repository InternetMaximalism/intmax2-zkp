use crate::{
    common::error::CommonError,
    constants::NULLIFIER_TREE_HEIGHT,
    ethereum_types::{
        bytes32::{Bytes32, Bytes32Target},
        u256::U256Target,
        u32limb_trait::U32LimbTargetTrait,
    },
    utils::{
        poseidon_hash_out::{PoseidonHashOut, PoseidonHashOutTarget},
        trees::indexed_merkle_tree::{
            insertion::{IndexedInsertionProof, IndexedInsertionProofTarget},
            IndexedMerkleTree,
        },
    },
};
use plonky2::{
    field::{extension::Extendable, types::Field},
    hash::hash_types::RichField,
    iop::witness::WitnessWrite,
    plonk::{
        circuit_builder::CircuitBuilder,
        config::{AlgebraicHasher, GenericConfig},
    },
};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NullifierTree(IndexedMerkleTree);
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NullifierInsertionProof(IndexedInsertionProof);
#[derive(Debug, Clone)]
pub struct NullifierInsertionProofTarget(IndexedInsertionProofTarget);

impl Default for NullifierTree {
    fn default() -> Self {
        Self::new()
    }
}

impl NullifierTree {
    pub fn new() -> Self {
        Self(IndexedMerkleTree::new(NULLIFIER_TREE_HEIGHT))
    }

    pub fn get_root(&self) -> PoseidonHashOut {
        self.0.get_root()
    }

    pub fn nullifiers(&self) -> Vec<Bytes32> {
        self.0
            .leaves()
            .iter()
            .skip(1) // ignore the default leaf
            .map(|l| l.key.into())
            .collect()
    }

    pub fn prove_and_insert(
        &mut self,
        nullifier: Bytes32,
    ) -> Result<NullifierInsertionProof, CommonError> {
        let proof = self
            .0
            .prove_and_insert(nullifier.into(), 0)
            .map_err(|e| CommonError::NullifierAlreadyExists(e.to_string()))?;
        Ok(NullifierInsertionProof(proof))
    }
}

impl NullifierInsertionProof {
    pub fn get_new_root(
        &self,
        prev_root: PoseidonHashOut,
        nullifier: Bytes32,
    ) -> Result<PoseidonHashOut, CommonError> {
        let root = self
            .0
            .get_new_root(nullifier.into(), 0, prev_root)
            .map_err(|e| CommonError::InvalidData(e.to_string()))?;
        Ok(root)
    }

    pub fn verify(
        &self,
        prev_root: PoseidonHashOut,
        new_root: PoseidonHashOut,
        nullifier: Bytes32,
    ) -> Result<(), CommonError> {
        let expected_new_root = self.get_new_root(prev_root, nullifier)?;
        if new_root != expected_new_root {
            return Err(CommonError::InvalidData(
                "new root is not equal to the expected new root".to_string(),
            ));
        }
        Ok(())
    }
}

impl NullifierInsertionProofTarget {
    pub fn new<F: RichField + Extendable<D>, const D: usize>(
        builder: &mut CircuitBuilder<F, D>,
        is_checked: bool,
    ) -> Self {
        Self(IndexedInsertionProofTarget::new(
            builder,
            NULLIFIER_TREE_HEIGHT,
            is_checked,
        ))
    }

    pub fn constant<F: RichField + Extendable<D>, const D: usize>(
        builder: &mut CircuitBuilder<F, D>,
        value: &NullifierInsertionProof,
    ) -> Self {
        Self(IndexedInsertionProofTarget::constant(builder, &value.0))
    }

    pub fn set_witness<F: Field, W: WitnessWrite<F>>(
        &self,
        witness: &mut W,
        value: &NullifierInsertionProof,
    ) {
        self.0.set_witness(witness, &value.0)
    }

    pub fn get_new_root<
        F: RichField + Extendable<D>,
        C: GenericConfig<D, F = F> + 'static,
        const D: usize,
    >(
        &self,
        builder: &mut CircuitBuilder<F, D>,
        prev_root: PoseidonHashOutTarget,
        nullifier: Bytes32Target,
    ) -> PoseidonHashOutTarget
    where
        <C as GenericConfig<D>>::Hasher: AlgebraicHasher<F>,
    {
        let zero = builder.zero();
        self.0.get_new_root::<F, C, D>(
            builder,
            U256Target::from_slice(&nullifier.to_vec()),
            zero,
            prev_root,
        )
    }

    pub fn verify<
        F: RichField + Extendable<D>,
        C: GenericConfig<D, F = F> + 'static,
        const D: usize,
    >(
        &self,
        builder: &mut CircuitBuilder<F, D>,
        prev_root: PoseidonHashOutTarget,
        new_root: PoseidonHashOutTarget,
        nullifier: Bytes32Target,
    ) where
        <C as GenericConfig<D>>::Hasher: AlgebraicHasher<F>,
    {
        let expected_new_root = self.get_new_root::<F, C, D>(builder, prev_root, nullifier);
        expected_new_root.connect(builder, new_root);
    }
}
