use crate::{
    constants::NULLIFIER_TREE_HEIGHT,
    ethereum_types::{
        bytes32::Bytes32,
        u256::U256,
        u32limb_trait::{U32LimbTargetTrait, U32LimbTrait},
    },
    utils::{
        poseidon_hash_out::{PoseidonHashOut, PoseidonHashOutTarget},
        trees::indexed_merkle_tree::{
            insertion::{IndexedInsertionProof, IndexedInsertionProofTarget},
            IndexedMerkleTree,
        },
    },
};
use anyhow::{ensure, Result};
use plonky2::{
    field::{extension::Extendable, types::Field},
    hash::hash_types::RichField,
    iop::{target::Target, witness::WitnessWrite},
    plonk::{
        circuit_builder::CircuitBuilder,
        config::{AlgebraicHasher, GenericConfig},
    },
};
#[derive(Debug, Clone)]
pub struct NullifierTree(IndexedMerkleTree);
#[derive(Debug, Clone)]
pub struct NullifierInsersionProof(IndexedInsertionProof);
#[derive(Debug, Clone)]
pub struct NullifierInsersionProofTarget(IndexedInsertionProofTarget);

impl NullifierTree {
    pub fn new() -> Self {
        Self(IndexedMerkleTree::new(NULLIFIER_TREE_HEIGHT))
    }

    pub fn get_root(&self) -> PoseidonHashOut {
        self.0.get_root()
    }

    pub fn prove_and_insert(&mut self, nullifier: Bytes32<u32>) -> Result<NullifierInsersionProof> {
        let proof = self
            .0
            .prove_and_insert(U256::<u32>::from_limbs(&nullifier.limbs()), 0)?;
        Ok(NullifierInsersionProof(proof))
    }
}

impl NullifierInsersionProof {
    pub fn get_new_root(
        &self,
        prev_root: PoseidonHashOut,
        nullifier: Bytes32<u32>,
    ) -> Result<PoseidonHashOut> {
        let root =
            self.0
                .get_new_root(U256::<u32>::from_limbs(&nullifier.limbs()), 0, prev_root)?;
        Ok(root)
    }

    pub fn verify(
        &self,
        prev_root: PoseidonHashOut,
        new_root: PoseidonHashOut,
        nullifier: Bytes32<u32>,
    ) -> Result<()> {
        let expected_new_root = self.get_new_root(prev_root, nullifier)?;
        ensure!(
            new_root == expected_new_root,
            "new root is not equal to the expected new root"
        );
        Ok(())
    }
}

impl NullifierInsersionProofTarget {
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
        value: &NullifierInsersionProof,
    ) -> Self {
        Self(IndexedInsertionProofTarget::constant(builder, &value.0))
    }

    pub fn set_witness<F: Field, W: WitnessWrite<F>>(
        &self,
        witness: &mut W,
        value: &NullifierInsersionProof,
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
        nullifier: Bytes32<Target>,
    ) -> PoseidonHashOutTarget
    where
        <C as GenericConfig<D>>::Hasher: AlgebraicHasher<F>,
    {
        let zero = builder.zero();
        self.0.get_new_root::<F, C, D>(
            builder,
            U256::<Target>::from_limbs(&nullifier.limbs()),
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
        nullifier: Bytes32<Target>,
    ) where
        <C as GenericConfig<D>>::Hasher: AlgebraicHasher<F>,
    {
        let expected_new_root = self.get_new_root::<F, C, D>(builder, prev_root, nullifier);
        expected_new_root.connect(builder, new_root);
    }
}
