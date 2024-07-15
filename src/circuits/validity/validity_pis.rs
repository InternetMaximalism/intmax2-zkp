use plonky2::{
    field::{extension::Extendable, types::PrimeField64},
    hash::hash_types::RichField,
    iop::{
        target::{BoolTarget, Target},
        witness::Witness,
    },
    plonk::circuit_builder::CircuitBuilder,
};

use crate::{
    common::public_state::{PublicState, PublicStateTarget, PUBLIC_STATE_LEN},
    ethereum_types::{
        bytes32::{Bytes32, BYTES32_LEN},
        u32limb_trait::{U32LimbTargetTrait as _, U32LimbTrait as _},
    },
    utils::{
        conversion::ToU64 as _,
        poseidon_hash_out::{PoseidonHashOut, PoseidonHashOutTarget, POSEIDON_HASH_OUT_LEN},
    },
};

pub const VALIDITY_PUBLIC_INPUTS_LEN: usize =
    PUBLIC_STATE_LEN + BYTES32_LEN + POSEIDON_HASH_OUT_LEN + 2;

/// Public inputs for the validity circuit
#[derive(Debug, Clone, PartialEq)]
pub struct ValidityPublicInputs {
    pub public_state: PublicState,
    pub tx_tree_root: Bytes32<u32>,
    pub sender_tree_root: PoseidonHashOut,
    pub is_registoration_block: bool, // todo remove
    pub is_valid_block: bool,
}

#[derive(Debug, Clone)]
pub struct ValidityPublicInputsTarget {
    pub public_state: PublicStateTarget,
    pub tx_tree_root: Bytes32<Target>,
    pub sender_tree_root: PoseidonHashOutTarget,
    pub is_registoration_block: BoolTarget,
    pub is_valid_block: BoolTarget,
}

impl ValidityPublicInputs {
    pub fn genesis() -> Self {
        // We don't have to construct the tx tree and the sender tree, because they will be skipped.
        let tx_tree_root = Bytes32::<u32>::default();
        let sender_tree_root = PoseidonHashOut::default();
        let is_registoration_block = false;
        let is_valid_block = false;
        Self {
            public_state: PublicState::genesis(),
            tx_tree_root,
            sender_tree_root,
            is_registoration_block,
            is_valid_block,
        }
    }

    pub fn to_u64_vec(&self) -> Vec<u64> {
        let vec = self
            .public_state
            .to_u64_vec()
            .into_iter()
            .chain(self.tx_tree_root.to_u64_vec())
            .chain(self.sender_tree_root.elements.into_iter())
            .chain(vec![
                self.is_registoration_block as u64,
                self.is_valid_block as u64,
            ])
            .collect::<Vec<_>>();
        assert_eq!(vec.len(), VALIDITY_PUBLIC_INPUTS_LEN);
        vec
    }

    pub fn from_u64_vec(input: &[u64]) -> Self {
        assert_eq!(input.len(), VALIDITY_PUBLIC_INPUTS_LEN);
        let public_state = PublicState::from_u64_vec(&input[0..PUBLIC_STATE_LEN]);
        let tx_tree_root =
            Bytes32::from_u64_vec(&input[PUBLIC_STATE_LEN..PUBLIC_STATE_LEN + BYTES32_LEN]);
        let sender_tree_root = PoseidonHashOut::from_u64_vec(
            &input[PUBLIC_STATE_LEN + BYTES32_LEN
                ..PUBLIC_STATE_LEN + BYTES32_LEN + POSEIDON_HASH_OUT_LEN],
        );
        let is_registoration_block =
            input[PUBLIC_STATE_LEN + BYTES32_LEN + POSEIDON_HASH_OUT_LEN] == 1;
        let is_valid_block = input[PUBLIC_STATE_LEN + BYTES32_LEN + POSEIDON_HASH_OUT_LEN + 1] == 1;
        Self {
            public_state,
            tx_tree_root,
            sender_tree_root,
            is_registoration_block,
            is_valid_block,
        }
    }

    pub fn from_pis<F: PrimeField64>(pis: &[F]) -> Self {
        Self::from_u64_vec(&pis[0..VALIDITY_PUBLIC_INPUTS_LEN].to_u64_vec())
    }
}

impl ValidityPublicInputsTarget {
    pub fn to_vec(&self) -> Vec<Target> {
        let vec = self
            .public_state
            .to_vec()
            .into_iter()
            .chain(self.tx_tree_root.to_vec())
            .chain(self.sender_tree_root.elements.into_iter())
            .chain(vec![
                self.is_registoration_block.target,
                self.is_valid_block.target,
            ])
            .collect::<Vec<_>>();
        assert_eq!(vec.len(), VALIDITY_PUBLIC_INPUTS_LEN);
        vec
    }

    pub fn from_vec(input: &[Target]) -> Self {
        assert_eq!(input.len(), VALIDITY_PUBLIC_INPUTS_LEN);
        let public_state = PublicStateTarget::from_vec(&input[0..PUBLIC_STATE_LEN]);
        let tx_tree_root =
            Bytes32::<Target>::from_limbs(&input[PUBLIC_STATE_LEN..PUBLIC_STATE_LEN + BYTES32_LEN]);
        let sender_tree_root = PoseidonHashOutTarget::from_vec(
            &input[PUBLIC_STATE_LEN + BYTES32_LEN
                ..PUBLIC_STATE_LEN + BYTES32_LEN + POSEIDON_HASH_OUT_LEN],
        );
        let is_registoration_block =
            BoolTarget::new_unsafe(input[PUBLIC_STATE_LEN + BYTES32_LEN + POSEIDON_HASH_OUT_LEN]);
        let is_valid_block = BoolTarget::new_unsafe(
            input[PUBLIC_STATE_LEN + BYTES32_LEN + POSEIDON_HASH_OUT_LEN + 1],
        );
        Self {
            public_state,
            tx_tree_root,
            sender_tree_root,
            is_registoration_block,
            is_valid_block,
        }
    }

    pub fn from_pis(pis: &[Target]) -> Self {
        Self::from_vec(&pis[0..VALIDITY_PUBLIC_INPUTS_LEN])
    }
}

impl ValidityPublicInputsTarget {
    pub fn new<F: RichField + Extendable<D>, const D: usize>(
        builder: &mut CircuitBuilder<F, D>,
        is_checked: bool,
    ) -> Self {
        let is_registoration_block = builder.add_virtual_bool_target_unsafe();
        let is_valid_block = builder.add_virtual_bool_target_unsafe();
        if is_checked {
            builder.assert_bool(is_registoration_block);
            builder.assert_bool(is_valid_block);
        }
        Self {
            public_state: PublicStateTarget::new(builder, is_checked),
            tx_tree_root: Bytes32::new(builder, is_checked),
            sender_tree_root: PoseidonHashOutTarget::new(builder),
            is_registoration_block,
            is_valid_block,
        }
    }

    pub fn constant<F: RichField + Extendable<D>, const D: usize>(
        builder: &mut CircuitBuilder<F, D>,
        value: &ValidityPublicInputs,
    ) -> Self {
        Self {
            public_state: PublicStateTarget::constant(builder, &value.public_state),
            tx_tree_root: Bytes32::constant(builder, value.tx_tree_root),
            sender_tree_root: PoseidonHashOutTarget::constant(builder, value.sender_tree_root),
            is_registoration_block: builder.constant_bool(value.is_registoration_block),
            is_valid_block: builder.constant_bool(value.is_valid_block),
        }
    }

    pub fn connect<F: RichField + Extendable<D>, const D: usize>(
        &self,
        builder: &mut CircuitBuilder<F, D>,
        other: &Self,
    ) {
        self.public_state.connect(builder, &other.public_state);
        self.tx_tree_root.connect(builder, other.tx_tree_root);
        self.sender_tree_root
            .connect(builder, other.sender_tree_root);
        builder.connect(
            self.is_registoration_block.target,
            other.is_registoration_block.target,
        );
        builder.connect(self.is_valid_block.target, other.is_valid_block.target);
    }

    pub fn conditional_assert_eq<F: RichField + Extendable<D>, const D: usize>(
        &self,
        builder: &mut CircuitBuilder<F, D>,
        other: &Self,
        condition: BoolTarget,
    ) {
        self.public_state
            .conditional_assert_eq(builder, &other.public_state, condition);
        self.tx_tree_root
            .conditional_assert_eq(builder, other.tx_tree_root, condition);
        self.sender_tree_root
            .conditional_assert_eq(builder, other.sender_tree_root, condition);
        builder.conditional_assert_eq(
            condition.target,
            self.is_registoration_block.target,
            other.is_registoration_block.target,
        );
        builder.conditional_assert_eq(
            condition.target,
            self.is_valid_block.target,
            other.is_valid_block.target,
        );
    }

    pub fn set_witness<F: RichField, W: Witness<F>>(
        &self,
        witness: &mut W,
        value: &ValidityPublicInputs,
    ) {
        self.public_state.set_witness(witness, &value.public_state);
        self.tx_tree_root.set_witness(witness, value.tx_tree_root);
        self.sender_tree_root
            .set_witness(witness, value.sender_tree_root);
        witness.set_bool_target(self.is_registoration_block, value.is_registoration_block);
        witness.set_bool_target(self.is_valid_block, value.is_valid_block);
    }
}
