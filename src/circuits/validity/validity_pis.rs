use plonky2::{
    field::{extension::Extendable, types::PrimeField64},
    hash::hash_types::RichField,
    iop::{
        target::{BoolTarget, Target},
        witness::WitnessWrite,
    },
    plonk::circuit_builder::CircuitBuilder,
};
use serde::{Deserialize, Serialize};

use crate::{
    common::public_state::{PublicState, PublicStateTarget, PUBLIC_STATE_LEN},
    ethereum_types::{
        bytes32::{Bytes32, Bytes32Target, BYTES32_LEN},
        u32limb_trait::{U32LimbTargetTrait as _, U32LimbTrait as _},
    },
    utils::{
        conversion::ToU64 as _,
        poseidon_hash_out::{PoseidonHashOut, PoseidonHashOutTarget, POSEIDON_HASH_OUT_LEN},
    },
};

pub const VALIDITY_PUBLIC_INPUTS_LEN: usize =
    PUBLIC_STATE_LEN + BYTES32_LEN + POSEIDON_HASH_OUT_LEN + 1;

/// Public inputs for the validity circuit
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ValidityPublicInputs {
    pub public_state: PublicState,
    pub tx_tree_root: Bytes32,
    pub sender_tree_root: PoseidonHashOut,
    pub is_valid_block: bool,
}

#[derive(Debug, Clone)]
pub struct ValidityPublicInputsTarget {
    pub public_state: PublicStateTarget,
    pub tx_tree_root: Bytes32Target,
    pub sender_tree_root: PoseidonHashOutTarget,
    pub is_valid_block: BoolTarget,
}

impl ValidityPublicInputs {
    pub fn genesis() -> Self {
        // We don't have to construct the tx tree and the sender tree, because they will be skipped.
        let tx_tree_root = Bytes32::default();
        let sender_tree_root = PoseidonHashOut::default();
        let is_valid_block = false;
        Self {
            public_state: PublicState::genesis(),
            tx_tree_root,
            sender_tree_root,
            is_valid_block,
        }
    }

    pub fn to_u64_vec(&self) -> Vec<u64> {
        let vec = self
            .public_state
            .to_u64_vec()
            .into_iter()
            .chain(self.tx_tree_root.to_u64_vec())
            .chain(self.sender_tree_root.elements)
            .chain(vec![self.is_valid_block as u64])
            .collect::<Vec<_>>();
        assert_eq!(vec.len(), VALIDITY_PUBLIC_INPUTS_LEN);
        vec
    }

    pub fn from_u64_slice(input: &[u64]) -> Self {
        Self::try_from_u64_slice(input).unwrap_or_else(|e| {
            panic!("Failed to create ValidityPublicInputs from u64 slice: {}", e);
        })
    }

    pub fn try_from_u64_slice(input: &[u64]) -> Result<Self, super::error::ValidityProverError> {
        if input.len() != VALIDITY_PUBLIC_INPUTS_LEN {
            return Err(super::error::ValidityProverError::Plonky2Error(format!(
                "Invalid input length for ValidityPublicInputs: expected {}, got {}",
                VALIDITY_PUBLIC_INPUTS_LEN,
                input.len()
            )));
        }
        let public_state = PublicState::try_from_u64_slice(&input[0..PUBLIC_STATE_LEN])
            .map_err(|e| super::error::ValidityProverError::Plonky2Error(format!("Invalid public_state: {}", e)))?;
        let tx_tree_root = Bytes32::from_u64_slice(&input[PUBLIC_STATE_LEN..PUBLIC_STATE_LEN + BYTES32_LEN])
            .map_err(|e| super::error::ValidityProverError::Plonky2Error(format!("Invalid tx_tree_root: {}", e)))?;
        let sender_tree_root = PoseidonHashOut::from_u64_slice(
            &input[PUBLIC_STATE_LEN + BYTES32_LEN
                ..PUBLIC_STATE_LEN + BYTES32_LEN + POSEIDON_HASH_OUT_LEN],
        )
        .unwrap_or_else(|e| {
            panic!("Failed to create PoseidonHashOut from u64 slice: {}", e)
        });
        let is_valid_block = input[PUBLIC_STATE_LEN + BYTES32_LEN + POSEIDON_HASH_OUT_LEN] == 1;
        Ok(Self {
            public_state,
            tx_tree_root,
            sender_tree_root,
            is_valid_block,
        })
    }

    pub fn from_pis<F: PrimeField64>(pis: &[F]) -> Self {
        Self::try_from_pis(pis).unwrap_or_else(|e| {
            panic!("Failed to create ValidityPublicInputs from pis: {}", e);
        })
    }

    pub fn try_from_pis<F: PrimeField64>(pis: &[F]) -> Result<Self, super::error::ValidityProverError> {
        if pis.len() < VALIDITY_PUBLIC_INPUTS_LEN {
            return Err(super::error::ValidityProverError::Plonky2Error(format!(
                "Public inputs length too short: expected at least {}, got {}",
                VALIDITY_PUBLIC_INPUTS_LEN,
                pis.len()
            )));
        }
        Self::try_from_u64_slice(&pis[0..VALIDITY_PUBLIC_INPUTS_LEN].to_u64_vec())
    }
}

impl ValidityPublicInputsTarget {
    pub fn to_vec(&self) -> Vec<Target> {
        let vec = self
            .public_state
            .to_vec()
            .into_iter()
            .chain(self.tx_tree_root.to_vec())
            .chain(self.sender_tree_root.elements)
            .chain(vec![self.is_valid_block.target])
            .collect::<Vec<_>>();
        assert_eq!(vec.len(), VALIDITY_PUBLIC_INPUTS_LEN);
        vec
    }

    pub fn from_slice(input: &[Target]) -> Self {
        assert_eq!(input.len(), VALIDITY_PUBLIC_INPUTS_LEN);
        let public_state = PublicStateTarget::from_slice(&input[0..PUBLIC_STATE_LEN]);
        let tx_tree_root =
            Bytes32Target::from_slice(&input[PUBLIC_STATE_LEN..PUBLIC_STATE_LEN + BYTES32_LEN]);
        let sender_tree_root = PoseidonHashOutTarget::from_slice(
            &input[PUBLIC_STATE_LEN + BYTES32_LEN
                ..PUBLIC_STATE_LEN + BYTES32_LEN + POSEIDON_HASH_OUT_LEN],
        );
        let is_valid_block =
            BoolTarget::new_unsafe(input[PUBLIC_STATE_LEN + BYTES32_LEN + POSEIDON_HASH_OUT_LEN]);
        Self {
            public_state,
            tx_tree_root,
            sender_tree_root,
            is_valid_block,
        }
    }

    pub fn from_pis(pis: &[Target]) -> Self {
        Self::from_slice(&pis[0..VALIDITY_PUBLIC_INPUTS_LEN])
    }
}

impl ValidityPublicInputsTarget {
    pub fn new<F: RichField + Extendable<D>, const D: usize>(
        builder: &mut CircuitBuilder<F, D>,
        is_checked: bool,
    ) -> Self {
        let is_valid_block = builder.add_virtual_bool_target_unsafe();
        if is_checked {
            builder.assert_bool(is_valid_block);
        }

        Self {
            public_state: PublicStateTarget::new(builder, is_checked),
            tx_tree_root: Bytes32Target::new(builder, is_checked),
            sender_tree_root: PoseidonHashOutTarget::new(builder),
            is_valid_block,
        }
    }

    pub fn constant<F: RichField + Extendable<D>, const D: usize>(
        builder: &mut CircuitBuilder<F, D>,
        value: &ValidityPublicInputs,
    ) -> Self {
        Self {
            public_state: PublicStateTarget::constant(builder, &value.public_state),
            tx_tree_root: Bytes32Target::constant(builder, value.tx_tree_root),
            sender_tree_root: PoseidonHashOutTarget::constant(builder, value.sender_tree_root),
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
            self.is_valid_block.target,
            other.is_valid_block.target,
        );
    }

    pub fn set_witness<F: RichField, W: WitnessWrite<F>>(
        &self,
        witness: &mut W,
        value: &ValidityPublicInputs,
    ) {
        self.public_state.set_witness(witness, &value.public_state);
        self.tx_tree_root.set_witness(witness, value.tx_tree_root);
        self.sender_tree_root
            .set_witness(witness, value.sender_tree_root);
        witness.set_bool_target(self.is_valid_block, value.is_valid_block);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand::thread_rng;

    #[test]
    fn test_validity_pis_genesis() {
        let genesis = ValidityPublicInputs::genesis();

        // Check that the genesis state has expected values
        assert_eq!(genesis.public_state, PublicState::genesis());
        assert_eq!(genesis.tx_tree_root, Bytes32::default());
        assert_eq!(genesis.sender_tree_root, PoseidonHashOut::default());
        assert_eq!(genesis.is_valid_block, false);
    }

    #[test]
    fn test_validity_pis_to_u64_vec_and_from_u64_slice() {
        // Create a ValidityPublicInputs instance
        let public_state = PublicState::genesis();
        let tx_tree_root = Bytes32::default();
        let mut rng = thread_rng();
        let sender_tree_root = PoseidonHashOut::rand(&mut rng);
        let is_valid_block = true;

        let original = ValidityPublicInputs {
            public_state,
            tx_tree_root,
            sender_tree_root,
            is_valid_block,
        };

        // Convert to u64 vector
        let u64_vec = original.to_u64_vec();

        // Check the length
        assert_eq!(u64_vec.len(), VALIDITY_PUBLIC_INPUTS_LEN);

        // Convert back from u64 slice
        let recovered = ValidityPublicInputs::from_u64_slice(&u64_vec);

        // Check that we get the original value back
        assert_eq!(recovered.public_state, original.public_state);
        assert_eq!(recovered.tx_tree_root, original.tx_tree_root);
        assert_eq!(recovered.sender_tree_root, original.sender_tree_root);
        assert_eq!(recovered.is_valid_block, original.is_valid_block);
    }
}
