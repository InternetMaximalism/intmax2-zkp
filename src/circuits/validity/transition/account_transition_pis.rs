use plonky2::iop::target::Target;

use super::error::ValidityTransitionError;
use crate::utils::poseidon_hash_out::{
    PoseidonHashOut, PoseidonHashOutTarget, POSEIDON_HASH_OUT_LEN,
};

pub const ACCOUNT_TRANSITION_PUBLIC_INPUTS_LEN: usize = 3 * POSEIDON_HASH_OUT_LEN + 3;

#[derive(Clone, Debug)]
pub struct AccountTransitionPublicInputs {
    pub prev_account_tree_root: PoseidonHashOut,
    pub prev_next_account_id: u64,
    pub new_account_tree_root: PoseidonHashOut,
    pub new_next_account_id: u64,
    pub sender_tree_root: PoseidonHashOut,
    pub block_number: u32,
}

#[derive(Clone, Debug)]
pub(crate) struct AccountTransitionPublicInputsTarget {
    pub(crate) prev_account_tree_root: PoseidonHashOutTarget,
    pub(crate) prev_next_account_id: Target,
    pub(crate) new_account_tree_root: PoseidonHashOutTarget,
    pub(crate) new_next_account_id: Target,
    pub(crate) sender_tree_root: PoseidonHashOutTarget,
    pub(crate) block_number: Target,
}

impl AccountTransitionPublicInputs {
    pub(crate) fn from_u64_slice(input: &[u64]) -> Result<Self, ValidityTransitionError> {
        if input.len() != ACCOUNT_TRANSITION_PUBLIC_INPUTS_LEN {
            return Err(
                ValidityTransitionError::AccountTransitionInputLengthMismatch {
                    expected: ACCOUNT_TRANSITION_PUBLIC_INPUTS_LEN,
                    actual: input.len(),
                },
            );
        }
        let prev_account_tree_root = PoseidonHashOut {
            elements: input[0..4].try_into().unwrap(),
        };
        let prev_next_account_id = input[4];
        let new_account_tree_root = PoseidonHashOut {
            elements: input[5..9].try_into().unwrap(),
        };
        let new_next_account_id = input[9];
        let sender_tree_root = PoseidonHashOut {
            elements: input[10..14].try_into().unwrap(),
        };
        let block_number = input[14] as u32;
        Ok(Self {
            prev_account_tree_root,
            prev_next_account_id,
            new_account_tree_root,
            new_next_account_id,
            sender_tree_root,
            block_number,
        })
    }
}

impl AccountTransitionPublicInputsTarget {
    pub(crate) fn to_vec(&self) -> Vec<Target> {
        let vec = self
            .prev_account_tree_root
            .elements
            .into_iter()
            .chain(vec![self.prev_next_account_id])
            .chain(self.new_account_tree_root.elements)
            .chain(vec![self.new_next_account_id])
            .chain(self.sender_tree_root.elements)
            .chain(vec![self.block_number])
            .collect::<Vec<_>>();

        // This is a sanity check that should never fail if the code is correct
        debug_assert_eq!(vec.len(), ACCOUNT_TRANSITION_PUBLIC_INPUTS_LEN);

        vec
    }

    pub(crate) fn from_slice(input: &[Target]) -> Result<Self, ValidityTransitionError> {
        if input.len() != ACCOUNT_TRANSITION_PUBLIC_INPUTS_LEN {
            return Err(
                ValidityTransitionError::AccountTransitionInputLengthMismatch {
                    expected: ACCOUNT_TRANSITION_PUBLIC_INPUTS_LEN,
                    actual: input.len(),
                },
            );
        }

        let prev_account_tree_root = PoseidonHashOutTarget {
            elements: input[0..4].try_into().unwrap(),
        };
        let prev_next_account_id = input[4];
        let new_account_tree_root = PoseidonHashOutTarget {
            elements: input[5..9].try_into().unwrap(),
        };
        let new_next_account_id = input[9];
        let sender_tree_root = PoseidonHashOutTarget {
            elements: input[10..14].try_into().unwrap(),
        };
        let block_number = input[14];

        Ok(Self {
            prev_account_tree_root,
            prev_next_account_id,
            new_account_tree_root,
            new_next_account_id,
            sender_tree_root,
            block_number,
        })
    }
}
