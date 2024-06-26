use plonky2::iop::target::Target;

use crate::utils::poseidon_hash_out::{PoseidonHashOut, PoseidonHashOutTarget};

pub const ACCOUNT_TRANSITION_PUBLIC_INPUTS_LEN: usize = 4 * 3 + 1;

#[derive(Clone, Debug)]
pub struct AccountTransitionPublicInputs {
    pub prev_account_tree_root: PoseidonHashOut,
    pub new_account_tree_root: PoseidonHashOut,
    pub sender_tree_root: PoseidonHashOut,
    pub block_number: u32,
}

#[derive(Clone, Debug)]
pub struct AccountTransitionPublicInputsTarget {
    pub prev_account_tree_root: PoseidonHashOutTarget,
    pub new_account_tree_root: PoseidonHashOutTarget,
    pub sender_tree_root: PoseidonHashOutTarget,
    pub block_number: Target,
}

impl AccountTransitionPublicInputs {
    pub fn from_u64_vec(input: &[u64]) -> Self {
        assert_eq!(input.len(), ACCOUNT_TRANSITION_PUBLIC_INPUTS_LEN);
        let prev_account_tree_root = PoseidonHashOut {
            elements: input[0..4].try_into().unwrap(),
        };
        let new_account_tree_root = PoseidonHashOut {
            elements: input[4..8].try_into().unwrap(),
        };
        let sender_tree_root = PoseidonHashOut {
            elements: input[8..12].try_into().unwrap(),
        };
        let block_number = input[12] as u32;
        Self {
            prev_account_tree_root,
            new_account_tree_root,
            sender_tree_root,
            block_number,
        }
    }
}

impl AccountTransitionPublicInputsTarget {
    pub fn to_vec(&self) -> Vec<Target> {
        let vec = self
            .prev_account_tree_root
            .elements
            .into_iter()
            .chain(self.new_account_tree_root.elements.into_iter())
            .chain(self.sender_tree_root.elements.into_iter())
            .chain(vec![self.block_number])
            .collect::<Vec<_>>();
        assert_eq!(vec.len(), ACCOUNT_TRANSITION_PUBLIC_INPUTS_LEN);
        vec
    }

    pub fn from_vec(input: &[Target]) -> Self {
        assert_eq!(input.len(), ACCOUNT_TRANSITION_PUBLIC_INPUTS_LEN);
        let prev_account_tree_root = PoseidonHashOutTarget {
            elements: input[0..4].try_into().unwrap(),
        };
        let new_account_tree_root = PoseidonHashOutTarget {
            elements: input[4..8].try_into().unwrap(),
        };
        let sender_tree_root = PoseidonHashOutTarget {
            elements: input[8..12].try_into().unwrap(),
        };
        let block_number = input[12];
        Self {
            prev_account_tree_root,
            new_account_tree_root,
            sender_tree_root,
            block_number,
        }
    }
}
