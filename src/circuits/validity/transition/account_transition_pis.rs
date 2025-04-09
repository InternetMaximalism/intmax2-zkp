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

#[cfg(test)]
mod tests {
    use plonky2::iop::target::Target;
    use rand::thread_rng;

    use super::*;

    #[test]
    fn test_account_transition_pis_from_u64_slice_success() {
        // Create a valid input slice
        let mut input = vec![0u64; ACCOUNT_TRANSITION_PUBLIC_INPUTS_LEN];

        // Set some recognizable values
        let prev_root = PoseidonHashOut::rand(&mut thread_rng());
        let new_root = PoseidonHashOut::rand(&mut thread_rng());
        let sender_root = PoseidonHashOut::rand(&mut thread_rng());

        // Fill the input slice
        input[0..4].copy_from_slice(&prev_root.elements);
        input[4] = 123; // prev_next_account_id
        input[5..9].copy_from_slice(&new_root.elements);
        input[9] = 456; // new_next_account_id
        input[10..14].copy_from_slice(&sender_root.elements);
        input[14] = 789; // block_number

        // Parse the input
        let result = AccountTransitionPublicInputs::from_u64_slice(&input);
        assert!(result.is_ok());

        let pis = result.unwrap();

        // Verify the parsed values
        assert_eq!(pis.prev_account_tree_root, prev_root);
        assert_eq!(pis.prev_next_account_id, 123);
        assert_eq!(pis.new_account_tree_root, new_root);
        assert_eq!(pis.new_next_account_id, 456);
        assert_eq!(pis.sender_tree_root, sender_root);
        assert_eq!(pis.block_number, 789);
    }

    #[test]
    fn test_account_transition_pis_from_u64_slice_error() {
        // Create an invalid input slice (too short)
        let input = vec![0u64; ACCOUNT_TRANSITION_PUBLIC_INPUTS_LEN - 1];

        // Parse the input
        let result = AccountTransitionPublicInputs::from_u64_slice(&input);
        assert!(result.is_err());

        // Verify the error
        match result {
            Err(ValidityTransitionError::AccountTransitionInputLengthMismatch {
                expected,
                actual,
            }) => {
                assert_eq!(expected, ACCOUNT_TRANSITION_PUBLIC_INPUTS_LEN);
                assert_eq!(actual, ACCOUNT_TRANSITION_PUBLIC_INPUTS_LEN - 1);
            }
            _ => panic!("Expected AccountTransitionInputLengthMismatch error"),
        }

        // Create another invalid input slice (too long)
        let input = vec![0u64; ACCOUNT_TRANSITION_PUBLIC_INPUTS_LEN + 1];

        // Parse the input
        let result = AccountTransitionPublicInputs::from_u64_slice(&input);
        assert!(result.is_err());

        // Verify the error
        match result {
            Err(ValidityTransitionError::AccountTransitionInputLengthMismatch {
                expected,
                actual,
            }) => {
                assert_eq!(expected, ACCOUNT_TRANSITION_PUBLIC_INPUTS_LEN);
                assert_eq!(actual, ACCOUNT_TRANSITION_PUBLIC_INPUTS_LEN + 1);
            }
            _ => panic!("Expected AccountTransitionInputLengthMismatch error"),
        }
    }

    #[test]
    fn test_account_transition_pis_target_to_vec() {
        // Create a target instance with default targets
        let prev_root = [Target::default(); 4];
        let new_root = [Target::default(); 4];
        let sender_root = [Target::default(); 4];

        let target = AccountTransitionPublicInputsTarget {
            prev_account_tree_root: PoseidonHashOutTarget {
                elements: prev_root,
            },
            prev_next_account_id: Target::default(),
            new_account_tree_root: PoseidonHashOutTarget { elements: new_root },
            new_next_account_id: Target::default(),
            sender_tree_root: PoseidonHashOutTarget {
                elements: sender_root,
            },
            block_number: Target::default(),
        };

        // Convert to vec
        let vec = target.to_vec();

        // Verify the length
        assert_eq!(vec.len(), ACCOUNT_TRANSITION_PUBLIC_INPUTS_LEN);

        // Verify the structure (we can't check specific values since we're using default targets)
        assert_eq!(vec.len(), 15);
    }

    #[test]
    fn test_account_transition_pis_target_from_slice_success() {
        // Create a valid input slice
        let input = vec![Target::default(); ACCOUNT_TRANSITION_PUBLIC_INPUTS_LEN];

        // Parse the input
        let result = AccountTransitionPublicInputsTarget::from_slice(&input);
        assert!(result.is_ok());

        let target = result.unwrap();

        // Verify the structure is correct (we can't check specific values)
        assert_eq!(target.prev_account_tree_root.elements.len(), 4);
        assert_eq!(target.new_account_tree_root.elements.len(), 4);
        assert_eq!(target.sender_tree_root.elements.len(), 4);
    }

    #[test]
    fn test_account_transition_pis_target_from_slice_error() {
        // Create an invalid input slice (too short)
        let input = vec![Target::default(); ACCOUNT_TRANSITION_PUBLIC_INPUTS_LEN - 1];

        // Parse the input
        let result = AccountTransitionPublicInputsTarget::from_slice(&input);
        assert!(result.is_err());

        // Verify the error
        match result {
            Err(ValidityTransitionError::AccountTransitionInputLengthMismatch {
                expected,
                actual,
            }) => {
                assert_eq!(expected, ACCOUNT_TRANSITION_PUBLIC_INPUTS_LEN);
                assert_eq!(actual, ACCOUNT_TRANSITION_PUBLIC_INPUTS_LEN - 1);
            }
            _ => panic!("Expected AccountTransitionInputLengthMismatch error"),
        }

        // Create another invalid input slice (too long)
        let input = vec![Target::default(); ACCOUNT_TRANSITION_PUBLIC_INPUTS_LEN + 1];

        // Parse the input
        let result = AccountTransitionPublicInputsTarget::from_slice(&input);
        assert!(result.is_err());

        // Verify the error
        match result {
            Err(ValidityTransitionError::AccountTransitionInputLengthMismatch {
                expected,
                actual,
            }) => {
                assert_eq!(expected, ACCOUNT_TRANSITION_PUBLIC_INPUTS_LEN);
                assert_eq!(actual, ACCOUNT_TRANSITION_PUBLIC_INPUTS_LEN + 1);
            }
            _ => panic!("Expected AccountTransitionInputLengthMismatch error"),
        }
    }
}
