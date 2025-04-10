//! Account registration circuit for validity transition.
//!
//! This circuit ensures the correct transition of the account tree when registering new users.
//! It verifies that:
//! 1. Users who provide valid signatures and have non-dummy public keys are added to the account
//!    tree
//! 2. Each new user is assigned the next available account ID
//! 3. The last block number for each new account is set to the current block number
//! 4. The account tree root is updated correctly after all registrations
//!
//! This circuit is called after successful block validation, ensuring that account registration
//! only occurs when users provide valid signatures and the block is valid.

use plonky2::{
    field::extension::Extendable,
    hash::hash_types::RichField,
    iop::{
        target::Target,
        witness::{PartialWitness, Witness},
    },
    plonk::{
        circuit_builder::CircuitBuilder,
        circuit_data::{CircuitConfig, CircuitData},
        config::{AlgebraicHasher, GenericConfig},
        proof::ProofWithPublicInputs,
    },
};

use super::error::ValidityTransitionError;

use crate::{
    common::trees::{
        account_tree::{AccountRegistrationProof, AccountRegistrationProofTarget},
        sender_tree::{SenderLeaf, SenderLeafTarget},
    },
    constants::{ACCOUNT_TREE_HEIGHT, NUM_SENDERS_IN_BLOCK, SENDER_TREE_HEIGHT},
    utils::{
        dummy::DummyProof,
        poseidon_hash_out::{PoseidonHashOut, PoseidonHashOutTarget},
        trees::get_root::{get_merkle_root_from_leaves, get_merkle_root_from_leaves_circuit},
    },
};

use super::account_transition_pis::AccountTransitionPublicInputsTarget;

/// Represents the values used in the account registration circuit.
///
/// This structure contains all the inputs and outputs for the account registration process,
/// including the previous and new account tree roots, account IDs, and the proofs needed
/// to verify the correct registration of new accounts.
#[derive(Debug, Clone)]
pub struct AccountRegistrationValue {
    pub prev_account_tree_root: PoseidonHashOut,
    pub prev_next_account_id: u64,
    pub new_account_tree_root: PoseidonHashOut,
    pub new_next_account_id: u64,
    pub sender_tree_root: PoseidonHashOut,
    pub block_number: u32,
    pub sender_leaves: Vec<SenderLeaf>,
    pub account_registration_proofs: Vec<AccountRegistrationProof>,
}

impl AccountRegistrationValue {
    /// Creates a new AccountRegistrationValue by processing sender leaves and updating the account
    /// tree.
    ///
    /// This function:
    /// 1. Validates that the correct number of sender leaves and proofs are provided
    /// 2. Computes the sender tree root from the sender leaves
    /// 3. Updates the account tree for each sender that has a signature and is not a dummy pubkey
    /// 4. Verifies that account IDs are assigned sequentially
    /// 5. Returns the updated account tree root and next account ID
    ///
    /// # Arguments
    /// * `prev_account_tree_root` - The root of the account tree before registration
    /// * `prev_next_account_id` - The next available account ID before registration
    /// * `block_number` - The current block number
    /// * `sender_leaves` - The sender leaves containing public keys and signature inclusion flags
    /// * `account_registration_proofs` - The proofs for inserting accounts into the account tree
    pub fn new(
        prev_account_tree_root: PoseidonHashOut,
        prev_next_account_id: u64,
        block_number: u32,
        sender_leaves: Vec<SenderLeaf>,
        account_registration_proofs: Vec<AccountRegistrationProof>,
    ) -> Result<Self, ValidityTransitionError> {
        if sender_leaves.len() != NUM_SENDERS_IN_BLOCK {
            return Err(ValidityTransitionError::InvalidSenderLeavesCount {
                expected: NUM_SENDERS_IN_BLOCK,
                actual: sender_leaves.len(),
            });
        }

        if account_registration_proofs.len() != NUM_SENDERS_IN_BLOCK {
            return Err(
                ValidityTransitionError::InvalidAccountRegistrationProofsCount {
                    expected: NUM_SENDERS_IN_BLOCK,
                    actual: account_registration_proofs.len(),
                },
            );
        }

        let sender_tree_root =
            get_merkle_root_from_leaves(SENDER_TREE_HEIGHT, &sender_leaves).unwrap();

        let mut account_tree_root = prev_account_tree_root;
        let mut next_account_id = prev_next_account_id;
        for (i, (sender_leaf, account_registration_proof)) in sender_leaves
            .iter()
            .zip(account_registration_proofs.iter())
            .enumerate()
        {
            let is_not_dummy_pubkey = !sender_leaf.sender.is_dummy_pubkey();
            let will_update = sender_leaf.signature_included && is_not_dummy_pubkey;
            account_tree_root = account_registration_proof
                .conditional_get_new_root(
                    will_update,
                    sender_leaf.sender,
                    block_number as u64,
                    account_tree_root,
                )
                .map_err(|e| {
                    ValidityTransitionError::InvalidAccountRegistrationProof(format!(
                        "Invalid account registration proof at index {}: {}",
                        i, e
                    ))
                })?;

            if will_update {
                if account_registration_proof.index != next_account_id {
                    return Err(ValidityTransitionError::AccountIdMismatch {
                        expected: next_account_id,
                        actual: account_registration_proof.index,
                    });
                }
                next_account_id += 1;
            }
        }

        Ok(Self {
            prev_account_tree_root,
            prev_next_account_id,
            new_account_tree_root: account_tree_root,
            new_next_account_id: next_account_id,
            sender_tree_root,
            block_number,
            sender_leaves,
            account_registration_proofs,
        })
    }
}

/// Target structure for the account registration circuit.
///
/// This structure contains all the circuit targets needed to implement the account
/// registration constraints in the ZK circuit.
#[derive(Debug)]
pub struct AccountRegistrationTarget {
    pub prev_account_tree_root: PoseidonHashOutTarget,
    pub prev_next_account_id: Target,
    pub new_account_tree_root: PoseidonHashOutTarget,
    pub new_next_account_id: Target,
    pub sender_tree_root: PoseidonHashOutTarget,
    pub block_number: Target,
    pub sender_leaves: Vec<SenderLeafTarget>,
    pub account_registration_proofs: Vec<AccountRegistrationProofTarget>,
}

impl AccountRegistrationTarget {
    /// Creates a new AccountRegistrationTarget with circuit constraints that enforce the
    /// account registration rules.
    ///
    /// The circuit enforces that:
    /// 1. The sender tree root is correctly computed from the sender leaves
    /// 2. For each sender with a signature and non-dummy pubkey, the account tree is updated
    /// 3. Each new account is assigned the next sequential account ID
    /// 4. The account tree root is correctly updated after all registrations
    /// 5. The next account ID is correctly incremented for each registration
    pub fn new<F: RichField + Extendable<D>, C: GenericConfig<D, F = F> + 'static, const D: usize>(
        builder: &mut CircuitBuilder<F, D>,
    ) -> Self
    where
        <C as GenericConfig<D>>::Hasher: AlgebraicHasher<F>,
    {
        let prev_account_tree_root = PoseidonHashOutTarget::new(builder);
        let prev_next_account_id = builder.add_virtual_target();
        let block_number = builder.add_virtual_target();

        // Range check is not needed because we check the commitment
        let sender_leaves = (0..NUM_SENDERS_IN_BLOCK)
            .map(|_| SenderLeafTarget::new(builder, false))
            .collect::<Vec<_>>();
        let account_registration_proofs = (0..NUM_SENDERS_IN_BLOCK)
            .map(|_| AccountRegistrationProofTarget::new(builder, ACCOUNT_TREE_HEIGHT, false))
            .collect::<Vec<_>>();
        let sender_tree_root = get_merkle_root_from_leaves_circuit::<F, C, D, _>(
            builder,
            SENDER_TREE_HEIGHT,
            &sender_leaves,
        );

        let mut account_tree_root = prev_account_tree_root;
        let mut next_account_id = prev_next_account_id;
        for (sender_leaf, account_registration_proof) in
            sender_leaves.iter().zip(account_registration_proofs.iter())
        {
            let is_dummy_pubkey = sender_leaf.sender.is_dummy_pubkey(builder);
            let is_not_dummy_pubkey = builder.not(is_dummy_pubkey);
            let will_update = builder.and(sender_leaf.signature_included, is_not_dummy_pubkey);
            account_tree_root = account_registration_proof.conditional_get_new_root::<F, C, D>(
                builder,
                will_update,
                sender_leaf.sender,
                block_number,
                account_tree_root,
            );
            builder.conditional_assert_eq(
                will_update.target,
                next_account_id,
                account_registration_proof.index,
            );
            let incremented_next_account_id = builder.add_const(next_account_id, F::ONE);
            next_account_id =
                builder.select(will_update, incremented_next_account_id, next_account_id);
        }

        Self {
            prev_account_tree_root,
            prev_next_account_id,
            new_account_tree_root: account_tree_root,
            new_next_account_id: next_account_id,
            sender_tree_root,
            block_number,
            sender_leaves,
            account_registration_proofs,
        }
    }

    pub fn set_witness<F: RichField, W: Witness<F>>(
        &self,
        witness: &mut W,
        value: &AccountRegistrationValue,
    ) {
        self.prev_account_tree_root
            .set_witness(witness, value.prev_account_tree_root);
        witness.set_target(
            self.prev_next_account_id,
            F::from_canonical_u64(value.prev_next_account_id),
        );
        self.new_account_tree_root
            .set_witness(witness, value.new_account_tree_root);
        witness.set_target(
            self.new_next_account_id,
            F::from_canonical_u64(value.new_next_account_id),
        );
        self.sender_tree_root
            .set_witness(witness, value.sender_tree_root);
        witness.set_target(self.block_number, F::from_canonical_u32(value.block_number));

        for (sender_leaf, sender_leaf_t) in
            value.sender_leaves.iter().zip(self.sender_leaves.iter())
        {
            sender_leaf_t.set_witness(witness, sender_leaf);
        }

        for (account_registration_proof, account_registration_proof_t) in value
            .account_registration_proofs
            .iter()
            .zip(self.account_registration_proofs.iter())
        {
            account_registration_proof_t.set_witness(witness, account_registration_proof);
        }
    }
}

/// Circuit for verifying account registration transitions.
///
/// This circuit verifies that the account tree is correctly updated when registering new users,
/// ensuring that only users with valid signatures and non-dummy public keys are registered.
#[derive(Debug)]
pub struct AccountRegistrationCircuit<F, C, const D: usize>
where
    F: RichField + Extendable<D>,
    C: GenericConfig<D, F = F>,
{
    pub(crate) data: CircuitData<F, C, D>,
    pub(crate) target: AccountRegistrationTarget,
    pub(crate) dummy_proof: DummyProof<F, C, D>,
}

impl<F, C, const D: usize> AccountRegistrationCircuit<F, C, D>
where
    F: RichField + Extendable<D>,
    C: GenericConfig<D, F = F> + 'static,
    C::Hasher: AlgebraicHasher<F>,
{
    /// Creates a new AccountRegistrationCircuit with the necessary constraints.
    pub(crate) fn new() -> Self {
        let config = CircuitConfig::default();
        let mut builder = CircuitBuilder::<F, D>::new(config.clone());
        let target = AccountRegistrationTarget::new::<F, C, D>(&mut builder);
        let pis = AccountTransitionPublicInputsTarget {
            prev_account_tree_root: target.prev_account_tree_root,
            prev_next_account_id: target.prev_next_account_id,
            new_account_tree_root: target.new_account_tree_root,
            new_next_account_id: target.new_next_account_id,
            sender_tree_root: target.sender_tree_root,
            block_number: target.block_number,
        };
        builder.register_public_inputs(&pis.to_vec());

        let data = builder.build();
        let dummy_proof = DummyProof::new(&data.common);
        Self {
            data,
            target,
            dummy_proof,
        }
    }

    /// Generates a proof for the account registration circuit.
    ///
    /// # Arguments
    /// * `value` - The AccountRegistrationValue containing all inputs and expected outputs
    ///
    /// # Returns
    /// A proof that the account registration was performed correctly
    pub(crate) fn prove(
        &self,
        value: &AccountRegistrationValue,
    ) -> Result<ProofWithPublicInputs<F, C, D>, ValidityTransitionError> {
        let mut pw = PartialWitness::<F>::new();
        self.target.set_witness(&mut pw, value);
        self.data
            .prove(pw)
            .map_err(|e| ValidityTransitionError::ProofGenerationError(format!("{:?}", e)))
    }
}

#[cfg(test)]
mod tests {
    use plonky2::{
        field::goldilocks_field::GoldilocksField, plonk::config::PoseidonGoldilocksConfig,
    };

    use crate::{
        common::{
            signature_content::key_set::KeySet,
            trees::{account_tree::AccountTree, sender_tree::get_sender_leaves},
        },
        ethereum_types::{bytes16::Bytes16, u256::U256, u32limb_trait::U32LimbTrait as _},
    };
    use rand::Rng;

    use super::*;
    type F = GoldilocksField;
    const D: usize = 2;
    type C = PoseidonGoldilocksConfig;

    /// Tests the account registration circuit with a valid registration scenario.
    ///
    /// This test:
    /// 1. Creates an account tree with some existing accounts
    /// 2. Generates sender leaves with some having signatures and non-dummy pubkeys
    /// 3. Creates account registration proofs for each sender
    /// 4. Verifies that the account tree is correctly updated
    /// 5. Generates and verifies a ZK proof for the registration
    #[test]
    fn test_account_registration_valid() {
        let mut rng = rand::thread_rng();
        let mut tree = AccountTree::initialize();
        let mut next_account_id = 2;

        for _ in 0..100 {
            let keyset = KeySet::rand(&mut rng);
            let last_block_number = rng.gen();
            tree.insert(keyset.pubkey, last_block_number).unwrap();
            next_account_id += 1;
        }
        let prev_account_tree_root = tree.get_root();
        let prev_next_account_id = next_account_id;

        let mut pubkeys = (0..10).map(|_| U256::rand(&mut rng)).collect::<Vec<_>>();
        pubkeys.resize(NUM_SENDERS_IN_BLOCK, U256::dummy_pubkey()); // pad with dummy pubkeys
        let sender_flag = Bytes16::rand(&mut rng);
        let sender_leaves = get_sender_leaves(&pubkeys, sender_flag);
        let block_number: u32 = 1000;
        let mut account_registration_proofs = Vec::new();
        for sender_leaf in sender_leaves.iter() {
            let is_dummy_pubkey = sender_leaf.sender.is_dummy_pubkey();
            let will_update = sender_leaf.signature_included && !is_dummy_pubkey;
            let proof = if will_update {
                tree.prove_and_insert(sender_leaf.sender, block_number as u64)
                    .unwrap()
            } else {
                AccountRegistrationProof::dummy(ACCOUNT_TREE_HEIGHT)
            };
            account_registration_proofs.push(proof);
            if will_update {
                next_account_id += 1;
            }
        }
        let account_registration_value = AccountRegistrationValue::new(
            prev_account_tree_root,
            prev_next_account_id,
            block_number,
            sender_leaves,
            account_registration_proofs,
        )
        .unwrap();

        // Verify the account tree root was updated correctly
        let new_account_tree_root = tree.get_root();
        assert_eq!(
            account_registration_value.new_account_tree_root, new_account_tree_root,
            "Account tree root mismatch after registration"
        );

        // Verify the next account ID was updated correctly
        assert_eq!(
            account_registration_value.new_next_account_id, next_account_id,
            "Next account ID mismatch after registration"
        );

        // Generate the ZK proof
        let account_registration_circuit = AccountRegistrationCircuit::<F, C, D>::new();
        let _proof = account_registration_circuit
            .prove(&account_registration_value)
            .unwrap();

        // If we got here without errors, the proof was generated successfully
    }

    /// Tests the account registration circuit with a scenario where no new accounts are registered.
    ///
    /// This test verifies that when no senders have both signatures and non-dummy pubkeys,
    /// the account tree and next account ID remain unchanged.
    #[test]
    fn test_account_registration_no_updates() {
        let mut rng = rand::thread_rng();
        let tree = AccountTree::initialize();
        let prev_next_account_id = 2;

        // Create the initial account tree state
        let prev_account_tree_root = tree.get_root();

        // Create sender leaves where none have both signatures and non-dummy pubkeys
        let pubkeys = vec![U256::dummy_pubkey(); NUM_SENDERS_IN_BLOCK];
        let sender_flag = Bytes16::rand(&mut rng);
        let mut sender_leaves = get_sender_leaves(&pubkeys, sender_flag);

        // Ensure no sender has both signature and non-dummy pubkey
        for leaf in &mut sender_leaves {
            if !leaf.sender.is_dummy_pubkey() {
                leaf.signature_included = false;
            }
        }

        let block_number: u32 = 1000;
        let mut account_registration_proofs = Vec::new();

        // Create dummy proofs since no accounts will be registered
        for _ in 0..NUM_SENDERS_IN_BLOCK {
            let proof = AccountRegistrationProof::dummy(ACCOUNT_TREE_HEIGHT);
            account_registration_proofs.push(proof);
        }

        let account_registration_value = AccountRegistrationValue::new(
            prev_account_tree_root,
            prev_next_account_id,
            block_number,
            sender_leaves,
            account_registration_proofs,
        )
        .unwrap();

        // Verify the account tree root and next account ID remain unchanged
        assert_eq!(
            account_registration_value.new_account_tree_root, prev_account_tree_root,
            "Account tree root should not change when no accounts are registered"
        );

        assert_eq!(
            account_registration_value.new_next_account_id, prev_next_account_id,
            "Next account ID should not change when no accounts are registered"
        );

        // Generate and verify the ZK proof
        let account_registration_circuit = AccountRegistrationCircuit::<F, C, D>::new();
        let _proof = account_registration_circuit
            .prove(&account_registration_value)
            .unwrap();
    }
}
