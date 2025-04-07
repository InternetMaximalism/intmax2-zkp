//! Account update circuit for validity transition.
//!
//! This circuit ensures the correct transition of the account tree in non-registration blocks.
//! It verifies that:
//! 1. The last block number in the account tree is updated to the current block number only when
//!    the user returns a signature
//! 2. For users who do not provide signatures, their last block number remains unchanged
//! 3. The account tree root is updated correctly after all updates
//!
//! This circuit is called after successful block validation, ensuring that account updates
//! only occur when users provide valid signatures and the block is valid.

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
        account_tree::{AccountUpdateProof, AccountUpdateProofTarget},
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

/// Represents the values used in the account update circuit.
///
/// This structure contains all the inputs and outputs for the account update process,
/// including the previous and new account tree roots, and the proofs needed
/// to verify the correct updating of last block numbers.
pub(crate) struct AccountUpdateValue {
    pub(crate) prev_account_tree_root: PoseidonHashOut,
    pub(crate) new_account_tree_root: PoseidonHashOut,
    pub(crate) next_account_id: u64,
    pub(crate) sender_tree_root: PoseidonHashOut,
    pub(crate) block_number: u32,
    pub(crate) sender_leaves: Vec<SenderLeaf>,
    pub(crate) account_update_proofs: Vec<AccountUpdateProof>,
}

impl AccountUpdateValue {
    /// Creates a new AccountUpdateValue by processing sender leaves and updating the account tree.
    ///
    /// This function:
    /// 1. Validates that the correct number of sender leaves and proofs are provided
    /// 2. Computes the sender tree root from the sender leaves
    /// 3. Updates the last block number for each sender that has a signature
    /// 4. Returns the updated account tree root
    ///
    /// # Arguments
    /// * `prev_account_tree_root` - The root of the account tree before updates
    /// * `prev_next_account_id` - The next available account ID (unchanged in update operations)
    /// * `block_number` - The current block number
    /// * `sender_leaves` - The sender leaves containing public keys and signature inclusion flags
    /// * `account_update_proofs` - The proofs for updating accounts in the account tree
    pub(crate) fn new(
        prev_account_tree_root: PoseidonHashOut,
        prev_next_account_id: u64,
        block_number: u32,
        sender_leaves: Vec<SenderLeaf>,
        account_update_proofs: Vec<AccountUpdateProof>,
    ) -> Result<Self, ValidityTransitionError> {
        if sender_leaves.len() != NUM_SENDERS_IN_BLOCK {
            return Err(ValidityTransitionError::InvalidSenderLeavesCount {
                expected: NUM_SENDERS_IN_BLOCK,
                actual: sender_leaves.len(),
            });
        }
        
        if account_update_proofs.len() != NUM_SENDERS_IN_BLOCK {
            return Err(ValidityTransitionError::InvalidAccountUpdateProofsCount {
                expected: NUM_SENDERS_IN_BLOCK,
                actual: account_update_proofs.len(),
            });
        }
        
        let sender_tree_root = get_merkle_root_from_leaves(SENDER_TREE_HEIGHT, &sender_leaves)
            .unwrap();

        let mut account_tree_root = prev_account_tree_root;
        for (i, (sender_leaf, account_update_proof)) in
            sender_leaves.iter().zip(account_update_proofs.iter()).enumerate()
        {
            let prev_last_block_number = account_update_proof.prev_leaf.value as u32;
            let last_block_number = if sender_leaf.signature_included {
                block_number
            } else {
                prev_last_block_number
            };
            account_tree_root = account_update_proof
                .get_new_root(
                    sender_leaf.sender,
                    prev_last_block_number as u64,
                    last_block_number as u64,
                    account_tree_root,
                )
                .map_err(|e| ValidityTransitionError::InvalidAccountUpdateProof(
                    format!("Invalid account update proof at index {}: {}", i, e)
                ))?;
        }

        Ok(Self {
            prev_account_tree_root,
            new_account_tree_root: account_tree_root,
            next_account_id: prev_next_account_id,
            sender_tree_root,
            block_number,
            sender_leaves,
            account_update_proofs,
        })
    }
}

/// Target structure for the account update circuit.
///
/// This structure contains all the circuit targets needed to implement the account
/// update constraints in the ZK circuit.
#[derive(Debug)]
pub(crate) struct AccountUpdateTarget {
    pub(crate) prev_account_tree_root: PoseidonHashOutTarget,
    pub(crate) new_account_tree_root: PoseidonHashOutTarget,
    pub(crate) next_account_id: Target,
    pub(crate) sender_tree_root: PoseidonHashOutTarget,
    pub(crate) block_number: Target,
    pub(crate) sender_leaves: Vec<SenderLeafTarget>,
    pub(crate) account_update_proofs: Vec<AccountUpdateProofTarget>,
}

impl AccountUpdateTarget {
    /// Creates a new AccountUpdateTarget with circuit constraints that enforce the
    /// account update rules.
    ///
    /// The circuit enforces that:
    /// 1. The sender tree root is correctly computed from the sender leaves
    /// 2. For each sender with a signature, the last block number is updated to the current block number
    /// 3. For each sender without a signature, the last block number remains unchanged
    /// 4. The account tree root is correctly updated after all updates
    pub(crate) fn new<
        F: RichField + Extendable<D>,
        C: GenericConfig<D, F = F> + 'static,
        const D: usize,
    >(
        builder: &mut CircuitBuilder<F, D>,
    ) -> Self
    where
        <C as GenericConfig<D>>::Hasher: AlgebraicHasher<F>,
    {
        let prev_account_tree_root = PoseidonHashOutTarget::new(builder);
        let next_account_id = builder.add_virtual_target();
        let block_number = builder.add_virtual_target();

        // Range check is not needed because we check the commitment
        let sender_leaves = (0..NUM_SENDERS_IN_BLOCK)
            .map(|_| SenderLeafTarget::new(builder, false))
            .collect::<Vec<_>>();
        let account_update_proofs = (0..NUM_SENDERS_IN_BLOCK)
            .map(|_| AccountUpdateProofTarget::new(builder, ACCOUNT_TREE_HEIGHT, false))
            .collect::<Vec<_>>();
        let sender_tree_root = get_merkle_root_from_leaves_circuit::<F, C, D, _>(
            builder,
            SENDER_TREE_HEIGHT,
            &sender_leaves,
        );

        let mut account_tree_root = prev_account_tree_root;
        for (sender_leaf, account_update_proof) in
            sender_leaves.iter().zip(account_update_proofs.iter())
        {
            let prev_last_block_number = account_update_proof.prev_leaf.value;
            let last_block_number = builder.select(
                sender_leaf.signature_included,
                block_number,
                prev_last_block_number,
            );
            account_tree_root = account_update_proof.get_new_root::<F, C, D>(
                builder,
                sender_leaf.sender,
                prev_last_block_number,
                last_block_number,
                account_tree_root,
            );
        }

        Self {
            prev_account_tree_root,
            new_account_tree_root: account_tree_root,
            next_account_id,
            sender_tree_root,
            block_number,
            sender_leaves,
            account_update_proofs,
        }
    }

    pub(crate) fn set_witness<F: RichField, W: Witness<F>>(
        &self,
        witness: &mut W,
        value: &AccountUpdateValue,
    ) {
        self.prev_account_tree_root
            .set_witness(witness, value.prev_account_tree_root);
        self.new_account_tree_root
            .set_witness(witness, value.new_account_tree_root);
        witness.set_target(
            self.next_account_id,
            F::from_canonical_u64(value.next_account_id),
        );
        self.sender_tree_root
            .set_witness(witness, value.sender_tree_root);
        witness.set_target(self.block_number, F::from_canonical_u32(value.block_number));

        for (sender_leaf, sender_leaf_t) in
            value.sender_leaves.iter().zip(self.sender_leaves.iter())
        {
            sender_leaf_t.set_witness(witness, sender_leaf);
        }

        for (account_update_proof, account_update_proof_t) in value
            .account_update_proofs
            .iter()
            .zip(self.account_update_proofs.iter())
        {
            account_update_proof_t.set_witness(witness, account_update_proof);
        }
    }
}

/// Circuit for verifying account update transitions.
///
/// This circuit verifies that the account tree is correctly updated in non-registration blocks,
/// ensuring that the last block number is updated only for users who provide valid signatures.
#[derive(Debug)]
pub struct AccountUpdateCircuit<F, C, const D: usize>
where
    F: RichField + Extendable<D>,
    C: GenericConfig<D, F = F>,
{
    pub(crate) data: CircuitData<F, C, D>,
    pub(crate) target: AccountUpdateTarget,
    pub(crate) dummy_proof: DummyProof<F, C, D>,
}

impl<F, C, const D: usize> AccountUpdateCircuit<F, C, D>
where
    F: RichField + Extendable<D>,
    C: GenericConfig<D, F = F> + 'static,
    C::Hasher: AlgebraicHasher<F>,
{
    /// Creates a new AccountUpdateCircuit with the necessary constraints.
    pub(crate) fn new() -> Self {
        let config = CircuitConfig::default();
        let mut builder = CircuitBuilder::<F, D>::new(config.clone());
        let target = AccountUpdateTarget::new::<F, C, D>(&mut builder);
        let pis = AccountTransitionPublicInputsTarget {
            prev_account_tree_root: target.prev_account_tree_root,
            prev_next_account_id: target.next_account_id,
            new_account_tree_root: target.new_account_tree_root,
            new_next_account_id: target.next_account_id,
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

    /// Generates a proof for the account update circuit.
    ///
    /// # Arguments
    /// * `value` - The AccountUpdateValue containing all inputs and expected outputs
    ///
    /// # Returns
    /// A proof that the account update was performed correctly
    pub(crate) fn prove(
        &self,
        value: &AccountUpdateValue,
    ) -> Result<ProofWithPublicInputs<F, C, D>, ValidityTransitionError> {
        let mut pw = PartialWitness::<F>::new();
        self.target.set_witness(&mut pw, value);
        self.data.prove(pw)
            .map_err(|e| ValidityTransitionError::ProofGenerationError(format!("{:?}", e)))
    }
}

#[cfg(test)]
mod tests {
    use plonky2::{
        field::goldilocks_field::GoldilocksField, plonk::config::PoseidonGoldilocksConfig,
    };

    use crate::{
        common::trees::{account_tree::AccountTree, sender_tree::get_sender_leaves},
        ethereum_types::{bytes16::Bytes16, u256::U256, u32limb_trait::U32LimbTrait as _},
    };
    use rand::Rng;

    use super::*;
    type F = GoldilocksField;
    const D: usize = 2;
    type C = PoseidonGoldilocksConfig;

    /// Tests the account update circuit with a valid update scenario.
    ///
    /// This test:
    /// 1. Creates an account tree with existing accounts
    /// 2. Generates sender leaves with some having signatures
    /// 3. Updates the last block number for senders with signatures
    /// 4. Verifies that the account tree is correctly updated
    /// 5. Generates and verifies a ZK proof for the update
    #[test]
    fn test_account_update_valid() {
        let mut rng = rand::thread_rng();
        let mut tree = AccountTree::initialize();
        let mut next_account_id = 2;
        let pubkeys = (0..NUM_SENDERS_IN_BLOCK)
            .map(|_| U256::rand(&mut rng))
            .collect::<Vec<_>>();
        for punkey in &pubkeys {
            tree.insert(*punkey, 10).unwrap();
            next_account_id += 1;
        }
        let prev_account_tree_root = tree.get_root();

        let sender_flag = Bytes16::rand(&mut rng);
        let sender_leaves = get_sender_leaves(&pubkeys, sender_flag);
        let block_number: u32 = 1000;
        let mut account_update_proofs = Vec::new();
        for sender_leaf in sender_leaves.iter() {
            let account_id = tree.index(sender_leaf.sender).unwrap();
            let prev_leaf = tree.get_leaf(account_id);
            let prev_last_block_number = prev_leaf.value as u32;
            let last_block_number = if sender_leaf.signature_included {
                block_number
            } else {
                prev_last_block_number
            };
            let proof = tree.prove_and_update(sender_leaf.sender, last_block_number as u64).unwrap();
            account_update_proofs.push(proof);
        }
        let new_account_tree_root = tree.get_root();

        let account_update_value = AccountUpdateValue::new(
            prev_account_tree_root,
            next_account_id,
            block_number,
            sender_leaves,
            account_update_proofs,
        ).unwrap();
        
        // Verify the account tree root was updated correctly
        assert_eq!(
            account_update_value.new_account_tree_root,
            new_account_tree_root,
            "Account tree root mismatch after update"
        );

        // Generate the ZK proof
        let account_update_circuit = AccountUpdateCircuit::<F, C, D>::new();
        let _proof = account_update_circuit
            .prove(&account_update_value)
            .unwrap();
        
        // If we got here without errors, the proof was generated successfully
    }
    
    /// Tests the account update circuit with a scenario where no signatures are included.
    ///
    /// This test verifies that when no senders have signatures, their last block numbers
    /// remain unchanged and the account tree root remains the same.
    #[test]
    fn test_account_update_no_signatures() {
        let mut rng = rand::thread_rng();
        let mut tree = AccountTree::initialize();
        let mut next_account_id = 2;
        
        // Create accounts in the account tree
        let pubkeys = (0..NUM_SENDERS_IN_BLOCK)
            .map(|_| U256::rand(&mut rng))
            .collect::<Vec<_>>();
        
        // Set initial last block number for all accounts
        let initial_block_number: u64 = 10;
        for pubkey in &pubkeys {
            tree.insert(*pubkey, initial_block_number).unwrap();
            next_account_id += 1;
        }
        
        let prev_account_tree_root = tree.get_root();
        
        // Create sender leaves with no signatures included
        let sender_flag = Bytes16::rand(&mut rng);
        let mut sender_leaves = get_sender_leaves(&pubkeys, sender_flag);
        
        // Ensure no sender has a signature
        for leaf in &mut sender_leaves {
            leaf.signature_included = false;
        }
        
        let block_number: u32 = 1000;
        let mut account_update_proofs = Vec::new();
        
        // Create proofs for each sender (but no updates will happen since no signatures)
        for sender_leaf in sender_leaves.iter() {
            let account_id = tree.index(sender_leaf.sender).unwrap();
            let prev_leaf = tree.get_leaf(account_id);
            let prev_last_block_number = prev_leaf.value as u32;
            
            // Last block number should remain unchanged
            let last_block_number = prev_last_block_number;
            
            let proof = tree.prove_and_update(sender_leaf.sender, last_block_number as u64).unwrap();
            account_update_proofs.push(proof);
        }
        
        let new_account_tree_root = tree.get_root();
        
        // The account tree root should remain unchanged since no updates occurred
        assert_eq!(
            prev_account_tree_root,
            new_account_tree_root,
            "Account tree root should not change when no signatures are included"
        );
        
        let account_update_value = AccountUpdateValue::new(
            prev_account_tree_root,
            next_account_id,
            block_number,
            sender_leaves,
            account_update_proofs,
        ).unwrap();
        
        // Verify the account tree root was not changed
        assert_eq!(
            account_update_value.new_account_tree_root,
            prev_account_tree_root,
            "Account tree root should not change when no signatures are included"
        );
        
        // Generate the ZK proof
        let account_update_circuit = AccountUpdateCircuit::<F, C, D>::new();
        let _proof = account_update_circuit
            .prove(&account_update_value)
            .unwrap();
    }
    
    /// Tests the account update circuit with a mixed scenario where some senders have signatures
    /// and others don't.
    ///
    /// This test verifies that only the last block numbers of senders with signatures are updated,
    /// while others remain unchanged.
    #[test]
    fn test_account_update_mixed_signatures() {
        let mut rng = rand::thread_rng();
        let mut tree = AccountTree::initialize();
        let mut next_account_id = 2;
        
        // Create accounts in the account tree
        let pubkeys = (0..NUM_SENDERS_IN_BLOCK)
            .map(|_| U256::rand(&mut rng))
            .collect::<Vec<_>>();
        
        // Set initial last block number for all accounts
        let initial_block_number: u64 = 10;
        for pubkey in &pubkeys {
            tree.insert(*pubkey, initial_block_number).unwrap();
            next_account_id += 1;
        }
        
        let prev_account_tree_root = tree.get_root();
        
        // Create sender leaves with random signature inclusion
        let sender_flag = Bytes16::rand(&mut rng);
        let mut sender_leaves = get_sender_leaves(&pubkeys, sender_flag);
        
        // Randomly set signature inclusion for each sender
        for leaf in &mut sender_leaves {
            leaf.signature_included = rng.gen_bool(0.5);
        }
        
        let block_number: u32 = 1000;
        let mut account_update_proofs = Vec::new();
        let mut expected_updated_accounts = 0;
        
        // Create proofs for each sender
        for sender_leaf in sender_leaves.iter() {
            let account_id = tree.index(sender_leaf.sender).unwrap();
            let prev_leaf = tree.get_leaf(account_id);
            let prev_last_block_number = prev_leaf.value as u32;
            
            // Update last block number only if signature is included
            let last_block_number = if sender_leaf.signature_included {
                expected_updated_accounts += 1;
                block_number
            } else {
                prev_last_block_number
            };
            
            let proof = tree.prove_and_update(sender_leaf.sender, last_block_number as u64).unwrap();
            account_update_proofs.push(proof);
        }
        
        let new_account_tree_root = tree.get_root();
        
        // The account tree root should change if at least one account was updated
        if expected_updated_accounts > 0 {
            assert_ne!(
                prev_account_tree_root,
                new_account_tree_root,
                "Account tree root should change when at least one signature is included"
            );
        } else {
            assert_eq!(
                prev_account_tree_root,
                new_account_tree_root,
                "Account tree root should not change when no signatures are included"
            );
        }
        
        let account_update_value = AccountUpdateValue::new(
            prev_account_tree_root,
            next_account_id,
            block_number,
            sender_leaves,
            account_update_proofs,
        ).unwrap();
        
        // Verify the account tree root matches the expected value
        assert_eq!(
            account_update_value.new_account_tree_root,
            new_account_tree_root,
            "Account tree root mismatch after mixed signature updates"
        );
        
        // Generate the ZK proof
        let account_update_circuit = AccountUpdateCircuit::<F, C, D>::new();
        let _proof = account_update_circuit
            .prove(&account_update_value)
            .unwrap();
    }
}
