//! Account exclusion circuit for registration block validation.
//!
//! This circuit ensures that for a given sender tree root, all senders are either:
//! 1. Not included in the account tree (if signatures are included), or
//! 2. Do not have signatures included
//!
//! This constraint is used during registration block validation when a sender
//! makes a transaction for the first time.

use plonky2::{
    field::extension::Extendable,
    hash::hash_types::RichField,
    iop::{
        target::{BoolTarget, Target},
        witness::{PartialWitness, Witness},
    },
    plonk::{
        circuit_builder::CircuitBuilder,
        circuit_data::{CircuitConfig, CircuitData},
        config::{AlgebraicHasher, GenericConfig},
        proof::ProofWithPublicInputs,
    },
};

use crate::{
    circuits::validity::block_validation::error::BlockValidationError,
    common::trees::{
        account_tree::{AccountMembershipProof, AccountMembershipProofTarget},
        sender_tree::{SenderLeaf, SenderLeafTarget},
    },
    constants::{ACCOUNT_TREE_HEIGHT, NUM_SENDERS_IN_BLOCK, SENDER_TREE_HEIGHT},
    utils::{
        dummy::DummyProof,
        poseidon_hash_out::{PoseidonHashOut, PoseidonHashOutTarget, POSEIDON_HASH_OUT_LEN},
        trees::get_root::{get_merkle_root_from_leaves, get_merkle_root_from_leaves_circuit},
    },
};

const ACCOUNT_EXCLUSION_PUBLIC_INPUTS_LEN: usize = 2 * POSEIDON_HASH_OUT_LEN + 1;

#[derive(Clone, Debug)]
pub struct AccountExclusionPublicInputs {
    pub account_tree_root: PoseidonHashOut,
    pub sender_tree_root: PoseidonHashOut,
    pub is_valid: bool,
}

#[derive(Clone, Debug)]
pub struct AccountExclusionPublicInputsTarget {
    pub account_tree_root: PoseidonHashOutTarget,
    pub sender_tree_root: PoseidonHashOutTarget,
    pub is_valid: BoolTarget,
}

impl AccountExclusionPublicInputs {
    pub fn from_u64_slice(input: &[u64]) -> Self {
        assert_eq!(input.len(), ACCOUNT_EXCLUSION_PUBLIC_INPUTS_LEN);
        let account_tree_root = PoseidonHashOut::from_u64_slice(&input[0..4])
            .unwrap_or_else(|e| panic!("Failed to create PoseidonHashOut from u64 slice: {}", e));
        let sender_tree_root = PoseidonHashOut::from_u64_slice(&input[4..8])
            .unwrap_or_else(|e| panic!("Failed to create PoseidonHashOut from u64 slice: {}", e));
        let is_valid = input[8] == 1;
        Self {
            account_tree_root,
            sender_tree_root,
            is_valid,
        }
    }
}

impl AccountExclusionPublicInputsTarget {
    pub fn to_vec(&self) -> Vec<Target> {
        let vec = self
            .account_tree_root
            .elements
            .into_iter()
            .chain(self.sender_tree_root.elements)
            .chain([self.is_valid.target])
            .collect::<Vec<_>>();
        assert_eq!(vec.len(), ACCOUNT_EXCLUSION_PUBLIC_INPUTS_LEN);
        vec
    }

    pub fn from_slice(input: &[Target]) -> Self {
        assert_eq!(input.len(), ACCOUNT_EXCLUSION_PUBLIC_INPUTS_LEN);
        let account_tree_root = PoseidonHashOutTarget::from_slice(&input[0..4]);
        let sender_tree_root = PoseidonHashOutTarget::from_slice(&input[4..8]);
        let is_valid = BoolTarget::new_unsafe(input[8]);
        Self {
            account_tree_root,
            sender_tree_root,
            is_valid,
        }
    }
}

#[derive(Clone, Debug)]
pub struct AccountExclusionValue {
    pub account_tree_root: PoseidonHashOut,
    pub account_membership_proofs: Vec<AccountMembershipProof>,
    pub sender_leaves: Vec<SenderLeaf>,
    pub sender_tree_root: PoseidonHashOut,
    pub is_valid: bool,
}

impl AccountExclusionValue {
    /// Creates a new AccountExclusionValue by validating that all senders in the sender tree
    /// satisfy the account exclusion constraint.
    ///
    /// The account exclusion constraint requires that for each sender:
    /// - If the sender has a signature included, it must NOT be present in the account tree
    /// - If the sender is already in the account tree, it must NOT have a signature included
    ///
    /// This constraint is used for registration block validation when a sender makes a transaction
    /// for the first time.
    pub fn new(
        account_tree_root: PoseidonHashOut,
        account_membership_proofs: Vec<AccountMembershipProof>,
        sender_leaves: Vec<SenderLeaf>,
    ) -> Result<Self, BlockValidationError> {
        if account_membership_proofs.len() != sender_leaves.len() {
            return Err(BlockValidationError::AccountExclusionValue(format!(
                "Mismatched lengths: {} account membership proofs, {} sender leaves",
                account_membership_proofs.len(),
                sender_leaves.len()
            )));
        }

        if sender_leaves.len() != NUM_SENDERS_IN_BLOCK {
            return Err(BlockValidationError::AccountExclusionValue(format!(
                "Expected {} sender leaves, got {}",
                NUM_SENDERS_IN_BLOCK,
                sender_leaves.len()
            )));
        }

        let mut result = true;
        for (sender_leaf, proof) in sender_leaves.iter().zip(account_membership_proofs.iter()) {
            proof
                .verify(sender_leaf.sender, account_tree_root)
                .map_err(|e| {
                    BlockValidationError::AccountExclusionValue(format!(
                        "Failed to verify account membership proof: {}",
                        e
                    ))
                })?;

            // For each sender, the constraint is satisfied if either:
            // 1. The sender is not in the account tree (proof.is_included == false) and has a
            //    signature, or
            // 2. The sender does not have a signature included (regardless of account tree
            //    inclusion)
            let is_valid = !proof.is_included || !sender_leaf.signature_included;
            result = result && is_valid;
        }

        let sender_tree_root = get_merkle_root_from_leaves(SENDER_TREE_HEIGHT, &sender_leaves)
            .map_err(|e| {
                BlockValidationError::AccountExclusionValue(format!(
                    "Failed to get merkle root from leaves: {}",
                    e
                ))
            })?;

        Ok(Self {
            account_tree_root,
            account_membership_proofs,
            sender_leaves,
            sender_tree_root,
            is_valid: result,
        })
    }
}

#[derive(Clone, Debug)]
pub struct AccountExclusionTarget {
    pub account_tree_root: PoseidonHashOutTarget,
    pub account_membership_proofs: Vec<AccountMembershipProofTarget>,
    pub sender_leaves: Vec<SenderLeafTarget>,
    pub sender_tree_root: PoseidonHashOutTarget,
    pub is_valid: BoolTarget,
}

impl AccountExclusionTarget {
    /// Creates a new AccountExclusionTarget with circuit constraints that enforce the account
    /// exclusion rule.
    ///
    /// The account exclusion rule requires that for each sender in the sender tree:
    /// - If the sender has a signature included, it must NOT be present in the account tree
    /// - If the sender is already in the account tree, it must NOT have a signature included
    ///
    /// This is used for registration block validation when a sender makes a transaction for the
    /// first time.
    pub fn new<F: RichField + Extendable<D>, C: GenericConfig<D, F = F> + 'static, const D: usize>(
        builder: &mut CircuitBuilder<F, D>,
    ) -> Self
    where
        <C as GenericConfig<D>>::Hasher: AlgebraicHasher<F>,
    {
        let mut result = builder._true();
        let account_tree_root = PoseidonHashOutTarget::new(builder);

        let account_membership_proofs = (0..NUM_SENDERS_IN_BLOCK)
            .map(|_| AccountMembershipProofTarget::new(builder, ACCOUNT_TREE_HEIGHT, true))
            .collect::<Vec<_>>();
        let sender_leaves = (0..NUM_SENDERS_IN_BLOCK)
            .map(|_| SenderLeafTarget::new(builder, true))
            .collect::<Vec<_>>();

        for (sender_leaf, proof) in sender_leaves.iter().zip(account_membership_proofs.iter()) {
            proof.verify::<F, C, D>(builder, sender_leaf.sender, account_tree_root);

            // Constraint logic:
            // 1. sender_not_in_account_tree = !proof.is_included
            let sender_not_in_account_tree = builder.not(proof.is_included);

            // 2. sender_not_in_tree_with_signature = sender_not_in_account_tree &&
            //    sender_leaf.signature_included
            let sender_not_in_tree_with_signature =
                builder.and(sender_not_in_account_tree, sender_leaf.signature_included);

            // 3. sender_has_no_signature = !sender_leaf.signature_included
            let sender_has_no_signature = builder.not(sender_leaf.signature_included);

            // 4. Valid if: (sender not in tree AND has signature) OR (sender has no signature)
            let is_valid = builder.or(sender_not_in_tree_with_signature, sender_has_no_signature);

            // Accumulate the result for all senders
            result = builder.and(result, is_valid);
        }

        let sender_tree_root = get_merkle_root_from_leaves_circuit::<F, C, D, _>(
            builder,
            SENDER_TREE_HEIGHT,
            &sender_leaves,
        );

        Self {
            account_tree_root,
            account_membership_proofs,
            sender_leaves,
            sender_tree_root,
            is_valid: result,
        }
    }

    pub fn set_witness<F: RichField, W: Witness<F>>(
        &self,
        witness: &mut W,
        value: &AccountExclusionValue,
    ) {
        self.account_tree_root
            .set_witness(witness, value.account_tree_root);
        for (proof_t, proof) in self
            .account_membership_proofs
            .iter()
            .zip(value.account_membership_proofs.iter())
        {
            proof_t.set_witness(witness, proof);
        }
        for (sender_leaf_t, sender_leaf) in
            self.sender_leaves.iter().zip(value.sender_leaves.iter())
        {
            sender_leaf_t.set_witness(witness, sender_leaf);
        }
        self.sender_tree_root
            .set_witness(witness, value.sender_tree_root);
        witness.set_bool_target(self.is_valid, value.is_valid);
    }
}

#[derive(Debug)]
pub struct AccountExclusionCircuit<F, C, const D: usize>
where
    F: RichField + Extendable<D>,
    C: GenericConfig<D, F = F>,
{
    pub data: CircuitData<F, C, D>,
    pub target: AccountExclusionTarget,
    pub dummy_proof: DummyProof<F, C, D>,
}

impl<F, C, const D: usize> Default for AccountExclusionCircuit<F, C, D>
where
    F: RichField + Extendable<D>,
    C: GenericConfig<D, F = F> + 'static,
    C::Hasher: AlgebraicHasher<F>,
{
    fn default() -> Self {
        Self::new()
    }
}

impl<F, C, const D: usize> AccountExclusionCircuit<F, C, D>
where
    F: RichField + Extendable<D>,
    C: GenericConfig<D, F = F> + 'static,
    C::Hasher: AlgebraicHasher<F>,
{
    pub fn new() -> Self {
        let mut builder = CircuitBuilder::<F, D>::new(CircuitConfig::default());
        let target = AccountExclusionTarget::new::<F, C, D>(&mut builder);
        let pis = AccountExclusionPublicInputsTarget {
            account_tree_root: target.account_tree_root,
            sender_tree_root: target.sender_tree_root,
            is_valid: target.is_valid,
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

    pub fn prove(
        &self,
        value: &AccountExclusionValue,
    ) -> Result<ProofWithPublicInputs<F, C, D>, BlockValidationError> {
        let mut pw = PartialWitness::<F>::new();
        self.target.set_witness(&mut pw, value);
        self.data
            .prove(pw)
            .map_err(|e| BlockValidationError::Plonky2Error(e.to_string()))
    }
}

#[cfg(test)]
mod tests {
    use plonky2::{
        field::goldilocks_field::GoldilocksField, plonk::config::PoseidonGoldilocksConfig,
    };

    use crate::{
        common::{signature_content::key_set::KeySet, trees::account_tree::AccountTree},
        constants::NUM_SENDERS_IN_BLOCK,
        ethereum_types::u256::U256,
    };
    use rand::Rng;

    use super::*;

    type F = GoldilocksField;
    const D: usize = 2;
    type C = PoseidonGoldilocksConfig;

    #[test]
    fn test_account_exclusion_valid_cases() {
        let mut rng = rand::thread_rng();
        let mut tree = AccountTree::initialize();

        // Insert some accounts into the account tree
        for _ in 0..100 {
            let keyset = KeySet::rand(&mut rng);
            let last_block_number = rng.gen();
            tree.insert(keyset.pubkey, last_block_number).unwrap();
        }
        let account_tree_root = tree.get_root();

        // Create random pubkeys for senders
        let mut pubkeys = (0..10).map(|_| U256::rand(&mut rng)).collect::<Vec<_>>();
        pubkeys.resize(NUM_SENDERS_IN_BLOCK, U256::dummy_pubkey());

        // Create valid sender leaves and proofs that satisfy the account exclusion constraint
        let mut account_membership_proofs = Vec::new();
        let mut sender_leaves = Vec::new();
        for pubkey in pubkeys.iter() {
            let proof = tree.prove_membership(*pubkey);

            // Ensure we satisfy the constraint:
            // - If in account tree (proof.is_included == true), don't include signature
            // - If not in account tree, can include signature or not
            let signature_included = if proof.is_included {
                false // No signature if already in account tree
            } else {
                rng.gen() && !pubkey.is_dummy_pubkey() // Random for new accounts
            };

            account_membership_proofs.push(proof);
            let sender_leaf = SenderLeaf {
                sender: *pubkey,
                signature_included,
            };
            sender_leaves.push(sender_leaf);
        }

        let value =
            AccountExclusionValue::new(account_tree_root, account_membership_proofs, sender_leaves)
                .unwrap();

        // The value should be valid since we constructed it to satisfy the constraint
        assert!(value.is_valid);

        // Verify we can generate a valid proof
        let circuit = AccountExclusionCircuit::<F, C, D>::new();
        let _proof = circuit.prove(&value).unwrap();
    }

    #[test]
    fn test_account_exclusion_invalid_case() {
        let mut rng = rand::thread_rng();
        let mut tree = AccountTree::initialize();

        // Insert some accounts into the account tree
        for _ in 0..100 {
            let keyset = KeySet::rand(&mut rng);
            let last_block_number = rng.gen();
            tree.insert(keyset.pubkey, last_block_number).unwrap();
        }

        // Insert one more account that we'll use to create an invalid case
        let special_keyset = KeySet::rand(&mut rng);
        let special_pubkey = special_keyset.pubkey;
        let last_block_number = rng.gen();
        tree.insert(special_pubkey, last_block_number).unwrap();

        let account_tree_root = tree.get_root();

        // Create random pubkeys for senders
        let mut pubkeys = (0..NUM_SENDERS_IN_BLOCK - 1)
            .map(|_| U256::rand(&mut rng))
            .collect::<Vec<_>>();
        // Add our special pubkey that's already in the account tree
        pubkeys.push(special_pubkey);

        let mut account_membership_proofs = Vec::new();
        let mut sender_leaves = Vec::new();

        for (i, pubkey) in pubkeys.iter().enumerate() {
            let proof = tree.prove_membership(*pubkey);

            // For the special pubkey (last one), we'll violate the constraint by including a
            // signature even though it's already in the account tree
            let signature_included = if i == pubkeys.len() - 1 {
                true // This violates the constraint!
            } else {
                !proof.is_included || rng.gen::<bool>() // Valid for other pubkeys
            };

            account_membership_proofs.push(proof);
            let sender_leaf = SenderLeaf {
                sender: *pubkey,
                signature_included,
            };
            sender_leaves.push(sender_leaf);
        }

        let value =
            AccountExclusionValue::new(account_tree_root, account_membership_proofs, sender_leaves)
                .unwrap();

        // The value should be invalid since we constructed it to violate the constraint
        assert!(!value.is_valid);
    }
}
