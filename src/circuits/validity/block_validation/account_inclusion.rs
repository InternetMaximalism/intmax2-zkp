//! Account inclusion circuit for non-registration block validation.
//!
//! This circuit ensures that for a given sender tree root, all senders are either:
//! 1. Included in the account tree (if signatures are included), or
//! 2. Do not have signatures included
//!
//! This constraint is used during non-registration block validation when a sender
//! makes a transaction for the second or subsequent time.

use crate::{
    circuits::validity::block_validation::{
        error::BlockValidationError, utils::get_pubkey_commitment,
    },
    common::trees::account_tree::{AccountMerkleProof, AccountMerkleProofTarget},
    constants::NUM_SENDERS_IN_BLOCK,
    ethereum_types::{
        account_id::{AccountIdPacked, AccountIdPackedTarget},
        bytes32::{Bytes32, Bytes32Target, BYTES32_LEN},
        u256::{U256Target, U256},
        u32limb_trait::{U32LimbTargetTrait, U32LimbTrait},
    },
    utils::{
        dummy::DummyProof,
        poseidon_hash_out::{PoseidonHashOut, PoseidonHashOutTarget},
    },
};
use plonky2::{
    field::{extension::Extendable, types::Field},
    gates::constant::ConstantGate,
    hash::hash_types::RichField,
    iop::{
        target::{BoolTarget, Target},
        witness::{PartialWitness, WitnessWrite},
    },
    plonk::{
        circuit_builder::CircuitBuilder,
        circuit_data::{CircuitConfig, CircuitData},
        config::{AlgebraicHasher, GenericConfig},
        proof::ProofWithPublicInputs,
    },
};

use super::utils::get_pubkey_commitment_circuit;

const ACCOUNT_INCLUSION_PUBLIC_INPUTS_LEN: usize = BYTES32_LEN + 4 + 4 + 1;

#[derive(Clone, Debug)]
pub struct AccountInclusionPublicInputs {
    pub account_id_hash: Bytes32,
    pub account_tree_root: PoseidonHashOut,
    pub pubkey_commitment: PoseidonHashOut,
    pub is_valid: bool,
}

#[derive(Clone, Debug)]
pub struct AccountInclusionPublicInputsTarget {
    pub account_id_hash: Bytes32Target,
    pub account_tree_root: PoseidonHashOutTarget,
    pub pubkey_commitment: PoseidonHashOutTarget,
    pub is_valid: BoolTarget,
}

impl AccountInclusionPublicInputs {
    pub fn from_u64_slice(input: &[u64]) -> Self {
        assert_eq!(input.len(), ACCOUNT_INCLUSION_PUBLIC_INPUTS_LEN);
        let account_id_hash = Bytes32::from_u64_slice(&input[0..8]).unwrap();
        let account_tree_root = PoseidonHashOut::from_u64_slice(&input[8..12]);
        let pubkey_commitment = PoseidonHashOut::from_u64_slice(&input[12..16]);
        let is_valid = input[16] == 1;
        Self {
            account_id_hash,
            account_tree_root,
            pubkey_commitment,
            is_valid,
        }
    }
}

impl AccountInclusionPublicInputsTarget {
    pub fn to_vec(&self) -> Vec<Target> {
        let vec = self
            .account_id_hash
            .to_vec()
            .into_iter()
            .chain(self.account_tree_root.elements)
            .chain(self.pubkey_commitment.elements)
            .chain([self.is_valid.target])
            .collect::<Vec<_>>();
        assert_eq!(vec.len(), ACCOUNT_INCLUSION_PUBLIC_INPUTS_LEN);
        vec
    }

    pub fn from_slice(input: &[Target]) -> Self {
        assert_eq!(input.len(), ACCOUNT_INCLUSION_PUBLIC_INPUTS_LEN);
        let account_id_hash = Bytes32Target::from_slice(&input[0..8]);
        let account_tree_root = PoseidonHashOutTarget {
            elements: input[8..12].try_into().unwrap(),
        };
        let pubkey_commitment = PoseidonHashOutTarget {
            elements: input[12..16].try_into().unwrap(),
        };
        let is_valid = BoolTarget::new_unsafe(input[16]);
        Self {
            account_id_hash,
            account_tree_root,
            pubkey_commitment,
            is_valid,
        }
    }
}

#[derive(Clone, Debug)]
pub struct AccountInclusionValue {
    pub account_id_packed: AccountIdPacked,
    pub account_id_hash: Bytes32,
    pub account_tree_root: PoseidonHashOut,
    pub account_merkle_proofs: Vec<AccountMerkleProof>,
    pub pubkeys: Vec<U256>,
    pub pubkey_commitment: PoseidonHashOut,
    pub is_valid: bool,
}

impl AccountInclusionValue {
    /// Creates a new AccountInclusionValue by validating that all senders in the sender tree
    /// satisfy the account inclusion constraint.
    ///
    /// The account inclusion constraint requires that for each sender:
    /// - If the sender has a signature included, it must be present in the account tree
    /// - If the sender is not in the account tree, it must NOT have a signature included
    ///
    /// This constraint is used for non-registration block validation when a sender makes a
    /// transaction for the second or subsequent time.
    pub fn new(
        account_tree_root: PoseidonHashOut,
        account_id_packed: AccountIdPacked,
        account_merkle_proofs: Vec<AccountMerkleProof>,
        pubkeys: Vec<U256>,
    ) -> Result<Self, BlockValidationError> {
        if account_merkle_proofs.len() != NUM_SENDERS_IN_BLOCK {
            return Err(BlockValidationError::AccountInclusionValue(format!(
                "Expected {} account merkle proofs, got {}",
                NUM_SENDERS_IN_BLOCK,
                account_merkle_proofs.len()
            )));
        }

        if pubkeys.len() != NUM_SENDERS_IN_BLOCK {
            return Err(BlockValidationError::AccountInclusionValue(format!(
                "Expected {} pubkeys, got {}",
                NUM_SENDERS_IN_BLOCK,
                pubkeys.len()
            )));
        }

        let mut result = true;
        let account_id_hash = account_id_packed.hash();
        let account_ids = account_id_packed.unpack();

        // Verify that all senders with signatures are included in the account tree
        for ((account_id, proof), pubkey) in account_ids
            .iter()
            .zip(account_merkle_proofs.iter())
            .zip(pubkeys.iter())
        {
            // Verify that the account is included in the account tree with the correct pubkey
            let is_valid_proof = proof.verify(account_tree_root, *account_id, *pubkey);
            result = result && is_valid_proof;
        }

        let pubkey_commitment = get_pubkey_commitment(&pubkeys);
        Ok(Self {
            account_id_packed,
            account_tree_root,
            account_merkle_proofs,
            pubkeys,
            account_id_hash,
            pubkey_commitment,
            is_valid: result,
        })
    }
}

#[derive(Clone, Debug)]
pub struct AccountInclusionTarget {
    pub account_id_packed: AccountIdPackedTarget,
    pub account_tree_root: PoseidonHashOutTarget,
    pub account_merkle_proofs: Vec<AccountMerkleProofTarget>,
    pub pubkeys: Vec<U256Target>,
    pub account_id_hash: Bytes32Target,
    pub pubkey_commitment: PoseidonHashOutTarget,
    pub is_valid: BoolTarget,
}

impl AccountInclusionTarget {
    /// Creates a new AccountInclusionTarget with circuit constraints that enforce the account
    /// inclusion rule.
    ///
    /// The account inclusion rule requires that for each sender in the sender tree:
    /// - If the sender has a signature included, it must be present in the account tree
    /// - If the sender is not in the account tree, it must NOT have a signature included
    ///
    /// This is used for non-registration block validation when a sender makes a transaction for the
    /// second or subsequent time.
    pub fn new<F: RichField + Extendable<D>, C: GenericConfig<D, F = F> + 'static, const D: usize>(
        builder: &mut CircuitBuilder<F, D>,
    ) -> Self
    where
        <C as GenericConfig<D>>::Hasher: AlgebraicHasher<F>,
    {
        let mut result = builder._true();
        let account_tree_root = PoseidonHashOutTarget::new(builder);
        let account_id_packed = AccountIdPackedTarget::new(builder, true);
        let account_merkle_proofs = (0..NUM_SENDERS_IN_BLOCK)
            .map(|_| AccountMerkleProofTarget::new(builder, true))
            .collect::<Vec<_>>();
        // The pubkey already exists in the account tree, so it has already been range
        // checked.
        let pubkeys = (0..NUM_SENDERS_IN_BLOCK)
            .map(|_| U256Target::new(builder, false))
            .collect::<Vec<_>>();
        let account_id_hash = account_id_packed.hash::<F, C, D>(builder);
        let account_ids = account_id_packed.unpack(builder);

        // For each sender, verify that it is included in the account tree with the correct pubkey
        for ((account_id, proof), pubkey) in account_ids
            .iter()
            .zip(account_merkle_proofs.iter())
            .zip(pubkeys.iter())
        {
            // Verify that the account is included in the account tree with the correct pubkey
            let is_proof_valid =
                proof.verify::<F, C, D>(builder, account_tree_root, *account_id, *pubkey);

            // Accumulate the result for all senders
            result = builder.and(result, is_proof_valid);
        }

        let pubkey_commitment = get_pubkey_commitment_circuit(builder, &pubkeys);
        Self {
            account_id_packed,
            account_tree_root,
            account_merkle_proofs,
            pubkeys,
            account_id_hash,
            pubkey_commitment,
            is_valid: result,
        }
    }

    pub fn set_witness<F: Field, W: WitnessWrite<F>>(
        &self,
        witness: &mut W,
        value: &AccountInclusionValue,
    ) {
        self.account_id_packed
            .set_witness(witness, value.account_id_packed);
        self.account_tree_root
            .set_witness(witness, value.account_tree_root);
        for (proof_t, proof) in self
            .account_merkle_proofs
            .iter()
            .zip(value.account_merkle_proofs.iter())
        {
            proof_t.set_witness(witness, proof);
        }
        for (pubkey_t, pubkey) in self.pubkeys.iter().zip(value.pubkeys.iter()) {
            pubkey_t.set_witness(witness, *pubkey);
        }
        self.account_id_hash
            .set_witness(witness, value.account_id_hash);
        self.pubkey_commitment
            .set_witness(witness, value.pubkey_commitment);
        witness.set_bool_target(self.is_valid, value.is_valid);
    }
}

#[derive(Debug)]
pub struct AccountInclusionCircuit<F, C, const D: usize>
where
    F: RichField + Extendable<D>,
    C: GenericConfig<D, F = F>,
{
    pub data: CircuitData<F, C, D>,
    pub target: AccountInclusionTarget,
    pub dummy_proof: DummyProof<F, C, D>,
}

impl<F, C, const D: usize> Default for AccountInclusionCircuit<F, C, D>
where
    F: RichField + Extendable<D>,
    C: GenericConfig<D, F = F> + 'static,
    C::Hasher: AlgebraicHasher<F>,
{
    fn default() -> Self {
        Self::new()
    }
}

impl<F, C, const D: usize> AccountInclusionCircuit<F, C, D>
where
    F: RichField + Extendable<D>,
    C: GenericConfig<D, F = F> + 'static,
    C::Hasher: AlgebraicHasher<F>,
{
    pub fn new() -> Self {
        let config = CircuitConfig::default();
        let mut builder = CircuitBuilder::<F, D>::new(config.clone());
        let target = AccountInclusionTarget::new::<F, C, D>(&mut builder);
        let pis = AccountInclusionPublicInputsTarget {
            account_id_hash: target.account_id_hash,
            account_tree_root: target.account_tree_root,
            pubkey_commitment: target.pubkey_commitment,
            is_valid: target.is_valid,
        };
        builder.register_public_inputs(&pis.to_vec());

        // Add a ConstantGate to create a dummy proof.
        builder.add_gate(ConstantGate::new(config.num_constants), vec![]);

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
        value: &AccountInclusionValue,
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
    use rand::Rng as _;

    use crate::{
        common::{signature_content::key_set::KeySet, trees::account_tree::AccountTree},
        constants::NUM_SENDERS_IN_BLOCK,
        ethereum_types::account_id::{AccountId, AccountIdPacked},
    };

    use super::{AccountInclusionCircuit, AccountInclusionValue};
    type F = GoldilocksField;
    const D: usize = 2;
    type C = PoseidonGoldilocksConfig;

    #[test]
    fn test_account_inclusion_valid_case() {
        let mut rng = rand::thread_rng();
        let mut tree = AccountTree::initialize();

        // Create and insert pubkeys into the account tree
        let mut pubkeys = Vec::new();
        for _ in 0..NUM_SENDERS_IN_BLOCK {
            let keyset = KeySet::rand(&mut rng);
            pubkeys.push(keyset.pubkey);
            let last_block_number = rng.gen();
            tree.insert(keyset.pubkey, last_block_number).unwrap();
        }

        // Create account IDs and proofs for each pubkey
        let mut account_ids = Vec::new();
        let mut account_merkle_proofs = Vec::new();
        for pubkey in &pubkeys {
            let account_id = AccountId(tree.index(*pubkey).unwrap());
            let proof = tree.prove_inclusion(account_id.0);
            account_ids.push(account_id);
            account_merkle_proofs.push(proof);
        }

        let account_tree_root = tree.get_root();
        let account_id_packed = AccountIdPacked::pack(&account_ids);

        // Create the account inclusion value
        let value = AccountInclusionValue::new(
            account_tree_root,
            account_id_packed,
            account_merkle_proofs,
            pubkeys,
        )
        .unwrap();

        // The value should be valid since all pubkeys are in the account tree
        assert!(value.is_valid);

        // Verify we can generate a valid proof
        let circuit = AccountInclusionCircuit::<F, C, D>::new();
        let _proof = circuit.prove(&value).unwrap();
    }

    #[test]
    fn test_account_inclusion_invalid_case() {
        let mut rng = rand::thread_rng();
        let mut tree = AccountTree::initialize();

        // Create and insert pubkeys into the account tree
        let mut pubkeys = Vec::new();
        for _ in 0..NUM_SENDERS_IN_BLOCK - 1 {
            let keyset = KeySet::rand(&mut rng);
            pubkeys.push(keyset.pubkey);
            let last_block_number = rng.gen();
            tree.insert(keyset.pubkey, last_block_number).unwrap();
        }

        // Add one more pubkey that we won't insert into the tree
        let invalid_keyset = KeySet::rand(&mut rng);
        let invalid_pubkey = invalid_keyset.pubkey;
        pubkeys.push(invalid_pubkey);

        // Create account IDs and proofs for each pubkey
        let mut account_ids = Vec::new();
        let mut account_merkle_proofs = Vec::new();

        for pubkey in &pubkeys {
            // For the invalid pubkey, we'll get an invalid proof
            let account_id = if *pubkey == invalid_pubkey {
                // Use a dummy account ID for the invalid pubkey
                AccountId(0)
            } else {
                AccountId(tree.index(*pubkey).unwrap())
            };

            let proof = tree.prove_inclusion(account_id.0);
            account_ids.push(account_id);
            account_merkle_proofs.push(proof);
        }

        let account_tree_root = tree.get_root();
        let account_id_packed = AccountIdPacked::pack(&account_ids);

        // Create the account inclusion value
        let value = AccountInclusionValue::new(
            account_tree_root,
            account_id_packed,
            account_merkle_proofs,
            pubkeys,
        )
        .unwrap();

        // The value should be invalid since one pubkey is not in the account tree
        assert!(!value.is_valid);
    }
}
