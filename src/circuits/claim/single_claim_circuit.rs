//! Single claim verification circuit for the claim process.
//!
//! This circuit proves that a deposit is eligible for claiming by:
//! 1. Verifying the deposit was included in a block (via deposit_time_proof)
//! 2. Verifying the required lock time has passed since the deposit
//! 3. Verifying no transfers occurred during the lock period (using account tree's last block
//!    number)
//! 4. Generating a claim target that can be used to claim the deposit
//!
//! The single claim circuit combines multiple proofs and verifications:
//! - Deposit time proof: Verifies when the deposit was included and calculates its lock time
//! - Validity proof: Verifies the current state of the system
//! - Block merkle proof: Verifies the deposit block is part of the block history
//! - Account membership proof: Verifies the account's last activity to ensure no transfers during
//!   lock period
use super::error::ClaimError;
use plonky2::{
    field::extension::Extendable,
    hash::hash_types::RichField,
    iop::{
        target::Target,
        witness::{PartialWitness, WitnessWrite},
    },
    plonk::{
        circuit_builder::CircuitBuilder,
        circuit_data::{CircuitConfig, CircuitData, VerifierCircuitData},
        config::{AlgebraicHasher, GenericConfig},
        proof::{ProofWithPublicInputs, ProofWithPublicInputsTarget},
    },
};

use crate::{
    circuits::{
        claim::deposit_time::{DepositTimePublicInputs, DepositTimePublicInputsTarget},
        validity::validity_pis::{ValidityPublicInputs, ValidityPublicInputsTarget},
    },
    common::{
        claim::ClaimTarget,
        trees::{
            account_tree::{AccountMembershipProof, AccountMembershipProofTarget},
            block_hash_tree::{BlockHashMerkleProof, BlockHashMerkleProofTarget},
        },
    },
    constants::{ACCOUNT_TREE_HEIGHT, BLOCK_HASH_TREE_HEIGHT},
    ethereum_types::{
        address::{Address, AddressTarget},
        bytes32::{Bytes32, Bytes32Target},
        u32limb_trait::U32LimbTargetTrait,
        u64::U64Target,
    },
    utils::{conversion::ToU64, recursively_verifiable::add_proof_target_and_verify},
};

/// Values needed for the single claim verification
///
/// Contains all the data required to prove that a deposit is eligible for claiming,
/// including proofs of deposit inclusion, lock time verification, and account activity.
#[derive(Debug, Clone)]
pub struct SingleClaimValue<
    F: RichField + Extendable<D>,
    C: GenericConfig<D, F = F>,
    const D: usize,
> {
    pub recipient: Address,  // Address that will receive the claimed funds
    pub block_hash: Bytes32, // Hash of the current block
    pub block_number: u32,   // Number of the current block
    pub block_merkle_proof: BlockHashMerkleProof, /* Proof that the deposit block is part of the
                              * block history */
    pub account_membership_proof: AccountMembershipProof, // Proof of the account's last activity
    pub validity_proof: ProofWithPublicInputs<F, C, D>,   // Proof of the current system state
    pub deposit_time_proof: ProofWithPublicInputs<F, C, D>, /* Proof of when the deposit was
                                                           * included */
}

impl<F: RichField + Extendable<D>, C: GenericConfig<D, F = F>, const D: usize>
    SingleClaimValue<F, C, D>
{
    /// Creates a new SingleClaimValue by verifying all the proofs and conditions
    /// required for a valid claim.
    ///
    /// This function:
    /// 1. Verifies the validity proof (current system state)
    /// 2. Verifies the deposit time proof (when deposit was included)
    /// 3. Verifies the block merkle proof (deposit block is part of history)
    /// 4. Verifies the account membership proof (account's last activity)
    /// 5. Checks that the deposit block number is greater than the account's last block number
    ///    (ensuring no transfers occurred during the lock period)
    /// 6. Checks that the required lock time has passed since the deposit
    ///
    /// # Arguments
    /// * `validity_vd` - Verifier data for the validity proof
    /// * `deposit_time_vd` - Verifier data for the deposit time proof
    /// * `recipient` - Address that will receive the claimed funds
    /// * `block_merkle_proof` - Proof that the deposit block is part of the block history
    /// * `account_membership_proof` - Proof of the account's last activity
    /// * `validity_proof` - Proof of the current system state
    /// * `deposit_time_proof` - Proof of when the deposit was included
    ///
    /// # Returns
    /// A Result containing either the new SingleClaimValue or an error
    pub fn new(
        validity_vd: &VerifierCircuitData<F, C, D>,
        deposit_time_vd: &VerifierCircuitData<F, C, D>,
        recipient: Address,
        block_merkle_proof: &BlockHashMerkleProof,
        account_membership_proof: &AccountMembershipProof,
        validity_proof: &ProofWithPublicInputs<F, C, D>,
        deposit_time_proof: &ProofWithPublicInputs<F, C, D>,
    ) -> Result<Self, ClaimError> {
        validity_vd.verify(validity_proof.clone()).map_err(|e| {
            ClaimError::VerificationFailed(format!("Validity proof is invalid: {:?}", e))
        })?;

        let validity_pis = ValidityPublicInputs::from_pis(&validity_proof.public_inputs)
            .map_err(|e| {
                ClaimError::InvalidInput(format!("Failed to parse validity public inputs: {}", e))
            })?;

        deposit_time_vd
            .verify(deposit_time_proof.clone())
            .map_err(|e| {
                ClaimError::VerificationFailed(format!("Deposit time proof is invalid: {:?}", e))
            })?;

        let deposit_time_pis =
            DepositTimePublicInputs::from_u64_slice(&deposit_time_proof.public_inputs.to_u64_vec())
                .map_err(|e| {
                    ClaimError::InvalidInput(format!(
                        "Failed to parse deposit time public inputs: {}",
                        e
                    ))
                })?;

        block_merkle_proof
            .verify(
                &deposit_time_pis.block_hash,
                deposit_time_pis.block_number as u64,
                validity_pis.public_state.block_tree_root,
            )
            .map_err(|e| {
                ClaimError::VerificationFailed(format!("Block merkle proof is invalid: {:?}", e))
            })?;

        account_membership_proof
            .verify(
                deposit_time_pis.pubkey,
                validity_pis.public_state.account_tree_root,
            )
            .map_err(|e| {
                ClaimError::VerificationFailed(format!(
                    "Account membership proof is invalid: {:?}",
                    e
                ))
            })?;

        let last_block_number = account_membership_proof.get_value() as u32;

        if deposit_time_pis.block_number <= last_block_number {
            return Err(ClaimError::InvalidBlockNumber(format!(
                "Last block number {} of the account is not older than the deposit block number {}",
                last_block_number, deposit_time_pis.block_number
            )));
        }

        if validity_pis.public_state.timestamp
            < deposit_time_pis.block_timestamp + (deposit_time_pis.lock_time as u64)
        {
            return Err(ClaimError::InvalidLockTime(format!(
                "Lock time is not passed yet. Deposit time: {}, lock time: {}, current time: {}",
                deposit_time_pis.block_timestamp,
                deposit_time_pis.lock_time,
                validity_pis.public_state.timestamp
            )));
        }

        let block_hash = validity_pis.public_state.block_hash;
        let block_number = validity_pis.public_state.block_number;

        Ok(Self {
            recipient,
            block_hash,
            block_number,
            block_merkle_proof: block_merkle_proof.clone(),
            account_membership_proof: account_membership_proof.clone(),
            validity_proof: validity_proof.clone(),
            deposit_time_proof: deposit_time_proof.clone(),
        })
    }
}

/// Target version of SingleClaimValue for use in ZKP circuits
///
/// Contains circuit targets for all components needed to verify a claim's
/// eligibility and generate a claim target for the deposit.
#[derive(Debug, Clone)]
pub struct SingleClaimTarget<const D: usize> {
    pub recipient: AddressTarget,  // Target for recipient address
    pub block_hash: Bytes32Target, // Target for current block hash
    pub block_number: Target,      // Target for current block number
    pub block_merkle_proof: BlockHashMerkleProofTarget, // Target for block merkle proof
    pub account_membership_proof: AccountMembershipProofTarget, /* Target for account membership
                                    * proof */
    pub validity_proof: ProofWithPublicInputsTarget<D>, // Target for validity proof
    pub deposit_time_proof: ProofWithPublicInputsTarget<D>, // Target for deposit time proof
}

impl<const D: usize> SingleClaimTarget<D> {
    /// Creates a new SingleClaimTarget with circuit constraints that enforce
    /// the claim verification rules.
    ///
    /// The circuit enforces:
    /// 1. Validity of the validity proof (current system state)
    /// 2. Validity of the deposit time proof (when deposit was included)
    /// 3. Validity of the block merkle proof (deposit block is part of history)
    /// 4. Validity of the account membership proof (account's last activity)
    /// 5. That the deposit block number is greater than the account's last block number (ensuring
    ///    no transfers occurred during the lock period)
    /// 6. That the required lock time has passed since the deposit
    ///
    /// # Arguments
    /// * `validity_vd` - Verifier data for the validity proof
    /// * `deposit_time_vd` - Verifier data for the deposit time proof
    /// * `builder` - Circuit builder
    /// * `is_checked` - Whether to add constraints for checking the values
    ///
    /// # Returns
    /// A new SingleClaimTarget with all necessary targets and constraints
    pub fn new<F: RichField + Extendable<D>, C: GenericConfig<D, F = F> + 'static>(
        validity_vd: &VerifierCircuitData<F, C, D>,
        deposit_time_vd: &VerifierCircuitData<F, C, D>,
        builder: &mut CircuitBuilder<F, D>,
        is_checked: bool,
    ) -> Self
    where
        <C as GenericConfig<D>>::Hasher: AlgebraicHasher<F>,
    {
        let validity_proof = add_proof_target_and_verify(validity_vd, builder);
        let deposit_time_proof = add_proof_target_and_verify(deposit_time_vd, builder);
        let validity_pis = ValidityPublicInputsTarget::from_pis(&validity_proof.public_inputs);
        let deposit_time_pis =
            DepositTimePublicInputsTarget::from_slice(&deposit_time_proof.public_inputs);

        let block_merkle_proof = BlockHashMerkleProofTarget::new(builder, BLOCK_HASH_TREE_HEIGHT);
        let account_membership_proof =
            AccountMembershipProofTarget::new(builder, ACCOUNT_TREE_HEIGHT, is_checked);
        block_merkle_proof.verify::<F, C, D>(
            builder,
            &deposit_time_pis.block_hash,
            deposit_time_pis.block_number,
            validity_pis.public_state.block_tree_root,
        );
        account_membership_proof.verify::<F, C, D>(
            builder,
            deposit_time_pis.pubkey,
            validity_pis.public_state.account_tree_root,
        );
        let last_block_number = account_membership_proof.get_value(builder);
        // assert last_block_number < deposit_time_pis.block_number
        let diff = builder.sub(deposit_time_pis.block_number, last_block_number);
        builder.range_check(diff, 32);
        let zero = builder.zero();
        let is_diff_zero = builder.is_equal(diff, zero);
        builder.assert_zero(is_diff_zero.target);

        let lock_time = U64Target::from_u32_target(builder, deposit_time_pis.lock_time);
        let maturity = deposit_time_pis.block_timestamp.add(builder, &lock_time);
        let is_mature = maturity.is_le(builder, &validity_pis.public_state.timestamp);
        builder.assert_one(is_mature.target);

        let block_hash = validity_pis.public_state.block_hash;
        let block_number = validity_pis.public_state.block_number;

        let recipient = AddressTarget::new(builder, is_checked);

        Self {
            recipient,
            block_hash,
            block_number,
            block_merkle_proof,
            account_membership_proof,
            validity_proof,
            deposit_time_proof,
        }
    }

    pub fn set_witness<
        W: WitnessWrite<F>,
        F: RichField + Extendable<D>,
        C: GenericConfig<D, F = F>,
    >(
        &self,
        witness: &mut W,
        value: &SingleClaimValue<F, C, D>,
    ) where
        <C as GenericConfig<D>>::Hasher: AlgebraicHasher<F>,
    {
        self.recipient.set_witness(witness, value.recipient);
        self.block_hash.set_witness(witness, value.block_hash);
        witness.set_target(self.block_number, F::from_canonical_u32(value.block_number));
        self.block_merkle_proof
            .set_witness(witness, &value.block_merkle_proof);
        self.account_membership_proof
            .set_witness(witness, &value.account_membership_proof);
        witness.set_proof_with_pis_target(&self.validity_proof, &value.validity_proof);
        witness.set_proof_with_pis_target(&self.deposit_time_proof, &value.deposit_time_proof);
    }
}

/// Circuit for verifying claim eligibility and generating claim targets
///
/// This circuit combines the deposit time proof and validity proof to verify that:
/// 1. A deposit was included in a block
/// 2. The required lock time has passed since the deposit
/// 3. No transfers occurred during the lock period (using account tree's last block number)
///
/// It then generates a claim target that can be used to claim the deposit.
#[derive(Debug)]
pub struct SingleClaimCircuit<F, C, const D: usize>
where
    F: RichField + Extendable<D>,
    C: GenericConfig<D, F = F>,
{
    pub data: CircuitData<F, C, D>,
    pub target: SingleClaimTarget<D>,
}

impl<F, C, const D: usize> SingleClaimCircuit<F, C, D>
where
    F: RichField + Extendable<D>,
    C: GenericConfig<D, F = F> + 'static,
    C::Hasher: AlgebraicHasher<F>,
{
    pub fn new(
        validity_vd: &VerifierCircuitData<F, C, D>,
        deposit_time_vd: &VerifierCircuitData<F, C, D>,
    ) -> Self {
        let mut builder =
            CircuitBuilder::<F, D>::new(CircuitConfig::standard_recursion_zk_config());
        let target = SingleClaimTarget::new(validity_vd, deposit_time_vd, &mut builder, true);
        let deposit_time_pis =
            DepositTimePublicInputsTarget::from_slice(&target.deposit_time_proof.public_inputs);
        let claim = ClaimTarget {
            recipient: target.recipient,
            amount: deposit_time_pis.deposit_amount,
            nullifier: deposit_time_pis.nullifier,
            block_hash: target.block_hash,
            block_number: target.block_number,
        };
        builder.register_public_inputs(&claim.to_vec());
        let data = builder.build();
        Self { data, target }
    }

    pub fn prove(
        &self,
        value: &SingleClaimValue<F, C, D>,
    ) -> Result<ProofWithPublicInputs<F, C, D>, ClaimError> {
        let mut pw = PartialWitness::<F>::new();
        self.target.set_witness(&mut pw, value);
        self.data
            .prove(pw)
            .map_err(|e| ClaimError::ProofGenerationError(format!("{:?}", e)))
    }

    pub fn verify(&self, proof: &ProofWithPublicInputs<F, C, D>) -> Result<(), ClaimError> {
        self.data.verify(proof.clone()).map_err(|e| {
            ClaimError::VerificationFailed(format!("Proof verification failed: {:?}", e))
        })
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use crate::{
        circuits::{
            claim::{deposit_time::DepositTimeCircuit, determine_lock_time::LockTimeConfig},
            test_utils::state_manager::ValidityStateManager,
            validity::validity_processor::ValidityProcessor,
        },
        common::{
            deposit::{get_pubkey_salt_hash, Deposit},
            salt::Salt,
            signature_content::key_set::KeySet,
            witness::deposit_time_witness::DepositTimeWitness,
        },
        ethereum_types::{address::Address, u256::U256, u32limb_trait::U32LimbTrait},
    };
    use plonky2::{
        field::goldilocks_field::GoldilocksField, plonk::config::PoseidonGoldilocksConfig,
    };
    use rand::Rng as _;

    use super::{SingleClaimCircuit, SingleClaimValue};

    type F = GoldilocksField;
    type C = PoseidonGoldilocksConfig;
    const D: usize = 2;

    #[test]
    fn test_single_claim_circuit() {
        let lock_config = LockTimeConfig::normal();

        let mut rng = rand::thread_rng();
        let validity_processor = Arc::new(ValidityProcessor::<F, C, D>::new());
        let mut validity_state_manager =
            ValidityStateManager::new(validity_processor.clone(), Address::default());
        let key = KeySet::rand(&mut rng);

        // deposit
        let deposit_salt = Salt::rand(&mut rng);
        let deposit_salt_hash = get_pubkey_salt_hash(key.pubkey, deposit_salt);
        let deposit = Deposit {
            depositor: Address::rand(&mut rng),
            pubkey_salt_hash: deposit_salt_hash,
            amount: U256::rand_small(&mut rng),
            token_index: rng.gen(),
            is_eligible: true,
        };
        let deposit_index = validity_state_manager.deposit(&deposit).unwrap();

        // post empty block to sync deposit tree
        validity_state_manager.tick(false, &[], 0, 0).unwrap();

        // lock time max passed in this block
        validity_state_manager
            .tick(false, &[], 0, lock_config.lock_time_max as u64)
            .unwrap();

        let update_witness = validity_state_manager
            .get_update_witness(key.pubkey, 2, 1, false)
            .unwrap();
        let deposit_time_public_witness = validity_state_manager
            .get_deposit_time_public_witness(1, deposit_index)
            .unwrap();

        let deposit_time_witness = DepositTimeWitness {
            public_witness: deposit_time_public_witness,
            deposit_index,
            deposit,
            deposit_salt,
            pubkey: key.pubkey,
        };
        let deposit_time_value = deposit_time_witness.to_value(&lock_config).unwrap();

        let deposit_time_circuit = DepositTimeCircuit::<F, C, D>::new(&lock_config);
        let deposit_time_proof = deposit_time_circuit.prove(&deposit_time_value).unwrap();

        let single_claim_value = SingleClaimValue::new(
            &validity_processor.get_verifier_data(),
            &deposit_time_circuit.data.verifier_data(),
            Address::rand(&mut rng),
            &update_witness.block_merkle_proof,
            &update_witness.account_membership_proof,
            &update_witness.validity_proof,
            &deposit_time_proof,
        )
        .unwrap();

        let single_claim_circuit = SingleClaimCircuit::<F, C, D>::new(
            &validity_processor.get_verifier_data(),
            &deposit_time_circuit.data.verifier_data(),
        );

        let single_claim_proof = single_claim_circuit.prove(&single_claim_value).unwrap();
        single_claim_circuit.verify(&single_claim_proof).unwrap();
    }
}
