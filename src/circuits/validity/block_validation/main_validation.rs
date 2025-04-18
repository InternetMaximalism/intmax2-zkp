//! Main validation circuit for block validation.
//!
//! This circuit handles the non-state-transition parts of block validity verification:
//! 1. Account exclusion (for registration blocks): Verifies accounts didn't exist previously
//! 2. Account inclusion (for non-registration blocks): Verifies accounts existed previously
//! 3. Format validation: Verifies pubkeys are valid G1 x-coordinates, are strictly descending
//!    (ensuring no duplicate accounts), and message points are correctly calculated
//! 4. Aggregation: Verifies the weighted public key aggregation is correctly computed
//!
//! The main validation circuit must be able to generate ZKPs for any contract-submittable block,
//! and is_valid must be deterministically calculated regardless of the block content or
//! ZKP generation method.

use crate::{
    circuits::validity::block_validation::error::BlockValidationError,
    common::{
        signature_content::utils::get_pubkey_hash_circuit,
        trees::sender_tree::{get_sender_tree_root, get_sender_tree_root_circuit},
    },
    ethereum_types::{
        bytes32::{Bytes32Target, BYTES32_LEN},
        u256::U256Target,
        u32limb_trait::U32LimbTrait as _,
        u64::{U64Target, U64, U64_LEN},
    },
    utils::{
        conversion::ToU64,
        dummy::DummyProof,
        logic::BuilderLogic,
        poseidon_hash_out::{PoseidonHashOut, PoseidonHashOutTarget, POSEIDON_HASH_OUT_LEN},
        recursively_verifiable::{
            add_proof_target_and_conditionally_verify, add_proof_target_and_verify,
        },
    },
};
use plonky2::{
    field::{extension::Extendable, types::Field},
    hash::hash_types::RichField,
    iop::{
        target::{BoolTarget, Target},
        witness::{PartialWitness, Witness},
    },
    plonk::{
        circuit_builder::CircuitBuilder,
        circuit_data::{CircuitConfig, CircuitData, VerifierCircuitData},
        config::{AlgebraicHasher, GenericConfig},
        proof::{ProofWithPublicInputs, ProofWithPublicInputsTarget},
    },
};

use crate::{
    circuits::validity::block_validation::{
        account_exclusion::AccountExclusionPublicInputs, aggregation::AggregationPublicInputs,
    },
    common::{
        block::{Block, BlockTarget},
        signature_content::{utils::get_pubkey_hash, SignatureContent, SignatureContentTarget},
    },
    constants::NUM_SENDERS_IN_BLOCK,
    ethereum_types::{bytes32::Bytes32, u256::U256, u32limb_trait::U32LimbTargetTrait},
};

use super::{
    account_exclusion::{AccountExclusionCircuit, AccountExclusionPublicInputsTarget},
    account_inclusion::{
        AccountInclusionCircuit, AccountInclusionPublicInputs, AccountInclusionPublicInputsTarget,
    },
    aggregation::{AggregationCircuit, AggregationPublicInputsTarget},
    format_validation::{
        FormatValidationCircuit, FormatValidationPublicInputs, FormatValidationPublicInputsTarget,
    },
    utils::{get_pubkey_commitment, get_pubkey_commitment_circuit},
};

pub const MAIN_VALIDATION_PUBLIC_INPUT_LEN: usize =
    4 * BYTES32_LEN + 2 * POSEIDON_HASH_OUT_LEN + U64_LEN + 3;

#[derive(Clone, Debug)]
pub struct MainValidationPublicInputs {
    pub prev_block_hash: Bytes32,
    pub block_hash: Bytes32,
    pub deposit_tree_root: Bytes32,
    pub account_tree_root: PoseidonHashOut,
    pub tx_tree_root: Bytes32,
    pub sender_tree_root: PoseidonHashOut,
    pub timestamp: u64,
    pub block_number: u32,
    pub is_registration_block: bool,
    pub is_valid: bool,
}

#[derive(Clone, Debug)]
pub struct MainValidationPublicInputsTarget {
    pub prev_block_hash: Bytes32Target,
    pub block_hash: Bytes32Target,
    pub deposit_tree_root: Bytes32Target,
    pub account_tree_root: PoseidonHashOutTarget,
    pub tx_tree_root: Bytes32Target,
    pub sender_tree_root: PoseidonHashOutTarget,
    pub timestamp: U64Target,
    pub block_number: Target,
    pub is_registration_block: BoolTarget,
    pub is_valid: BoolTarget,
}

impl MainValidationPublicInputs {
    pub fn from_u64_slice(input: &[u64]) -> Result<Self, BlockValidationError> {
        if input.len() != MAIN_VALIDATION_PUBLIC_INPUT_LEN {
            return Err(BlockValidationError::MainValidationInputLengthMismatch {
                expected: MAIN_VALIDATION_PUBLIC_INPUT_LEN,
                actual: input.len(),
            });
        }
        let prev_block_hash = Bytes32::from_u64_slice(&input[0..8]).unwrap();
        let block_hash = Bytes32::from_u64_slice(&input[8..16]).unwrap();
        let deposit_tree_root = Bytes32::from_u64_slice(&input[16..24]).unwrap();
        let account_tree_root = PoseidonHashOut::from_u64_slice(&input[24..28])
            .unwrap_or_else(|e| panic!("Failed to create PoseidonHashOut from u64 slice: {}", e));
        let tx_tree_root = Bytes32::from_u64_slice(&input[28..36]).unwrap();
        let sender_tree_root = PoseidonHashOut::from_u64_slice(&input[36..40])
            .unwrap_or_else(|e| panic!("Failed to create PoseidonHashOut from u64 slice: {}", e));
        let timestamp = U64::from_u64_slice(&input[40..42]).unwrap().into();
        let block_number = input[42];
        let is_registration_block = input[43] == 1;
        let is_valid = input[44] == 1;
        Ok(Self {
            prev_block_hash,
            block_hash,
            deposit_tree_root,
            account_tree_root,
            tx_tree_root,
            sender_tree_root,
            timestamp,
            block_number: block_number as u32,
            is_registration_block,
            is_valid,
        })
    }
}

impl MainValidationPublicInputsTarget {
    pub fn new<F: RichField + Extendable<D>, const D: usize>(
        builder: &mut CircuitBuilder<F, D>,
        is_checked: bool,
    ) -> Self {
        let block_number = builder.add_virtual_target();
        let is_registration_block = builder.add_virtual_bool_target_unsafe();
        let is_valid = builder.add_virtual_bool_target_unsafe();
        if is_checked {
            builder.range_check(block_number, 32);
            builder.assert_bool(is_registration_block);
            builder.assert_bool(is_valid);
        }
        Self {
            prev_block_hash: Bytes32Target::new(builder, is_checked),
            block_hash: Bytes32Target::new(builder, is_checked),
            deposit_tree_root: Bytes32Target::new(builder, is_checked),
            account_tree_root: PoseidonHashOutTarget::new(builder),
            tx_tree_root: Bytes32Target::new(builder, is_checked),
            sender_tree_root: PoseidonHashOutTarget::new(builder),
            timestamp: U64Target::new(builder, is_checked),
            block_number,
            is_registration_block,
            is_valid,
        }
    }

    pub fn to_vec(&self) -> Vec<Target> {
        let vec = self
            .prev_block_hash
            .to_vec()
            .into_iter()
            .chain(self.block_hash.to_vec())
            .chain(self.deposit_tree_root.to_vec())
            .chain(self.account_tree_root.elements)
            .chain(self.tx_tree_root.to_vec())
            .chain(self.sender_tree_root.elements)
            .chain(self.timestamp.to_vec())
            .chain([
                self.block_number,
                self.is_registration_block.target,
                self.is_valid.target,
            ])
            .collect::<Vec<_>>();
        assert_eq!(vec.len(), MAIN_VALIDATION_PUBLIC_INPUT_LEN);
        vec
    }

    pub fn from_slice(input: &[Target]) -> Self {
        assert_eq!(input.len(), MAIN_VALIDATION_PUBLIC_INPUT_LEN);
        let prev_block_hash = Bytes32Target::from_slice(&input[0..8]);
        let block_hash = Bytes32Target::from_slice(&input[8..16]);
        let deposit_tree_root = Bytes32Target::from_slice(&input[16..24]);
        let account_tree_root = PoseidonHashOutTarget::from_slice(&input[24..28]);
        let tx_tree_root = Bytes32Target::from_slice(&input[28..36]);
        let sender_tree_root = PoseidonHashOutTarget::from_slice(&input[36..40]);
        let timestamp = U64Target::from_slice(&input[40..42]);
        let block_number = input[42];
        let is_registration_block = BoolTarget::new_unsafe(input[43]);
        let is_valid = BoolTarget::new_unsafe(input[44]);
        Self {
            prev_block_hash,
            block_hash,
            deposit_tree_root,
            account_tree_root,
            tx_tree_root,
            sender_tree_root,
            timestamp,
            block_number,
            is_registration_block,
            is_valid,
        }
    }

    pub fn connect<F: RichField + Extendable<D>, const D: usize>(
        &self,
        builder: &mut CircuitBuilder<F, D>,
        other: &Self,
    ) {
        self.prev_block_hash.connect(builder, other.prev_block_hash);
        self.block_hash.connect(builder, other.block_hash);
        self.deposit_tree_root
            .connect(builder, other.deposit_tree_root);
        self.account_tree_root
            .connect(builder, other.account_tree_root);
        self.tx_tree_root.connect(builder, other.tx_tree_root);
        self.sender_tree_root
            .connect(builder, other.sender_tree_root);
        self.timestamp.connect(builder, other.timestamp);
        builder.connect(self.block_number, other.block_number);
        builder.connect(
            self.is_registration_block.target,
            other.is_registration_block.target,
        );
        builder.connect(self.is_valid.target, other.is_valid.target);
    }

    pub fn set_witness<W: Witness<F>, F: Field>(
        &self,
        witness: &mut W,
        value: &MainValidationPublicInputs,
    ) {
        self.prev_block_hash
            .set_witness(witness, value.prev_block_hash);
        self.block_hash.set_witness(witness, value.block_hash);
        self.deposit_tree_root
            .set_witness(witness, value.deposit_tree_root);
        self.account_tree_root
            .set_witness(witness, value.account_tree_root);
        self.tx_tree_root.set_witness(witness, value.tx_tree_root);
        self.sender_tree_root
            .set_witness(witness, value.sender_tree_root);
        self.timestamp
            .set_witness(witness, U64::from(value.timestamp));
        witness.set_target(self.block_number, F::from_canonical_u32(value.block_number));
        witness.set_bool_target(self.is_registration_block, value.is_registration_block);
        witness.set_bool_target(self.is_valid, value.is_valid);
    }
}

/// Contains all the values needed to generate a proof for the main validation circuit.
///
/// This structure holds the block data, signatures, proofs from sub-circuits, and
/// computed values needed to verify the block's validity without state transitions.
pub struct MainValidationValue<
    F: RichField + Extendable<D>,
    C: GenericConfig<D, F = F>,
    const D: usize,
> {
    block: Block,
    signature: SignatureContent,
    pubkeys: Vec<U256>,
    account_tree_root: PoseidonHashOut,
    account_inclusion_proof: Option<ProofWithPublicInputs<F, C, D>>,
    account_exclusion_proof: Option<ProofWithPublicInputs<F, C, D>>,
    format_validation_proof: ProofWithPublicInputs<F, C, D>,
    aggregation_proof: Option<ProofWithPublicInputs<F, C, D>>,
    signature_commitment: PoseidonHashOut,
    pubkey_commitment: PoseidonHashOut,
    prev_block_hash: Bytes32,
    block_hash: Bytes32,
    sender_tree_root: PoseidonHashOut,
    is_registration_block: bool,
    is_valid: bool,
}

impl<F: RichField + Extendable<D>, C: GenericConfig<D, F = F>, const D: usize>
    MainValidationValue<F, C, D>
{
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        account_inclusion_circuit: &AccountInclusionCircuit<F, C, D>,
        account_exclusion_circuit: &AccountExclusionCircuit<F, C, D>,
        format_validation_circuit: &FormatValidationCircuit<F, C, D>,
        aggregation_circuit: &AggregationCircuit<F, C, D>,
        block: Block,
        signature: SignatureContent,
        pubkeys: Vec<U256>,
        account_tree_root: PoseidonHashOut,
        account_inclusion_proof: Option<ProofWithPublicInputs<F, C, D>>,
        account_exclusion_proof: Option<ProofWithPublicInputs<F, C, D>>,
        format_validation_proof: ProofWithPublicInputs<F, C, D>,
        aggregation_proof: Option<ProofWithPublicInputs<F, C, D>>,
    ) -> Result<Self, BlockValidationError> {
        let mut result = true;
        let pubkey_commitment = get_pubkey_commitment(&pubkeys);
        let pubkey_hash = get_pubkey_hash(&pubkeys);
        let is_registration_block = signature.block_sign_payload.is_registration_block;
        let is_pubkey_eq = signature.pubkey_hash == pubkey_hash;

        if is_registration_block {
            // if given pubkey hash is not equal to the calculated pubkey hash, it means that the
            // given pubkeys are wrong, so we should return an error.
            if !is_pubkey_eq {
                return Err(BlockValidationError::PubkeyHashMismatch {
                    expected: pubkey_hash,
                    actual: signature.pubkey_hash,
                });
            }
        } else {
            // In the account id case, The value of signature.pubkey_hash can be freely chosen by
            // the block builder, so it should not be constrained in the circuit.
            result = result && is_pubkey_eq;
        }

        let signature_commitment = signature.commitment();
        let signature_hash = signature.hash();
        if block.signature_hash != signature_hash {
            return Err(BlockValidationError::SignatureHashMismatch {
                expected: signature_hash,
                actual: block.signature_hash,
            });
        }

        let sender_tree_root = get_sender_tree_root(&pubkeys, signature.sender_flag);

        if is_registration_block {
            // Account exclusion verification
            let account_exclusion_proof = account_exclusion_proof.clone().ok_or_else(|| {
                BlockValidationError::AccountExclusionValue(
                    "account exclusion proof should be provided".to_string(),
                )
            })?;

            account_exclusion_circuit
                .data
                .verify(account_exclusion_proof.clone())
                .map_err(|e| {
                    BlockValidationError::AccountExclusionProofVerificationFailed(e.to_string())
                })?;

            let pis = AccountExclusionPublicInputs::from_u64_slice(
                &account_exclusion_proof.public_inputs.to_u64_vec(),
            )?;

            if pis.sender_tree_root != sender_tree_root {
                return Err(BlockValidationError::SenderTreeRootMismatch {
                    expected: sender_tree_root,
                    actual: pis.sender_tree_root,
                });
            }

            if pis.account_tree_root != account_tree_root {
                return Err(BlockValidationError::AccountTreeRootMismatch {
                    expected: account_tree_root,
                    actual: pis.account_tree_root,
                });
            }

            result = result && pis.is_valid;
        } else {
            // Account inclusion verification
            let account_inclusion_proof = account_inclusion_proof.clone().ok_or_else(|| {
                BlockValidationError::AccountInclusionValue(
                    "account inclusion proof should be provided".to_string(),
                )
            })?;

            account_inclusion_circuit
                .data
                .verify(account_inclusion_proof.clone())
                .map_err(|e| {
                    BlockValidationError::AccountInclusionProofVerificationFailed(e.to_string())
                })?;

            let pis = AccountInclusionPublicInputs::from_u64_slice(
                &account_inclusion_proof
                    .public_inputs
                    .into_iter()
                    .map(|x| x.to_canonical_u64())
                    .collect::<Vec<_>>(),
            )?;

            if pis.pubkey_commitment != pubkey_commitment {
                return Err(BlockValidationError::PubkeyCommitmentMismatch {
                    expected: pubkey_commitment,
                    actual: pis.pubkey_commitment,
                });
            }

            if pis.account_tree_root != account_tree_root {
                return Err(BlockValidationError::AccountTreeRootMismatch {
                    expected: account_tree_root,
                    actual: pis.account_tree_root,
                });
            }

            if pis.account_id_hash != signature.account_id_hash {
                return Err(BlockValidationError::AccountIdHashMismatch {
                    expected: signature.account_id_hash,
                    actual: pis.account_id_hash,
                });
            }

            result = result && pis.is_valid;
        }

        // Format validation
        format_validation_circuit
            .data
            .verify(format_validation_proof.clone())
            .map_err(|e| {
                BlockValidationError::FormatValidationProofVerificationFailed(e.to_string())
            })?;

        let format_validation_pis = FormatValidationPublicInputs::from_u64_slice(
            &format_validation_proof.public_inputs.to_u64_vec(),
        )
        .map_err(|e| {
            BlockValidationError::FormatValidationProofVerificationFailed(e.to_string())
        })?;

        if format_validation_pis.pubkey_commitment != pubkey_commitment {
            return Err(BlockValidationError::PubkeyCommitmentMismatch {
                expected: pubkey_commitment,
                actual: format_validation_pis.pubkey_commitment,
            });
        }

        if format_validation_pis.signature_commitment != signature_commitment {
            return Err(BlockValidationError::SignatureCommitmentMismatch {
                expected: signature_commitment,
                actual: format_validation_pis.signature_commitment,
            });
        }

        result = result && format_validation_pis.is_valid;

        if result {
            // Perform aggregation verification only if all the above processes are verified.
            let aggregation_proof = aggregation_proof.clone().ok_or_else(|| {
                BlockValidationError::AggregationProofVerificationFailed(
                    "aggregation proof should be provided".to_string(),
                )
            })?;

            aggregation_circuit
                .data
                .verify(aggregation_proof.clone())
                .map_err(|e| {
                    BlockValidationError::AggregationProofVerificationFailed(e.to_string())
                })?;

            let pis = AggregationPublicInputs::from_u64_slice(
                &aggregation_proof
                    .public_inputs
                    .into_iter()
                    .map(|x| x.to_canonical_u64())
                    .collect::<Vec<_>>(),
            )
            .map_err(|e| {
                BlockValidationError::AggregationProofVerificationFailed(format!(
                    "Failed to parse aggregation public inputs: {}",
                    e
                ))
            })?;

            if pis.pubkey_commitment != pubkey_commitment {
                return Err(BlockValidationError::PubkeyCommitmentMismatch {
                    expected: pubkey_commitment,
                    actual: pis.pubkey_commitment,
                });
            }

            if pis.signature_commitment != signature_commitment {
                return Err(BlockValidationError::SignatureCommitmentMismatch {
                    expected: signature_commitment,
                    actual: pis.signature_commitment,
                });
            }

            result = result && pis.is_valid;
        }

        // block hash calculation
        let prev_block_hash = block.prev_block_hash;
        let block_hash = block.hash();

        Ok(Self {
            block,
            signature,
            pubkeys,
            account_tree_root,
            account_inclusion_proof,
            account_exclusion_proof,
            format_validation_proof,
            aggregation_proof,
            signature_commitment,
            pubkey_commitment,
            prev_block_hash,
            block_hash,
            sender_tree_root,
            is_registration_block,
            is_valid: result,
        })
    }
}

#[derive(Debug, Clone)]
pub struct MainValidationTarget<const D: usize> {
    block: BlockTarget,
    signature: SignatureContentTarget,
    pubkeys: Vec<U256Target>,
    account_tree_root: PoseidonHashOutTarget,
    account_inclusion_proof: ProofWithPublicInputsTarget<D>,
    account_exclusion_proof: ProofWithPublicInputsTarget<D>,
    format_validation_proof: ProofWithPublicInputsTarget<D>,
    aggregation_proof: ProofWithPublicInputsTarget<D>,
    signature_commitment: PoseidonHashOutTarget,
    pubkey_commitment: PoseidonHashOutTarget,
    prev_block_hash: Bytes32Target,
    block_hash: Bytes32Target,
    sender_tree_root: PoseidonHashOutTarget,
    is_registration_block: BoolTarget,
    is_valid: BoolTarget,
}

/// Implementation of MainValidationTarget for circuit construction.
impl<const D: usize> MainValidationTarget<D> {
    /// Creates a new MainValidationTarget with circuit constraints for block validation.
    ///
    /// This method builds the circuit logic for validating blocks by:
    /// 1. Verifying pubkey hash consistency
    /// 2. For registration blocks: verifying account exclusion via sub-circuit
    /// 3. For non-registration blocks: verifying account inclusion via sub-circuit
    /// 4. Verifying format validation via sub-circuit
    /// 5. Conditionally verifying aggregation if all previous validations pass
    ///
    /// The is_valid flag is computed based on the combined result of all validations.
    pub fn new<F: RichField + Extendable<D>, C: GenericConfig<D, F = F> + 'static>(
        account_inclusion_vd: &VerifierCircuitData<F, C, D>,
        account_exclusion_vd: &VerifierCircuitData<F, C, D>,
        format_validation_vd: &VerifierCircuitData<F, C, D>,
        aggregation_vd: &VerifierCircuitData<F, C, D>,
        builder: &mut CircuitBuilder<F, D>,
    ) -> Self
    where
        C::Hasher: AlgebraicHasher<F>,
    {
        let mut result = builder._true();
        let block = BlockTarget::new(builder, true);
        let signature = SignatureContentTarget::new(builder, true);
        let pubkeys = (0..NUM_SENDERS_IN_BLOCK)
            .map(|_| U256Target::new(builder, true))
            .collect::<Vec<_>>();
        let sender_tree_root =
            get_sender_tree_root_circuit::<F, C, D>(builder, &pubkeys, signature.sender_flag);
        let pubkey_commitment = get_pubkey_commitment_circuit(builder, &pubkeys);
        let pubkey_hash = get_pubkey_hash_circuit::<F, C, D>(builder, &pubkeys);
        let account_tree_root = PoseidonHashOutTarget::new(builder);

        let is_registration_block = signature.block_sign_payload.is_registration_block;
        let is_not_registration_block = builder.not(is_registration_block);
        let is_pubkey_eq = signature.pubkey_hash.is_equal(builder, &pubkey_hash);
        // pubkey case
        builder.conditional_assert_true(is_registration_block, is_pubkey_eq);
        // account id case
        result = builder.conditional_and(is_not_registration_block, result, is_pubkey_eq);

        let signature_commitment = signature.commitment(builder);
        let signature_hash = signature.hash::<F, C, D>(builder);
        block.signature_hash.connect(builder, signature_hash);

        // Account exclusion verification
        let account_exclusion_proof = add_proof_target_and_conditionally_verify(
            account_exclusion_vd,
            builder,
            is_registration_block,
        );
        let account_exclusion_pis =
            AccountExclusionPublicInputsTarget::from_slice(&account_exclusion_proof.public_inputs);
        account_exclusion_pis
            .sender_tree_root
            .conditional_assert_eq(builder, sender_tree_root, is_registration_block);
        account_exclusion_pis
            .account_tree_root
            .conditional_assert_eq(builder, account_tree_root, is_registration_block);
        result = builder.conditional_and(
            is_registration_block,
            result,
            account_exclusion_pis.is_valid,
        );

        // Account inclusion verification
        let account_inclusion_proof = add_proof_target_and_conditionally_verify(
            account_inclusion_vd,
            builder,
            is_not_registration_block,
        );
        let account_inclusion_pis =
            AccountInclusionPublicInputsTarget::from_slice(&account_inclusion_proof.public_inputs);
        account_inclusion_pis
            .pubkey_commitment
            .conditional_assert_eq(builder, pubkey_commitment, is_not_registration_block);
        account_inclusion_pis
            .account_tree_root
            .conditional_assert_eq(builder, account_tree_root, is_not_registration_block);
        account_inclusion_pis.account_id_hash.conditional_assert_eq(
            builder,
            signature.account_id_hash,
            is_not_registration_block,
        );
        result = builder.conditional_and(
            is_not_registration_block,
            result,
            account_inclusion_pis.is_valid,
        );

        // Format validation
        let format_validation_proof = add_proof_target_and_verify(format_validation_vd, builder);
        let format_validation_pis =
            FormatValidationPublicInputsTarget::from_slice(&format_validation_proof.public_inputs)
                .expect("Failed to parse format validation public inputs target");
        format_validation_pis
            .pubkey_commitment
            .connect(builder, pubkey_commitment);
        format_validation_pis
            .signature_commitment
            .connect(builder, signature_commitment);
        result = builder.and(result, format_validation_pis.is_valid);

        // Perform aggregation verification only if all the above processes are verified.
        let aggregation_proof =
            add_proof_target_and_conditionally_verify(aggregation_vd, builder, result);
        let aggregation_pis =
            AggregationPublicInputsTarget::from_slice(&aggregation_proof.public_inputs)
                .expect("Failed to parse aggregation public inputs target");
        aggregation_pis
            .pubkey_commitment
            .conditional_assert_eq(builder, pubkey_commitment, result);
        aggregation_pis.signature_commitment.conditional_assert_eq(
            builder,
            signature_commitment,
            result,
        );
        result = builder.conditional_and(result, result, aggregation_pis.is_valid);

        let prev_block_hash = block.prev_block_hash;
        let block_hash = block.hash::<F, C, D>(builder);

        Self {
            block,
            signature,
            pubkeys,
            account_tree_root,
            account_inclusion_proof,
            account_exclusion_proof,
            format_validation_proof,
            aggregation_proof,
            signature_commitment,
            pubkey_commitment,
            prev_block_hash,
            block_hash,
            sender_tree_root,
            is_registration_block,
            is_valid: result,
        }
    }

    /// Sets the witness values for all targets in the MainValidationTarget.
    ///
    /// This method populates the witness with values from MainValidationValue,
    /// handling both registration and non-registration block cases appropriately.
    /// It uses dummy proofs when actual proofs are not available.
    pub fn set_witness<F: RichField + Extendable<D>, C: GenericConfig<D, F = F>, W: Witness<F>>(
        &self,
        witness: &mut W,
        account_inclusion_proof_dummy: DummyProof<F, C, D>,
        account_exclusion_proof_dummy: DummyProof<F, C, D>,
        aggregation_proof_dummy: DummyProof<F, C, D>,
        value: &MainValidationValue<F, C, D>,
    ) where
        <C as GenericConfig<D>>::Hasher: AlgebraicHasher<F>,
    {
        self.block.set_witness(witness, &value.block);
        self.signature.set_witness(witness, &value.signature);
        for (pubkey_t, pubkey) in self.pubkeys.iter().zip(value.pubkeys.iter()) {
            pubkey_t.set_witness(witness, *pubkey);
        }
        self.account_tree_root
            .set_witness(witness, value.account_tree_root);
        let account_inclusion_proof = value
            .account_inclusion_proof
            .as_ref()
            .unwrap_or(&account_inclusion_proof_dummy.proof);
        witness.set_proof_with_pis_target(&self.account_inclusion_proof, account_inclusion_proof);
        let account_exclusion_proof = value
            .account_exclusion_proof
            .as_ref()
            .unwrap_or(&account_exclusion_proof_dummy.proof);
        witness.set_proof_with_pis_target(&self.account_exclusion_proof, account_exclusion_proof);
        witness.set_proof_with_pis_target(
            &self.format_validation_proof,
            &value.format_validation_proof,
        );
        let aggregation_proof = value
            .aggregation_proof
            .as_ref()
            .unwrap_or(&aggregation_proof_dummy.proof);
        witness.set_proof_with_pis_target(&self.aggregation_proof, aggregation_proof);
        self.signature_commitment
            .set_witness(witness, value.signature_commitment);
        self.pubkey_commitment
            .set_witness(witness, value.pubkey_commitment);
        self.prev_block_hash
            .set_witness(witness, value.prev_block_hash);
        self.block_hash.set_witness(witness, value.block_hash);
        self.sender_tree_root
            .set_witness(witness, value.sender_tree_root);
        witness.set_bool_target(self.is_registration_block, value.is_registration_block);
        witness.set_bool_target(self.is_valid, value.is_valid);
    }
}

/// Main circuit for validating blocks without performing state transitions.
///
/// This circuit combines account exclusion/inclusion, format validation, and
/// aggregation verification to determine if a block is valid. It verifies:
/// - For registration blocks: accounts didn't exist previously (account exclusion)
/// - For non-registration blocks: accounts existed previously (account inclusion)
/// - Pubkeys are valid G1 x-coordinates and strictly descending (format validation)
/// - Message points are correctly calculated (format validation)
/// - Weighted public key aggregation is correctly computed (aggregation)
#[derive(Debug)]
pub struct MainValidationCircuit<F, C, const D: usize>
where
    F: RichField + Extendable<D>,
    C: GenericConfig<D, F = F>,
{
    pub data: CircuitData<F, C, D>,
    pub target: MainValidationTarget<D>,
}

impl<F, C, const D: usize> MainValidationCircuit<F, C, D>
where
    F: RichField + Extendable<D>,
    C: GenericConfig<D, F = F> + 'static,
    C::Hasher: AlgebraicHasher<F>,
{
    pub fn new(
        account_inclusion_vd: &VerifierCircuitData<F, C, D>,
        account_exclusion_vd: &VerifierCircuitData<F, C, D>,
        format_validation_vd: &VerifierCircuitData<F, C, D>,
        aggregation_vd: &VerifierCircuitData<F, C, D>,
    ) -> Self {
        let mut builder = CircuitBuilder::<F, D>::new(CircuitConfig::default());
        let target = MainValidationTarget::new::<F, C>(
            account_inclusion_vd,
            account_exclusion_vd,
            format_validation_vd,
            aggregation_vd,
            &mut builder,
        );
        let pis = MainValidationPublicInputsTarget {
            prev_block_hash: target.prev_block_hash,
            block_hash: target.block_hash,
            deposit_tree_root: target.block.deposit_tree_root,
            account_tree_root: target.account_tree_root,
            tx_tree_root: target.signature.block_sign_payload.tx_tree_root,
            sender_tree_root: target.sender_tree_root,
            timestamp: target.block.timestamp,
            block_number: target.block.block_number,
            is_registration_block: target.is_registration_block,
            is_valid: target.is_valid,
        };
        builder.register_public_inputs(&pis.to_vec());
        let data = builder.build();

        Self { data, target }
    }

    pub fn prove(
        &self,
        account_inclusion_proof_dummy: DummyProof<F, C, D>,
        account_exclusion_proof_dummy: DummyProof<F, C, D>,
        aggregation_proof_dummy: DummyProof<F, C, D>,
        value: &MainValidationValue<F, C, D>,
    ) -> Result<ProofWithPublicInputs<F, C, D>, BlockValidationError> {
        let mut pw = PartialWitness::<F>::new();
        self.target.set_witness(
            &mut pw,
            account_inclusion_proof_dummy,
            account_exclusion_proof_dummy,
            aggregation_proof_dummy,
            value,
        );
        let proof = self.data.prove(pw).map_err(|e| {
            BlockValidationError::Plonky2Error(format!(
                "Failed to prove main validation circuit: {}",
                e
            ))
        })?;
        Ok(proof)
    }
}

#[cfg(test)]
mod tests {
    use plonky2::{
        field::goldilocks_field::GoldilocksField, plonk::config::PoseidonGoldilocksConfig,
    };
    use rand::Rng;

    use crate::{
        circuits::{
            test_utils::witness_generator::{construct_validity_and_tx_witness, MockTxRequest},
            validity::{
                block_validation::{
                    account_exclusion::{AccountExclusionCircuit, AccountExclusionValue},
                    account_inclusion::{AccountInclusionCircuit, AccountInclusionValue},
                    aggregation::{AggregationCircuit, AggregationValue},
                    format_validation::{FormatValidationCircuit, FormatValidationValue},
                },
                validity_pis::ValidityPublicInputs,
            },
        },
        common::{
            signature_content::key_set::KeySet,
            trees::{
                account_tree::AccountTree, block_hash_tree::BlockHashTree,
                deposit_tree::DepositTree,
            },
            tx::Tx,
        },
        constants::NUM_SENDERS_IN_BLOCK,
        ethereum_types::{
            account_id::{AccountId, AccountIdPacked},
            address::Address,
        },
    };

    use super::{MainValidationCircuit, MainValidationValue};

    type F = GoldilocksField;
    const D: usize = 2;
    type C = PoseidonGoldilocksConfig;

    #[test]
    fn test_main_validation_registration_block() {
        let mut rng = rand::thread_rng();

        let mut account_tree = AccountTree::initialize();
        let mut block_tree = BlockHashTree::initialize();
        let deposit_tree = DepositTree::initialize();

        let prev_validity_pis = ValidityPublicInputs::genesis();
        let tx_requests = (0..NUM_SENDERS_IN_BLOCK)
            .map(|_| MockTxRequest {
                tx: Tx::rand(&mut rng),
                sender_key: KeySet::rand(&mut rng),
                will_return_sig: rng.gen_bool(0.5),
            })
            .collect::<Vec<_>>();
        let (validity_witness, _) = construct_validity_and_tx_witness(
            prev_validity_pis,
            &mut account_tree,
            &mut block_tree,
            &deposit_tree,
            true, // registration block
            0,
            Address::default(),
            0,
            &tx_requests,
            0,
        )
        .unwrap();

        let account_inclusion_circuit = AccountInclusionCircuit::<F, C, D>::new();
        let account_exclusion_circuit = AccountExclusionCircuit::<F, C, D>::new();
        let format_validation_circuit = FormatValidationCircuit::<F, C, D>::new();
        let aggregation_circuit = AggregationCircuit::<F, C, D>::new();

        let block_witness = validity_witness.block_witness.clone();
        let sender_leaves = block_witness.get_sender_tree().leaves();

        let account_exclusion_value = AccountExclusionValue::new(
            block_witness.prev_account_tree_root,
            block_witness.account_membership_proofs.unwrap(),
            sender_leaves.clone(),
        )
        .unwrap();
        assert!(account_exclusion_value.is_valid);
        let account_exclusion_proof = account_exclusion_circuit
            .prove(&account_exclusion_value)
            .unwrap();

        let format_validation_value = FormatValidationValue::new(
            block_witness.pubkeys.clone(),
            block_witness.signature.clone(),
        )
        .unwrap();
        assert!(format_validation_value.is_valid);
        let format_validation_proof = format_validation_circuit
            .prove(&format_validation_value)
            .unwrap();

        let aggregation_value = AggregationValue::new(
            block_witness.pubkeys.clone(),
            block_witness.signature.clone(),
        );
        assert!(aggregation_value.is_valid);
        let aggregation_proof = aggregation_circuit.prove(&aggregation_value).unwrap();

        let main_validation_value = MainValidationValue::new(
            &account_inclusion_circuit,
            &account_exclusion_circuit,
            &format_validation_circuit,
            &aggregation_circuit,
            block_witness.block.clone(),
            block_witness.signature.clone(),
            block_witness.pubkeys.clone(),
            block_witness.prev_account_tree_root,
            None,
            Some(account_exclusion_proof),
            format_validation_proof,
            Some(aggregation_proof),
        )
        .unwrap();
        assert!(main_validation_value.is_valid);

        let main_validation_circuit = MainValidationCircuit::new(
            &account_inclusion_circuit.data.verifier_data(),
            &account_exclusion_circuit.data.verifier_data(),
            &format_validation_circuit.data.verifier_data(),
            &aggregation_circuit.data.verifier_data(),
        );
        let main_validation_proof = main_validation_circuit
            .prove(
                account_inclusion_circuit.dummy_proof,
                account_exclusion_circuit.dummy_proof,
                aggregation_circuit.dummy_proof,
                &main_validation_value,
            )
            .unwrap();

        main_validation_circuit
            .data
            .verify(main_validation_proof.clone())
            .unwrap();
    }

    #[test]
    fn test_main_validation_non_registration_block() {
        let mut rng = rand::thread_rng();

        let mut account_tree = AccountTree::initialize();
        let mut block_tree = BlockHashTree::initialize();
        let deposit_tree = DepositTree::initialize();
        let mut prev_validity_pis = ValidityPublicInputs::genesis();

        // create a block that registers new accounts
        let keys = (0..NUM_SENDERS_IN_BLOCK)
            .map(|_| KeySet::rand(&mut rng))
            .collect::<Vec<_>>();
        let tx_requests = keys
            .iter()
            .map(|key| MockTxRequest {
                tx: Tx::rand(&mut rng),
                sender_key: key.clone(),
                will_return_sig: true, // all sender return sigs to register to the account tree
            })
            .collect::<Vec<_>>();
        let (registration_validity_witness, _) = construct_validity_and_tx_witness(
            prev_validity_pis,
            &mut account_tree,
            &mut block_tree,
            &deposit_tree,
            true, // registration block
            0,
            Address::default(),
            0,
            &tx_requests,
            0,
        )
        .unwrap();
        prev_validity_pis = registration_validity_witness.to_validity_pis().unwrap();

        // check account registration
        for key in keys.iter() {
            let account = account_tree.index(key.pubkey);
            assert!(account.is_some());
        }

        // create a non-registration block
        let tx_requests = keys
            .iter()
            .map(|key| MockTxRequest {
                tx: Tx::rand(&mut rng),
                sender_key: key.clone(),
                will_return_sig: rng.gen_bool(0.5), // some senders return sigs
            })
            .collect::<Vec<_>>();
        let (validity_witness, _) = construct_validity_and_tx_witness(
            prev_validity_pis,
            &mut account_tree,
            &mut block_tree,
            &deposit_tree,
            false, // non-registration block
            0,
            Address::default(),
            0,
            &tx_requests,
            0,
        )
        .unwrap();

        let account_inclusion_circuit = AccountInclusionCircuit::<F, C, D>::new();
        let account_exclusion_circuit = AccountExclusionCircuit::<F, C, D>::new();
        let format_validation_circuit = FormatValidationCircuit::<F, C, D>::new();
        let aggregation_circuit = AggregationCircuit::<F, C, D>::new();

        let block_witness = validity_witness.block_witness.clone();
        let pubkeys = block_witness.pubkeys.clone();

        // get account id packed
        let account_ids = pubkeys
            .iter()
            .map(|pubkey| {
                let account = account_tree.index(*pubkey);
                AccountId(account.unwrap())
            })
            .collect::<Vec<_>>();
        let account_id_packed = AccountIdPacked::pack(&account_ids);

        let account_inclusion_value = AccountInclusionValue::new(
            block_witness.prev_account_tree_root,
            account_id_packed,
            block_witness.account_merkle_proofs.unwrap(),
            pubkeys.clone(),
        )
        .unwrap();
        assert!(account_inclusion_value.is_valid);
        let account_inclusion_proof = account_inclusion_circuit
            .prove(&account_inclusion_value)
            .unwrap();

        let format_validation_value = FormatValidationValue::new(
            block_witness.pubkeys.clone(),
            block_witness.signature.clone(),
        )
        .unwrap();
        assert!(format_validation_value.is_valid);
        let format_validation_proof = format_validation_circuit
            .prove(&format_validation_value)
            .unwrap();

        let aggregation_value = AggregationValue::new(
            block_witness.pubkeys.clone(),
            block_witness.signature.clone(),
        );
        assert!(aggregation_value.is_valid);
        let aggregation_proof = aggregation_circuit.prove(&aggregation_value).unwrap();

        let main_validation_value = MainValidationValue::new(
            &account_inclusion_circuit,
            &account_exclusion_circuit,
            &format_validation_circuit,
            &aggregation_circuit,
            block_witness.block.clone(),
            block_witness.signature.clone(),
            block_witness.pubkeys.clone(),
            block_witness.prev_account_tree_root,
            Some(account_inclusion_proof),
            None,
            format_validation_proof,
            Some(aggregation_proof),
        )
        .unwrap();

        let main_validation_circuit = MainValidationCircuit::new(
            &account_inclusion_circuit.data.verifier_data(),
            &account_exclusion_circuit.data.verifier_data(),
            &format_validation_circuit.data.verifier_data(),
            &aggregation_circuit.data.verifier_data(),
        );
        let main_validation_proof = main_validation_circuit
            .prove(
                account_inclusion_circuit.dummy_proof,
                account_exclusion_circuit.dummy_proof,
                aggregation_circuit.dummy_proof,
                &main_validation_value,
            )
            .unwrap();

        main_validation_circuit
            .data
            .verify(main_validation_proof.clone())
            .unwrap();
    }
}
