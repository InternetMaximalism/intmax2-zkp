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
        let account_tree_root = PoseidonHashOut::from_u64_slice(&input[24..28]);
        let tx_tree_root = Bytes32::from_u64_slice(&input[28..36]).unwrap();
        let sender_tree_root = PoseidonHashOut::from_u64_slice(&input[36..40]);
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
            // When pubkey is directly given, the constraint is that signature.pubkey_hash and
            // pubkey_hash match.
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
            );

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
            );

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

impl<const D: usize> MainValidationTarget<D> {
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
