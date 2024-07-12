use crate::{
    common::{
        signature::utils::get_pubkey_hash_circuit,
        trees::sender_tree::{get_sender_tree_root, get_sender_tree_root_circuit},
    },
    ethereum_types::{bytes32::BYTES32_LEN, u32limb_trait::U32LimbTrait as _},
    utils::{
        conversion::ToU64,
        dummy::DummyProof,
        logic::BuilderLogic,
        poseidon_hash_out::{PoseidonHashOut, PoseidonHashOutTarget},
        recursivable::Recursivable,
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
        circuit_data::{CircuitConfig, CircuitData},
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
        signature::{utils::get_pubkey_hash, SignatureContent, SignatureContentTarget},
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

pub const MAIN_VALIDATION_PUBLIC_INPUT_LEN: usize = 4 * BYTES32_LEN + 2 * 4 + 3;

#[derive(Clone, Debug)]
pub struct MainValidationPublicInputs {
    pub prev_block_hash: Bytes32<u32>,
    pub block_hash: Bytes32<u32>,
    pub deposit_tree_root: Bytes32<u32>,
    pub account_tree_root: PoseidonHashOut,
    pub tx_tree_root: Bytes32<u32>,
    pub sender_tree_root: PoseidonHashOut,
    pub block_number: u32,
    pub is_registoration_block: bool,
    pub is_valid: bool,
}

#[derive(Clone, Debug)]
pub struct MainValidationPublicInputsTarget {
    pub prev_block_hash: Bytes32<Target>,
    pub block_hash: Bytes32<Target>,
    pub deposit_tree_root: Bytes32<Target>,
    pub account_tree_root: PoseidonHashOutTarget,
    pub tx_tree_root: Bytes32<Target>,
    pub sender_tree_root: PoseidonHashOutTarget,
    pub block_number: Target,
    pub is_registoration_block: BoolTarget,
    pub is_valid: BoolTarget,
}

impl MainValidationPublicInputs {
    pub fn from_u64_vec(input: &[u64]) -> Self {
        assert_eq!(input.len(), MAIN_VALIDATION_PUBLIC_INPUT_LEN);
        let prev_block_hash = Bytes32::<u32>::from_u64_vec(&input[0..8]);
        let block_hash = Bytes32::<u32>::from_u64_vec(&input[8..16]);
        let deposit_tree_root = Bytes32::<u32>::from_u64_vec(&input[16..24]);
        let account_tree_root = PoseidonHashOut::from_u64_vec(&input[24..28]);
        let tx_tree_root = Bytes32::<u32>::from_u64_vec(&input[28..36]);
        let sender_tree_root = PoseidonHashOut::from_u64_vec(&input[36..40]);
        let block_number = input[40] as u32;
        let is_registoration_block = input[41] == 1;
        let is_valid = input[42] == 1;
        Self {
            prev_block_hash,
            block_hash,
            deposit_tree_root,
            account_tree_root,
            tx_tree_root,
            sender_tree_root,
            block_number,
            is_registoration_block,
            is_valid,
        }
    }
}

impl MainValidationPublicInputsTarget {
    pub fn new<F: RichField + Extendable<D>, const D: usize>(
        builder: &mut CircuitBuilder<F, D>,
        is_checked: bool,
    ) -> Self {
        let block_number = builder.add_virtual_target();
        let is_registoration_block = builder.add_virtual_bool_target_unsafe();
        let is_valid = builder.add_virtual_bool_target_unsafe();
        if is_checked {
            builder.range_check(block_number, 32);
            builder.assert_bool(is_registoration_block);
            builder.assert_bool(is_valid);
        }
        Self {
            prev_block_hash: Bytes32::<Target>::new(builder, is_checked),
            block_hash: Bytes32::<Target>::new(builder, is_checked),
            deposit_tree_root: Bytes32::<Target>::new(builder, is_checked),
            account_tree_root: PoseidonHashOutTarget::new(builder),
            tx_tree_root: Bytes32::<Target>::new(builder, is_checked),
            sender_tree_root: PoseidonHashOutTarget::new(builder),
            block_number,
            is_registoration_block,
            is_valid,
        }
    }

    pub fn to_vec(&self) -> Vec<Target> {
        let vec = self
            .prev_block_hash
            .limbs()
            .into_iter()
            .chain(self.block_hash.limbs().into_iter())
            .chain(self.deposit_tree_root.limbs().into_iter())
            .chain(self.account_tree_root.elements.into_iter())
            .chain(self.tx_tree_root.limbs().into_iter())
            .chain(self.sender_tree_root.elements.into_iter())
            .chain([
                self.block_number,
                self.is_registoration_block.target,
                self.is_valid.target,
            ])
            .collect::<Vec<_>>();
        assert_eq!(vec.len(), MAIN_VALIDATION_PUBLIC_INPUT_LEN);
        vec
    }

    pub fn from_vec(input: &[Target]) -> Self {
        assert_eq!(input.len(), MAIN_VALIDATION_PUBLIC_INPUT_LEN);
        let prev_block_hash = Bytes32::<Target>::from_limbs(&input[0..8]);
        let block_hash = Bytes32::<Target>::from_limbs(&input[8..16]);
        let deposit_tree_root = Bytes32::<Target>::from_limbs(&input[16..24]);
        let account_tree_root = PoseidonHashOutTarget::from_vec(&input[24..28]);
        let tx_tree_root = Bytes32::<Target>::from_limbs(&input[28..36]);
        let sender_tree_root = PoseidonHashOutTarget::from_vec(&input[36..40]);
        let block_number = input[40];
        let is_registoration_block = BoolTarget::new_unsafe(input[41]);
        let is_valid = BoolTarget::new_unsafe(input[42]);
        Self {
            prev_block_hash,
            block_hash,
            deposit_tree_root,
            account_tree_root,
            tx_tree_root,
            sender_tree_root,
            block_number,
            is_registoration_block,
            is_valid,
        }
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
        witness.set_target(self.block_number, F::from_canonical_u32(value.block_number));
        witness.set_bool_target(self.is_registoration_block, value.is_registoration_block);
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
    pubkeys: Vec<U256<u32>>,
    account_tree_root: PoseidonHashOut,
    account_inclusion_proof: Option<ProofWithPublicInputs<F, C, D>>,
    account_exclusion_proof: Option<ProofWithPublicInputs<F, C, D>>,
    format_validation_proof: ProofWithPublicInputs<F, C, D>,
    aggregation_proof: Option<ProofWithPublicInputs<F, C, D>>,
    block_commitment: PoseidonHashOut,
    signature_commitment: PoseidonHashOut,
    pubkey_commitment: PoseidonHashOut,
    prev_block_hash: Bytes32<u32>,
    block_hash: Bytes32<u32>,
    sender_tree_root: PoseidonHashOut,
    is_registoration_block: bool,
    is_valid: bool,
}

impl<F: RichField + Extendable<D>, C: GenericConfig<D, F = F>, const D: usize>
    MainValidationValue<F, C, D>
{
    pub fn new(
        account_inclusion_circuit: &AccountInclusionCircuit<F, C, D>,
        account_exclusion_circuit: &AccountExclusionCircuit<F, C, D>,
        format_validation_circuit: &FormatValidationCircuit<F, C, D>,
        aggregation_circuit: &AggregationCircuit<F, C, D>,
        block: Block,
        signature: SignatureContent,
        pubkeys: Vec<U256<u32>>,
        account_tree_root: PoseidonHashOut,
        account_inclusion_proof: Option<ProofWithPublicInputs<F, C, D>>,
        account_exclusion_proof: Option<ProofWithPublicInputs<F, C, D>>,
        format_validation_proof: ProofWithPublicInputs<F, C, D>,
        aggregation_proof: Option<ProofWithPublicInputs<F, C, D>>,
    ) -> Self {
        let mut result = true;
        let pubkey_commitment = get_pubkey_commitment(&pubkeys);
        let pubkey_hash = get_pubkey_hash(&pubkeys);
        let is_registoration_block = signature.is_registoration_block;
        let is_pubkey_eq = signature.pubkey_hash == pubkey_hash;
        if is_registoration_block {
            // When pubkey is directly given, the constraint is that signature.pubkey_hash and
            // pubkey_hash match.
            assert!(is_pubkey_eq, "pubkey hash mismatch");
        } else {
            // In the account id case, The value of signature.pubkey_hash can be freely chosen by
            // the block builder, so it should not be constrained to match in the circuit.
            result = result && is_pubkey_eq;
        }

        let signature_commitment = signature.commitment();
        let signature_hash = signature.hash();
        assert_eq!(
            block.signature_hash, signature_hash,
            "signature hash mismatch"
        );

        if is_registoration_block {
            // Account exclusion verification
            let account_exclusion_proof = account_exclusion_proof
                .clone()
                .expect("account exclusion proof should be provided");
            account_exclusion_circuit
                .data
                .verify(account_exclusion_proof.clone())
                .expect("account exclusion proof verification failed");
            let pis = AccountExclusionPublicInputs::from_u64_vec(
                &account_exclusion_proof.public_inputs.to_u64_vec(),
            );
            assert_eq!(
                pis.pubkey_commitment, pubkey_commitment,
                "pubkey commitment mismatch"
            );
            assert_eq!(
                pis.account_tree_root, account_tree_root,
                "account tree root mismatch"
            );
            result = result && pis.is_valid;
        } else {
            // Account inclusion verification
            let account_inclusion_proof = account_inclusion_proof
                .clone()
                .expect("account inclusion proof should be provided");
            account_inclusion_circuit
                .data
                .verify(account_inclusion_proof.clone())
                .expect("account inclusion proof verification failed");
            let pis = AccountInclusionPublicInputs::from_u64_vec(
                &account_inclusion_proof
                    .public_inputs
                    .into_iter()
                    .map(|x| x.to_canonical_u64())
                    .collect::<Vec<_>>(),
            );
            assert_eq!(
                pis.pubkey_commitment, pubkey_commitment,
                "pubkey commitment mismatch"
            );
            assert_eq!(
                pis.account_tree_root, account_tree_root,
                "account tree root mismatch"
            );
            assert_eq!(
                pis.account_id_hash, signature.account_id_hash,
                "account id hash mismatch"
            );
            result = result && pis.is_valid;
        }

        // Format validation
        format_validation_circuit
            .data
            .verify(format_validation_proof.clone())
            .expect("format validation proof verification failed");
        let format_validation_pis = FormatValidationPublicInputs::from_u64_vec(
            &format_validation_proof.public_inputs.to_u64_vec(),
        );
        assert_eq!(
            format_validation_pis.pubkey_commitment, pubkey_commitment,
            "pubkey commitment mismatch"
        );
        assert_eq!(
            format_validation_pis.signature_commitment, signature_commitment,
            "signature commitment mismatch"
        );
        result = result && format_validation_pis.is_valid;

        if result {
            // Perform aggregation verification only if all the above processes are verified.
            let aggregation_proof = aggregation_proof
                .clone()
                .expect("aggregation proof should be provided");
            aggregation_circuit
                .data
                .verify(aggregation_proof.clone())
                .unwrap();
            let pis = AggregationPublicInputs::from_u64_vec(
                &aggregation_proof
                    .public_inputs
                    .into_iter()
                    .map(|x| x.to_canonical_u64())
                    .collect::<Vec<_>>(),
            );
            assert_eq!(
                pis.pubkey_commitment, pubkey_commitment,
                "pubkey commitment mismatch"
            );
            assert_eq!(
                pis.signature_commitment, signature_commitment,
                "signature commitment mismatch"
            );
            result = result && pis.is_valid;
        }

        // block hash calculation
        let prev_block_hash = block.prev_block_hash;
        let block_hash = block.hash();
        let block_commitment = block.commitment();
        let sender_tree_root = get_sender_tree_root(&pubkeys, signature.sender_flag);

        Self {
            block,
            signature,
            pubkeys,
            account_tree_root,
            account_inclusion_proof,
            account_exclusion_proof,
            format_validation_proof,
            aggregation_proof,
            block_commitment,
            signature_commitment,
            pubkey_commitment,
            prev_block_hash,
            block_hash,
            sender_tree_root,
            is_registoration_block,
            is_valid: result,
        }
    }
}

pub struct MainValidationTarget<const D: usize> {
    block: BlockTarget,
    signature: SignatureContentTarget,
    pubkeys: Vec<U256<Target>>,
    account_tree_root: PoseidonHashOutTarget,
    account_inclusion_proof: ProofWithPublicInputsTarget<D>,
    account_exclusion_proof: ProofWithPublicInputsTarget<D>,
    format_validation_proof: ProofWithPublicInputsTarget<D>,
    aggregation_proof: ProofWithPublicInputsTarget<D>,
    block_commitment: PoseidonHashOutTarget,
    signature_commitment: PoseidonHashOutTarget,
    pubkey_commitment: PoseidonHashOutTarget,
    prev_block_hash: Bytes32<Target>,
    block_hash: Bytes32<Target>,
    sender_tree_root: PoseidonHashOutTarget,
    is_registoration_block: BoolTarget,
    is_valid: BoolTarget,
}

impl<const D: usize> MainValidationTarget<D> {
    pub fn new<F: RichField + Extendable<D>, C: GenericConfig<D, F = F> + 'static>(
        account_inclusion_circuit: &AccountInclusionCircuit<F, C, D>,
        account_exclusion_circuit: &AccountExclusionCircuit<F, C, D>,
        format_validation_circuit: &FormatValidationCircuit<F, C, D>,
        aggregation_circuit: &AggregationCircuit<F, C, D>,
        builder: &mut CircuitBuilder<F, D>,
    ) -> Self
    where
        C::Hasher: AlgebraicHasher<F>,
    {
        let mut result = builder._true();
        let block = BlockTarget::new(builder, true);
        let signature = SignatureContentTarget::new(builder, true);
        let pubkeys = (0..NUM_SENDERS_IN_BLOCK)
            .map(|_| U256::<Target>::new(builder, true))
            .collect::<Vec<_>>();
        let pubkey_commitment = get_pubkey_commitment_circuit(builder, &pubkeys);
        let pubkey_hash = get_pubkey_hash_circuit::<F, C, D>(builder, &pubkeys);
        let account_tree_root = PoseidonHashOutTarget::new(builder);

        let is_registoration_block = signature.is_registoration_block;
        let is_not_registoration_block = builder.not(is_registoration_block);
        let is_pubkey_eq = signature.pubkey_hash.is_equal(builder, &pubkey_hash);
        // pubkey case
        builder.conditional_assert_true(is_registoration_block, is_pubkey_eq);
        // account id case
        result = builder.conditional_and(is_not_registoration_block, result, is_pubkey_eq);

        // signature.pubkey_hash.connect(builder, pubkey_hash);
        let signature_commitment = signature.commitment(builder);
        let signature_hash = signature.hash::<F, C, D>(builder);
        block.signature_hash.connect(builder, signature_hash);

        // Account exclusion verification
        let account_exclusion_proof = account_exclusion_circuit
            .add_proof_target_and_conditionally_verify(builder, is_registoration_block);
        let account_exclusion_pis =
            AccountExclusionPublicInputsTarget::from_vec(&account_exclusion_proof.public_inputs);
        builder.conditional_assert_eq_targets(
            is_registoration_block,
            &account_exclusion_pis.pubkey_commitment.elements,
            &pubkey_commitment.elements,
        );
        builder.conditional_assert_eq_targets(
            is_registoration_block,
            &account_exclusion_pis.account_tree_root.elements,
            &account_tree_root.elements,
        );
        result = builder.conditional_and(
            is_registoration_block,
            result,
            account_exclusion_pis.is_valid,
        );

        // Account inclusion verification
        let account_inclusion_proof = account_inclusion_circuit
            .add_proof_target_and_conditionally_verify(builder, is_not_registoration_block);
        let account_inclusion_pis =
            AccountInclusionPublicInputsTarget::from_vec(&account_inclusion_proof.public_inputs);
        builder.conditional_assert_eq_targets(
            is_not_registoration_block,
            &account_inclusion_pis.pubkey_commitment.elements,
            &pubkey_commitment.elements,
        );
        builder.conditional_assert_eq_targets(
            is_not_registoration_block,
            &account_inclusion_pis.account_tree_root.elements,
            &account_tree_root.elements,
        );
        account_inclusion_pis.account_id_hash.conditional_assert_eq(
            builder,
            signature.account_id_hash,
            is_not_registoration_block,
        );
        result = builder.conditional_and(
            is_not_registoration_block,
            result,
            account_inclusion_pis.is_valid,
        );

        // Format validation
        let format_validation_proof =
            format_validation_circuit.add_proof_target_and_verify(builder);
        let format_validation_pis =
            FormatValidationPublicInputsTarget::from_vec(&format_validation_proof.public_inputs);
        format_validation_pis
            .pubkey_commitment
            .connect(builder, pubkey_commitment);
        format_validation_pis
            .signature_commitment
            .connect(builder, signature_commitment);
        result = builder.and(result, format_validation_pis.is_valid);

        // Perform aggregation verification only if all the above processes are verified.
        let aggregation_proof =
            aggregation_circuit.add_proof_target_and_conditionally_verify(builder, result);
        let aggregation_pis =
            AggregationPublicInputsTarget::from_vec(&aggregation_proof.public_inputs);
        builder.conditional_assert_eq_targets(
            result,
            &aggregation_pis.pubkey_commitment.elements,
            &pubkey_commitment.elements,
        );
        builder.conditional_assert_eq_targets(
            result,
            &aggregation_pis.signature_commitment.elements,
            &signature_commitment.elements,
        );
        result = builder.conditional_and(result, result, aggregation_pis.is_valid);

        let prev_block_hash = block.prev_block_hash;
        let block_hash = block.hash::<F, C, D>(builder);
        let block_commitment = block.commitment(builder);
        let sender_tree_root =
            get_sender_tree_root_circuit::<F, C, D>(builder, &pubkeys, signature.sender_flag);

        Self {
            block,
            signature,
            pubkeys,
            account_tree_root,
            account_inclusion_proof,
            account_exclusion_proof,
            format_validation_proof,
            aggregation_proof,
            block_commitment,
            signature_commitment,
            pubkey_commitment,
            prev_block_hash,
            block_hash,
            sender_tree_root,
            is_registoration_block,
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
        witness.set_proof_with_pis_target(&self.account_inclusion_proof, &account_inclusion_proof);
        let account_exclusion_proof = value
            .account_exclusion_proof
            .as_ref()
            .unwrap_or(&account_exclusion_proof_dummy.proof);
        witness.set_proof_with_pis_target(&self.account_exclusion_proof, &account_exclusion_proof);
        witness.set_proof_with_pis_target(
            &self.format_validation_proof,
            &value.format_validation_proof,
        );
        let aggregation_proof = value
            .aggregation_proof
            .as_ref()
            .unwrap_or(&aggregation_proof_dummy.proof);
        witness.set_proof_with_pis_target(&self.aggregation_proof, &aggregation_proof);
        self.block_commitment
            .set_witness(witness, value.block_commitment);
        self.signature_commitment
            .set_witness(witness, value.signature_commitment);
        self.pubkey_commitment
            .set_witness(witness, value.pubkey_commitment);
        self.prev_block_hash
            .set_witness(witness, value.prev_block_hash);
        self.block_hash.set_witness(witness, value.block_hash);
        self.sender_tree_root
            .set_witness(witness, value.sender_tree_root);
        witness.set_bool_target(self.is_registoration_block, value.is_registoration_block);
        witness.set_bool_target(self.is_valid, value.is_valid);
    }
}

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
        account_inclusion_circuit: &AccountInclusionCircuit<F, C, D>,
        account_exclusion_circuit: &AccountExclusionCircuit<F, C, D>,
        format_validation_circuit: &FormatValidationCircuit<F, C, D>,
        aggregation_circuit: &AggregationCircuit<F, C, D>,
    ) -> Self {
        let mut builder = CircuitBuilder::<F, D>::new(CircuitConfig::default());
        let target = MainValidationTarget::new::<F, C>(
            account_inclusion_circuit,
            account_exclusion_circuit,
            format_validation_circuit,
            aggregation_circuit,
            &mut builder,
        );
        let pis = MainValidationPublicInputsTarget {
            prev_block_hash: target.prev_block_hash,
            block_hash: target.block_hash,
            deposit_tree_root: target.block.deposit_tree_root,
            account_tree_root: target.account_tree_root,
            tx_tree_root: target.signature.tx_tree_root,
            sender_tree_root: target.sender_tree_root,
            block_number: target.block.block_number,
            is_registoration_block: target.is_registoration_block,
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
    ) -> anyhow::Result<ProofWithPublicInputs<F, C, D>> {
        let mut pw = PartialWitness::<F>::new();
        self.target.set_witness(
            &mut pw,
            account_inclusion_proof_dummy,
            account_exclusion_proof_dummy,
            aggregation_proof_dummy,
            value,
        );
        self.data.prove(pw)
    }
}

impl<F: RichField + Extendable<D>, C: GenericConfig<D, F = F> + 'static, const D: usize>
    Recursivable<F, C, D> for MainValidationCircuit<F, C, D>
where
    <C as GenericConfig<D>>::Hasher: AlgebraicHasher<F>,
{
    fn circuit_data(&self) -> &CircuitData<F, C, D> {
        &self.data
    }
}
