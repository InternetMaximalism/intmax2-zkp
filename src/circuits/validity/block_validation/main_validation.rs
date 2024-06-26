use crate::{
    common::{
        signature::utils::get_pubkey_hash_circuit,
        trees::sender_tree::{get_sender_tree_root, get_sender_tree_root_circuit},
    },
    ethereum_types::{bytes32::BYTES32_LEN, u32limb_trait::U32LimbTrait as _},
    utils::{
        dummy::DummyProof,
        logic::BuilderLogic,
        poseidon_hash_out::{PoseidonHashOut, PoseidonHashOutTarget},
    },
};
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

pub const MAIN_VALIDATION_PUBLIC_INPUT_LEN: usize = 3 * BYTES32_LEN + 2 * 4 + 2;

#[derive(Clone, Debug)]
pub struct MainValidationPublicInputs {
    pub prev_block_hash: Bytes32<u32>,
    pub block_hash: Bytes32<u32>,
    pub account_tree_root: PoseidonHashOut,
    pub tx_tree_root: Bytes32<u32>,
    pub sender_tree_root: PoseidonHashOut,
    pub is_registoration_block: bool,
    pub is_valid: bool,
}

#[derive(Clone, Debug)]
pub struct MainValidationPublicInputsTarget {
    pub prev_block_hash: Bytes32<Target>,
    pub block_hash: Bytes32<Target>,
    pub account_tree_root: PoseidonHashOutTarget,
    pub tx_tree_root: Bytes32<Target>,
    pub sender_tree_root: PoseidonHashOutTarget,
    pub is_registoration_block: BoolTarget,
    pub is_valid: BoolTarget,
}

impl MainValidationPublicInputs {
    pub fn from_u64_vec(input: &[u64]) -> Self {
        assert_eq!(input.len(), MAIN_VALIDATION_PUBLIC_INPUT_LEN);
        let prev_block_hash = Bytes32::<u32>::from_u64_vec(&input[0..8]);
        let block_hash = Bytes32::<u32>::from_u64_vec(&input[8..16]);
        let account_tree_root = PoseidonHashOut::from_u64_vec(&input[16..20]);
        let tx_tree_root = Bytes32::<u32>::from_u64_vec(&input[20..28]);
        let sender_tree_root = PoseidonHashOut::from_u64_vec(&input[28..32]);
        let is_registoration_block = input[32] == 1;
        let is_valid = input[33] == 1;
        Self {
            prev_block_hash,
            block_hash,
            account_tree_root,
            tx_tree_root,
            sender_tree_root,
            is_registoration_block,
            is_valid,
        }
    }
}

impl MainValidationPublicInputsTarget {
    pub fn to_vec(&self) -> Vec<Target> {
        let vec = self
            .prev_block_hash
            .limbs()
            .into_iter()
            .chain(self.block_hash.limbs().into_iter())
            .chain(self.account_tree_root.elements.into_iter())
            .chain(self.tx_tree_root.limbs().into_iter())
            .chain(self.sender_tree_root.elements.into_iter())
            .chain([self.is_registoration_block.target, self.is_valid.target])
            .collect::<Vec<_>>();
        assert_eq!(vec.len(), MAIN_VALIDATION_PUBLIC_INPUT_LEN);
        vec
    }

    pub fn from_vec(input: &[Target]) -> Self {
        assert_eq!(input.len(), MAIN_VALIDATION_PUBLIC_INPUT_LEN);
        let prev_block_hash = Bytes32::<Target>::from_limbs(&input[0..8]);
        let block_hash = Bytes32::<Target>::from_limbs(&input[8..16]);
        let account_tree_root = PoseidonHashOutTarget::from_vec(&input[16..20]);
        let tx_tree_root = Bytes32::<Target>::from_limbs(&input[20..28]);
        let sender_tree_root = PoseidonHashOutTarget::from_vec(&input[28..32]);
        let is_registoration_block = BoolTarget::new_unsafe(input[32]);
        let is_valid = BoolTarget::new_unsafe(input[33]);
        Self {
            prev_block_hash,
            block_hash,
            account_tree_root,
            tx_tree_root,
            sender_tree_root,
            is_registoration_block,
            is_valid,
        }
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
                &account_exclusion_proof
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
            &format_validation_proof
                .public_inputs
                .iter()
                .map(|x| x.to_canonical_u64())
                .collect::<Vec<_>>(),
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
            account_tree_root: target.account_tree_root,
            tx_tree_root: target.signature.tx_tree_root,
            sender_tree_root: target.sender_tree_root,
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

    pub fn add_proof_target_and_verify(
        &self,
        builder: &mut CircuitBuilder<F, D>,
    ) -> ProofWithPublicInputsTarget<D> {
        let proof = builder.add_virtual_proof_with_pis(&self.data.common);
        let vd_target = builder.constant_verifier_data(&self.data.verifier_only);
        builder.verify_proof::<C>(&proof, &vd_target, &self.data.common);
        proof
    }
}

#[cfg(test)]
mod tests {
    use plonky2::{
        field::goldilocks_field::GoldilocksField, plonk::config::PoseidonGoldilocksConfig,
    };
    use rand::Rng;

    use crate::{
        circuits::validity::block_validation::{
            account_exclusion::{AccountExclusionCircuit, AccountExclusionValue},
            account_inclusion::AccountInclusionCircuit,
            aggregation::{AggregationCircuit, AggregationValue},
            format_validation::{FormatValidationCircuit, FormatValidationValue},
        },
        common::{signature::key_set::KeySet, tx::Tx},
        constants::NUM_SENDERS_IN_BLOCK,
        mock::{
            block_builder::{MockBlockBuilder, TxResuest},
            db::MockDB,
        },
    };

    use super::{MainValidationCircuit, MainValidationValue};

    type F = GoldilocksField;
    const D: usize = 2;
    type C = PoseidonGoldilocksConfig;

    #[test]
    fn main_validation() {
        let account_inclusion_circuit = AccountInclusionCircuit::<F, C, D>::new();
        let account_exclusion_circuit = AccountExclusionCircuit::<F, C, D>::new();
        let format_validation_circuit = FormatValidationCircuit::<F, C, D>::new();
        let aggregation_circuit = AggregationCircuit::<F, C, D>::new();

        let main_validation_circuit = MainValidationCircuit::<F, C, D>::new(
            &account_inclusion_circuit,
            &account_exclusion_circuit,
            &format_validation_circuit,
            &aggregation_circuit,
        );

        let mut rng = rand::thread_rng();
        let mut mock_db = MockDB::new();
        let mock_block_builder = MockBlockBuilder {};
        let txs = (0..NUM_SENDERS_IN_BLOCK)
            .map(|_| {
                let sender = KeySet::rand(&mut rng);
                TxResuest {
                    tx: Tx::rand(&mut rng),
                    sender,
                    will_return_signature: rng.gen_bool(0.5),
                }
            })
            .collect::<Vec<_>>();

        let block_info = mock_block_builder.generate_block(&mut mock_db, true, txs);
        let block_witness = block_info.block_witness;

        // generate account exclusion proof
        let account_exclusion_value = AccountExclusionValue::new(
            block_witness.account_tree_root,
            block_witness.account_membership_proofs.unwrap(),
            block_witness.pubkeys.clone(),
        );
        let account_exclusion_proof = account_exclusion_circuit
            .prove(&account_exclusion_value)
            .unwrap();

        let format_validation_value = FormatValidationValue::new(
            block_witness.pubkeys.clone(),
            block_witness.signature.clone(),
        );
        let format_validation_proof = format_validation_circuit
            .prove(&format_validation_value)
            .unwrap();

        let aggregation_value = AggregationValue::new(
            block_witness.pubkeys.clone(),
            block_witness.signature.clone(),
        );
        let aggregation_proof = aggregation_circuit.prove(&aggregation_value).unwrap();

        let instant = std::time::Instant::now();
        let main_validation_value = MainValidationValue::new(
            &account_inclusion_circuit,
            &account_exclusion_circuit,
            &format_validation_circuit,
            &aggregation_circuit,
            block_witness.block,
            block_witness.signature,
            block_witness.pubkeys,
            block_witness.account_tree_root,
            None,
            Some(account_exclusion_proof),
            format_validation_proof,
            Some(aggregation_proof),
        );
        assert!(main_validation_value.is_valid);
        let _main_validation_proof = main_validation_circuit
            .prove(
                account_inclusion_circuit.dummy_proof,
                account_exclusion_circuit.dummy_proof,
                aggregation_circuit.dummy_proof,
                &main_validation_value,
            )
            .unwrap();
        println!(
            "main validation proof generation time: {:?}",
            instant.elapsed()
        );
    }
}
