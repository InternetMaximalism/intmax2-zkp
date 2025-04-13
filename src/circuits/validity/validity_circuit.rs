//! Validity circuit for proving the correctness of block validation and state transitions.
//!
//! This circuit implements an Incremental Verifiable Computation ZKP that:
//! 1. Verifies the previous validity proof (or initializes with genesis state if first step)
//! 2. Verifies a transition proof that validates block correctness and updates account/block trees
//! 3. Produces a new validity proof that can be used in subsequent block validations
//!
//! The validity circuit advances one step each time a new block is processed, ensuring:
//! - Blocks submitted to the contract are correctly formatted and signed
//! - Account registrations in registration blocks are valid
//! - Account updates in non-registration blocks are valid
//! - Account tree and block hash tree transitions are correctly performed
//!
//! This forms a chain of proofs that maintains the integrity of the rollup state.

use crate::{
    circuits::validity::{
        error::ValidityProverError,
        validity_pis::{
            ValidityPublicInputs, ValidityPublicInputsTarget, VALIDITY_PUBLIC_INPUTS_LEN,
        },
    },
    constants::CYCLIC_CIRCUIT_PADDING_DEGREE,
    utils::{
        conversion::ToField, cyclic::vd_vec_len,
        recursively_verifiable::add_proof_target_and_verify,
    },
};
use plonky2::{
    field::extension::Extendable,
    gates::noop::NoopGate,
    hash::hash_types::RichField,
    iop::{
        target::BoolTarget,
        witness::{PartialWitness, WitnessWrite as _},
    },
    plonk::{
        circuit_builder::CircuitBuilder,
        circuit_data::{
            CircuitConfig, CircuitData, CommonCircuitData, VerifierCircuitData,
            VerifierCircuitTarget,
        },
        config::{AlgebraicHasher, GenericConfig},
        proof::{ProofWithPublicInputs, ProofWithPublicInputsTarget},
    },
    recursion::{
        cyclic_recursion::check_cyclic_proof_verifier_data, dummy_circuit::cyclic_base_proof,
    },
};

/// Validity circuit for proving the correctness of block validation and state transitions.
///
/// This circuit implements an IVC (Incremental Verifiable Computation) pattern where:
/// - Each proof represents a valid state of the L2 system after processing a block
/// - The circuit recursively verifies the previous proof in the chain
/// - A transition proof is verified to ensure block validity and correct state transitions
/// - A new proof is generated that can be used for the next block validation
///
/// The circuit handles both the first step (genesis state) and subsequent steps
/// by conditionally verifying either a dummy proof or the actual previous proof.
#[derive(Debug)]
pub struct ValidityCircuit<F, C, const D: usize>
where
    F: RichField + Extendable<D>,
    C: GenericConfig<D, F = F>,
{
    pub data: CircuitData<F, C, D>, // Circuit data containing the compiled circuit
    is_first_step: BoolTarget,      // Flag indicating if this is the first proof in the chain
    transition_proof: ProofWithPublicInputsTarget<D>, /* Proof of the block validation and state
                                     * transition */
    prev_proof: ProofWithPublicInputsTarget<D>, // Previous validity proof in the chain
    verifier_data_target: VerifierCircuitTarget, // Verifier data for the circuit
}

impl<F, C, const D: usize> ValidityCircuit<F, C, D>
where
    F: RichField + Extendable<D>,
    C: GenericConfig<D, F = F> + 'static,
    C::Hasher: AlgebraicHasher<F>,
{
    pub fn new(
        #[cfg(not(feature = "dummy_validity_proof"))] transition_wrap_vd: &VerifierCircuitData<
            F,
            C,
            D,
        >,
        #[cfg(feature = "dummy_validity_proof")] dummy_transition_wrap_vd: &VerifierCircuitData<
            F,
            C,
            D,
        >,
    ) -> Self {
        let mut builder = CircuitBuilder::<F, D>::new(CircuitConfig::default());
        let is_first_step = builder.add_virtual_bool_target_safe();
        let is_not_first_step = builder.not(is_first_step);

        #[cfg(not(feature = "dummy_validity_proof"))]
        let transition_proof = add_proof_target_and_verify(transition_wrap_vd, &mut builder);
        #[cfg(feature = "dummy_validity_proof")]
        let transition_proof = add_proof_target_and_verify(dummy_transition_wrap_vd, &mut builder);

        let prev_pis_ = ValidityPublicInputsTarget::from_slice(
            &transition_proof.public_inputs[0..VALIDITY_PUBLIC_INPUTS_LEN],
        );
        let new_pis = ValidityPublicInputsTarget::from_slice(
            &transition_proof.public_inputs[VALIDITY_PUBLIC_INPUTS_LEN..],
        );
        builder.register_public_inputs(&new_pis.to_vec());

        let common_data = common_data_for_validity_circuit::<F, C, D>();
        let verifier_data_target = builder.add_verifier_data_public_inputs();

        let prev_proof = builder.add_virtual_proof_with_pis(&common_data);
        builder
            .conditionally_verify_cyclic_proof_or_dummy::<C>(
                is_not_first_step,
                &prev_proof,
                &common_data,
            )
            .unwrap();
        let prev_pis = ValidityPublicInputsTarget::from_slice(
            &prev_proof.public_inputs[0..VALIDITY_PUBLIC_INPUTS_LEN],
        );
        prev_pis.connect(&mut builder, &prev_pis_);
        let genesis_pis = ValidityPublicInputs::genesis();
        let genesis_pis_t = ValidityPublicInputsTarget::constant(&mut builder, &genesis_pis);
        prev_pis.conditional_assert_eq(&mut builder, &genesis_pis_t, is_first_step);

        let (data, success) = builder.try_build_with_options::<C>(true);
        assert_eq!(data.common, common_data);
        assert!(success);
        Self {
            data,
            is_first_step,
            transition_proof,
            prev_proof,
            verifier_data_target,
        }
    }

    /// Generates a ZK proof for the validity circuit.
    ///
    /// This method:
    /// 1. Creates a partial witness with all necessary values
    /// 2. Sets the appropriate flags based on whether this is the first step
    /// 3. Verifies the transition proof and connects it to the previous proof
    /// 4. Generates a proof that can be verified by others
    ///
    /// # Arguments
    /// * `transition_proof` - Proof of the block validation and state transition
    /// * `prev_proof` - Optional previous validity proof (None if this is the first step)
    ///
    /// # Returns
    /// A Result containing either the proof or an error if validation or proof generation fails
    pub fn prove(
        &self,
        transition_proof: &ProofWithPublicInputs<F, C, D>,
        prev_proof: &Option<ProofWithPublicInputs<F, C, D>>,
    ) -> Result<ProofWithPublicInputs<F, C, D>, ValidityProverError> {
        let mut pw = PartialWitness::<F>::new();
        pw.set_verifier_data_target(&self.verifier_data_target, &self.data.verifier_only);
        pw.set_proof_with_pis_target(&self.transition_proof, transition_proof);
        if prev_proof.is_none() {
            let dummy_proof = cyclic_base_proof(
                &self.data.common,
                &self.data.verifier_only,
                ValidityPublicInputs::genesis()
                    .to_u64_vec()
                    .to_field_vec::<F>()
                    .into_iter()
                    .enumerate()
                    .collect(),
            );
            pw.set_bool_target(self.is_first_step, true);
            pw.set_proof_with_pis_target(&self.prev_proof, &dummy_proof);
        } else {
            pw.set_bool_target(self.is_first_step, false);
            pw.set_proof_with_pis_target(&self.prev_proof, prev_proof.as_ref().unwrap());
        }
        self.data
            .prove(pw)
            .map_err(|e| ValidityProverError::ValidityCircuitProofError(e.to_string()))
    }

    pub fn verify(
        &self,
        proof: &ProofWithPublicInputs<F, C, D>,
    ) -> Result<(), ValidityProverError> {
        check_cyclic_proof_verifier_data(proof, &self.data.verifier_only, &self.data.common)
            .map_err(|e| ValidityProverError::Plonky2Error(e.to_string()))?;
        self.data
            .verify(proof.clone())
            .map_err(|e| ValidityProverError::Plonky2Error(e.to_string()))
    }
}

/// Generates `CommonCircuitData` for the cyclic validity circuit.
fn common_data_for_validity_circuit<
    F: RichField + Extendable<D>,
    C: GenericConfig<D, F = F>,
    const D: usize,
>() -> CommonCircuitData<F, D>
where
    C::Hasher: AlgebraicHasher<F>,
{
    let builder = CircuitBuilder::<F, D>::new(CircuitConfig::default());
    let data = builder.build::<C>();

    let mut builder = CircuitBuilder::<F, D>::new(CircuitConfig::default());
    let proof = builder.add_virtual_proof_with_pis(&data.common);
    let verifier_data = VerifierCircuitTarget {
        constants_sigmas_cap: builder.add_virtual_cap(data.common.config.fri_config.cap_height),
        circuit_digest: builder.add_virtual_hash(),
    };
    builder.verify_proof::<C>(&proof, &verifier_data, &data.common);
    let data = builder.build::<C>();

    let mut builder = CircuitBuilder::<F, D>::new(CircuitConfig::default());
    let proof = builder.add_virtual_proof_with_pis(&data.common);
    let verifier_data = VerifierCircuitTarget {
        constants_sigmas_cap: builder.add_virtual_cap(data.common.config.fri_config.cap_height),
        circuit_digest: builder.add_virtual_hash(),
    };
    builder.verify_proof::<C>(&proof, &verifier_data, &data.common);
    while builder.num_gates() < 1 << CYCLIC_CIRCUIT_PADDING_DEGREE {
        builder.add_gate(NoopGate, vec![]);
    }
    let mut common = builder.build::<C>().common;
    common.num_public_inputs = VALIDITY_PUBLIC_INPUTS_LEN + vd_vec_len(&common.config);
    common
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
                transition::dummy_wrapper::DummyValidityTransitionWrapperCircuit,
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
            witness::validity_witness::ValidityWitness,
        },
        constants::NUM_SENDERS_IN_BLOCK,
        ethereum_types::address::Address,
    };

    type F = GoldilocksField;
    type C = PoseidonGoldilocksConfig;
    const D: usize = 2;

    fn generate_test_witness() -> Vec<ValidityWitness> {
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
        let (validity_witness1, _) = construct_validity_and_tx_witness(
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
        prev_validity_pis = validity_witness1.to_validity_pis().unwrap();

        // create a non-registration block
        let tx_requests = keys
            .iter()
            .map(|key| MockTxRequest {
                tx: Tx::rand(&mut rng),
                sender_key: key.clone(),
                will_return_sig: rng.gen_bool(0.5), // some senders return sigs
            })
            .collect::<Vec<_>>();
        let (validity_witness2, _) = construct_validity_and_tx_witness(
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
        vec![validity_witness1, validity_witness2]
    }

    #[test]
    fn test_validity_circuit() {
        use crate::circuits::validity::transition::processor::ValidityTransitionProcessor;

        let validity_witnesses = generate_test_witness();

        let validity_transition_processor = ValidityTransitionProcessor::<F, C, D>::new();
        let validity_circuit = super::ValidityCircuit::<F, C, D>::new(
            &validity_transition_processor
                .transition_wrapper_circuit
                .data
                .verifier_data(),
        );

        let mut prev_validity_pis = ValidityPublicInputs::genesis();
        let transition_proof1 = validity_transition_processor
            .prove(&prev_validity_pis, &validity_witnesses[0])
            .unwrap();
        let validity_proof1 = validity_circuit.prove(&transition_proof1, &None).unwrap();

        // Verify the first proof
        validity_circuit
            .data
            .verify(validity_proof1.clone())
            .unwrap();

        // update the previous validity pis
        prev_validity_pis = ValidityPublicInputs::from_pis(&validity_proof1.public_inputs).unwrap();

        let transition_proof2 = validity_transition_processor
            .prove(&prev_validity_pis, &validity_witnesses[1])
            .unwrap();
        let validity_proof2 = validity_circuit
            .prove(&transition_proof2, &Some(validity_proof1))
            .unwrap();
        // Verify the second proof
        validity_circuit
            .data
            .verify(validity_proof2.clone())
            .unwrap();
    }

    #[test]
    fn test_dummy_validity_circuit() {
        let validity_witnesses = generate_test_witness();

        let dummy_transition_wrapper_circuit =
            DummyValidityTransitionWrapperCircuit::<F, C, D>::new();
        let validity_circuit = super::ValidityCircuit::<F, C, D>::new(
            &dummy_transition_wrapper_circuit.data.verifier_data(),
        );

        let mut prev_validity_pis = ValidityPublicInputs::genesis();
        let transition_proof1 = dummy_transition_wrapper_circuit
            .prove(&prev_validity_pis, &validity_witnesses[0])
            .unwrap();
        let validity_proof1 = validity_circuit.prove(&transition_proof1, &None).unwrap();

        // Verify the first proof
        validity_circuit
            .data
            .verify(validity_proof1.clone())
            .unwrap();

        // update the previous validity pis
        prev_validity_pis = ValidityPublicInputs::from_pis(&validity_proof1.public_inputs).unwrap();

        let transition_proof2 = dummy_transition_wrapper_circuit
            .prove(&prev_validity_pis, &validity_witnesses[1])
            .unwrap();
        let validity_proof2 = validity_circuit
            .prove(&transition_proof2, &Some(validity_proof1))
            .unwrap();
        // Verify the second proof
        validity_circuit
            .data
            .verify(validity_proof2.clone())
            .unwrap();
    }
}
