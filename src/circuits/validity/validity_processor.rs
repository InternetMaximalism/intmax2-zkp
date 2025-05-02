use super::error::ValidityProverError;
use plonky2::{
    field::extension::Extendable,
    hash::hash_types::RichField,
    plonk::{
        circuit_data::VerifierCircuitData,
        config::{AlgebraicHasher, GenericConfig},
        proof::ProofWithPublicInputs,
    },
};

use crate::common::witness::validity_witness::ValidityWitness;

use super::{validity_circuit::ValidityCircuit, validity_pis::ValidityPublicInputs};

#[cfg(feature = "dummy_validity_proof")]
use super::transition::dummy_wrapper::DummyValidityTransitionWrapperCircuit;

#[cfg(not(feature = "dummy_validity_proof"))]
use super::transition::processor::ValidityTransitionProcessor;

#[derive(Debug)]
pub struct ValidityProcessor<F, C, const D: usize>
where
    F: RichField + Extendable<D>,
    C: GenericConfig<D, F = F>,
{
    #[cfg(not(feature = "dummy_validity_proof"))]
    pub transition_processor: ValidityTransitionProcessor<F, C, D>,
    #[cfg(feature = "dummy_validity_proof")]
    pub dummy_transition_circuit: DummyValidityTransitionWrapperCircuit<F, C, D>,
    pub validity_circuit: ValidityCircuit<F, C, D>,
}

impl<F, C, const D: usize> Default for ValidityProcessor<F, C, D>
where
    F: RichField + Extendable<D>,
    C: GenericConfig<D, F = F> + 'static,
    <C as GenericConfig<D>>::Hasher: AlgebraicHasher<F>,
{
    fn default() -> Self {
        Self::new()
    }
}

impl<F, C, const D: usize> ValidityProcessor<F, C, D>
where
    F: RichField + Extendable<D>,
    C: GenericConfig<D, F = F> + 'static,
    <C as GenericConfig<D>>::Hasher: AlgebraicHasher<F>,
{
    pub fn new() -> Self {
        #[cfg(not(feature = "dummy_validity_proof"))]
        let transition_processor = ValidityTransitionProcessor::new();
        #[cfg(not(feature = "dummy_validity_proof"))]
        let validity_circuit = ValidityCircuit::new(
            &transition_processor
                .transition_wrapper_circuit
                .data
                .verifier_data(),
        );

        #[cfg(feature = "dummy_validity_proof")]
        let dummy_transition_circuit = DummyValidityTransitionWrapperCircuit::new();
        #[cfg(feature = "dummy_validity_proof")]
        let validity_circuit = ValidityCircuit::new(&dummy_transition_circuit.data.verifier_data());
        Self {
            #[cfg(not(feature = "dummy_validity_proof"))]
            transition_processor,
            #[cfg(feature = "dummy_validity_proof")]
            dummy_transition_circuit,
            validity_circuit,
        }
    }

    pub fn prove(
        &self,
        prev_proof: &Option<ProofWithPublicInputs<F, C, D>>,
        validity_witness: &ValidityWitness,
    ) -> Result<ProofWithPublicInputs<F, C, D>, ValidityProverError> {
        let prev_pis = if prev_proof.is_some() {
            ValidityPublicInputs::from_pis(&prev_proof.as_ref().unwrap().public_inputs).map_err(
                |e| {
                    ValidityProverError::Plonky2Error(format!(
                        "Failed to parse validity public inputs: {}",
                        e
                    ))
                },
            )?
        } else {
            ValidityPublicInputs::genesis()
        };

        // Validate previous account tree root
        if prev_pis.public_state.account_tree_root
            != validity_witness.block_witness.prev_account_tree_root
        {
            return Err(ValidityProverError::PrevAccountTreeRootMismatch {
                expected: prev_pis.public_state.account_tree_root,
                actual: validity_witness.block_witness.prev_account_tree_root,
            });
        }

        // Validate previous block tree root
        if prev_pis.public_state.block_tree_root
            != validity_witness.block_witness.prev_block_tree_root
        {
            return Err(ValidityProverError::PrevBlockTreeRootMismatch {
                expected: prev_pis.public_state.block_tree_root,
                actual: validity_witness.block_witness.prev_block_tree_root,
            });
        }

        // Generate transition proof
        #[cfg(not(feature = "dummy_validity_proof"))]
        let transition_proof = self
            .transition_processor
            .prove(&prev_pis, validity_witness)
            .map_err(ValidityProverError::from)?;

        #[cfg(feature = "dummy_validity_proof")]
        let transition_proof = self
            .dummy_transition_circuit
            .prove(&prev_pis, validity_witness)
            .map_err(ValidityProverError::from)?;

        // Generate validity circuit proof
        self.validity_circuit
            .prove(&transition_proof, prev_proof)
            .map_err(|e| ValidityProverError::ValidityCircuitProofError(e.to_string()))
    }

    pub fn get_verifier_data(&self) -> VerifierCircuitData<F, C, D> {
        self.validity_circuit.data.verifier_data()
    }
}
