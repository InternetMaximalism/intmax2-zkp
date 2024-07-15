use anyhow::Result;
use plonky2::{
    field::extension::Extendable,
    hash::hash_types::RichField,
    plonk::{
        config::{AlgebraicHasher, GenericConfig},
        proof::ProofWithPublicInputs,
    },
};

use crate::common::witness::validity_witness::ValidityWitness;

use super::{validity_circuit::ValidityCircuit, validity_pis::ValidityPublicInputs};

#[cfg(feature = "dummy_validity_proof")]
use super::transition::dummy_wrapper::DummyTransitionWrapperCircuit;

#[cfg(not(feature = "dummy_validity_proof"))]
use super::transition::processor::TransitionProcessor;

pub struct ValidityProcessor<F, C, const D: usize>
where
    F: RichField + Extendable<D>,
    C: GenericConfig<D, F = F>,
{
    #[cfg(not(feature = "dummy_validity_proof"))]
    pub transition_processor: TransitionProcessor<F, C, D>,
    #[cfg(feature = "dummy_validity_proof")]
    pub dummy_transition_circuit: DummyTransitionWrapperCircuit<F, C, D>,
    pub validity_circuit: ValidityCircuit<F, C, D>,
}

impl<F, C, const D: usize> ValidityProcessor<F, C, D>
where
    F: RichField + Extendable<D>,
    C: GenericConfig<D, F = F> + 'static,
    <C as GenericConfig<D>>::Hasher: AlgebraicHasher<F>,
{
    pub fn new() -> Self {
        #[cfg(not(feature = "dummy_validity_proof"))]
        let transition_processor = TransitionProcessor::new();
        #[cfg(not(feature = "dummy_validity_proof"))]
        let validity_circuit =
            ValidityCircuit::new(&transition_processor.transition_wrapper_circuit);

        #[cfg(feature = "dummy_validity_proof")]
        let dummy_transition_circuit = DummyTransitionWrapperCircuit::new();
        #[cfg(feature = "dummy_validity_proof")]
        let validity_circuit = ValidityCircuit::new(&dummy_transition_circuit);
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
    ) -> Result<ProofWithPublicInputs<F, C, D>> {
        let prev_pis = if prev_proof.is_some() {
            ValidityPublicInputs::from_pis(&prev_proof.as_ref().unwrap().public_inputs)
        } else {
            ValidityPublicInputs::genesis()
        };
        // assertion
        assert_eq!(
            prev_pis.public_state.account_tree_root,
            validity_witness.block_witness.prev_account_tree_root
        );
        assert_eq!(
            prev_pis.public_state.block_tree_root,
            validity_witness.block_witness.prev_block_tree_root
        );

        #[cfg(not(feature = "dummy_validity_proof"))]
        let transition_proof = self
            .transition_processor
            .prove(&prev_pis, &validity_witness)?;
        #[cfg(feature = "dummy_validity_proof")]
        let transition_proof = self
            .dummy_transition_circuit
            .prove(&prev_pis, &validity_witness)?;
        self.validity_circuit.prove(&transition_proof, &prev_proof)
    }
}
