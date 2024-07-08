use anyhow::Result;
use plonky2::{
    field::extension::Extendable,
    hash::hash_types::RichField,
    plonk::{
        config::{AlgebraicHasher, GenericConfig},
        proof::ProofWithPublicInputs,
    },
};

use crate::common::witness::{block_witness::BlockWitness, transition_witness::TransitionWitness};

use super::validity_circuit::ValidityCircuit;

#[cfg(feature = "dummy_validity_proof")]
use super::transition::dummy_wrapper::DummyTransitionWrapperCircuit;

#[cfg(not(feature = "dummy_validity_proof"))]
use super::transition::processor::TransitionProcessor;

pub struct ValdityProcessor<F, C, const D: usize>
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

impl<F, C, const D: usize> ValdityProcessor<F, C, D>
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
        block_witness: &BlockWitness,
        prev_block_witness: &BlockWitness,
        transition_witness: &TransitionWitness,
        prev_proof: &Option<ProofWithPublicInputs<F, C, D>>,
    ) -> Result<ProofWithPublicInputs<F, C, D>> {
        #[cfg(not(feature = "dummy_validity_proof"))]
        let transition_proof = self.transition_processor.prove(
            &block_witness,
            &prev_block_witness,
            &transition_witness,
        )?;
        #[cfg(feature = "dummy_validity_proof")]
        let transition_proof = self.dummy_transition_circuit.prove(
            &prev_block_witness.to_validity_pis(),
            &block_witness.to_validity_pis(),
        )?;
        #[cfg(feature = "dummy_validity_proof")]
        {
            // Just to avoid unused variable warning
            let _ = transition_witness;
            let _ = prev_proof;
        }
        self.validity_circuit.prove(&transition_proof, &prev_proof)
    }
}
