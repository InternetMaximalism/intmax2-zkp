use anyhow::Result;
use plonky2::{
    field::extension::Extendable,
    hash::hash_types::RichField,
    plonk::{
        config::{AlgebraicHasher, GenericConfig},
        proof::ProofWithPublicInputs,
    },
};

use crate::{
    circuits::validity::validity_pis::{ValidityPublicInputs, VALIDITY_PUBLIC_INPUTS_LEN},
    common::witness::{block_witness::BlockWitness, validity_witness::ValidityWitness},
    utils::conversion::ToU64,
};

use super::validity_circuit::ValidityCircuit;

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
        prev_block_witness: &BlockWitness,
        prev_proof: &Option<ProofWithPublicInputs<F, C, D>>,
        validity_witness: &ValidityWitness,
    ) -> Result<ProofWithPublicInputs<F, C, D>> {
        #[cfg(not(feature = "dummy_validity_proof"))]
        let transition_proof = self
            .transition_processor
            .prove(&prev_block_witness, &validity_witness)?;
        #[cfg(feature = "dummy_validity_proof")]
        let transition_proof = self.dummy_transition_circuit.prove(
            &prev_block_witness.to_validity_pis(),
            &validity_witness.block_witness.to_validity_pis(),
        )?;
        if prev_proof.is_some() {
            let transition_prev_pis = ValidityPublicInputs::from_u64_vec(
                &transition_proof.public_inputs[0..VALIDITY_PUBLIC_INPUTS_LEN].to_u64_vec(),
            );
            let prev_pis = ValidityPublicInputs::from_u64_vec(
                &prev_proof.as_ref().unwrap().public_inputs[0..VALIDITY_PUBLIC_INPUTS_LEN]
                    .to_u64_vec(),
            );
            dbg!(&transition_prev_pis);
            dbg!(&prev_pis);
            assert_eq!(transition_prev_pis, prev_pis);
        }
        dbg!("end of transition proof");
        self.validity_circuit.prove(&transition_proof, &prev_proof)
    }
}
