use plonky2::{
    field::extension::Extendable,
    hash::hash_types::RichField,
    plonk::{
        config::{AlgebraicHasher, GenericConfig},
        proof::ProofWithPublicInputs,
    },
};

use crate::{
    circuits::validity::block_validation::processor::MainValidationProcessor,
    common::witness::{block_witness::BlockWitness, transition_witness::TransitionWitness},
};

use super::{
    account_registoration::AccountRegistorationCircuit, account_update::AccountUpdateCircuit,
    wrapper::TransitionWrapperCircuit,
};
use anyhow::Result;

pub struct TransitionProcessor<F, C, const D: usize>
where
    F: RichField + Extendable<D>,
    C: GenericConfig<D, F = F>,
{
    pub main_validation_processor: MainValidationProcessor<F, C, D>,
    pub account_registoration_circuit: AccountRegistorationCircuit<F, C, D>,
    pub account_update_circuit: AccountUpdateCircuit<F, C, D>,
    pub transition_wrapper_circuit: TransitionWrapperCircuit<F, C, D>,
}

impl<F, C, const D: usize> TransitionProcessor<F, C, D>
where
    F: RichField + Extendable<D>,
    C: GenericConfig<D, F = F> + 'static,
    <C as GenericConfig<D>>::Hasher: AlgebraicHasher<F>,
{
    pub fn new() -> Self {
        let main_validation_processor = MainValidationProcessor::new();
        let account_registoration_circuit = AccountRegistorationCircuit::new();
        let account_update_circuit = AccountUpdateCircuit::new();
        let transition_wrapper_circuit = TransitionWrapperCircuit::new(
            &main_validation_processor.main_validation_circuit,
            &account_registoration_circuit,
            &account_update_circuit,
        );
        Self {
            main_validation_processor,
            account_registoration_circuit,
            account_update_circuit,
            transition_wrapper_circuit,
        }
    }

    pub fn prove(
        &self,
        prev_block_witness: &BlockWitness,
        block_witness: &BlockWitness,
        transition_witness: &TransitionWitness,
    ) -> Result<ProofWithPublicInputs<F, C, D>> {
        todo!()
    }
}
