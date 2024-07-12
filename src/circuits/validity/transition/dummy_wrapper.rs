use anyhow::Result;
use plonky2::{
    field::extension::Extendable,
    hash::hash_types::RichField,
    iop::witness::PartialWitness,
    plonk::{
        circuit_builder::CircuitBuilder,
        circuit_data::{CircuitConfig, CircuitData},
        config::{AlgebraicHasher, GenericConfig},
        proof::ProofWithPublicInputs,
    },
};

use crate::{
    circuits::validity::validity_pis::ValidityPublicInputsTarget,
    common::witness::{block_witness::BlockWitness, validity_witness::ValidityWitness},
    utils::recursivable::Recursivable,
};

/// A dummy implementation of the transition wrapper circuit used for testing balance proof.
pub struct DummyTransitionWrapperCircuit<F, C, const D: usize>
where
    F: RichField + Extendable<D>,
    C: GenericConfig<D, F = F>,
{
    pub data: CircuitData<F, C, D>,
    pub prev_pis: ValidityPublicInputsTarget,
    pub new_pis: ValidityPublicInputsTarget,
}

impl<F, C, const D: usize> DummyTransitionWrapperCircuit<F, C, D>
where
    F: RichField + Extendable<D>,
    C: GenericConfig<D, F = F> + 'static,
    C::Hasher: AlgebraicHasher<F>,
{
    pub fn new() -> Self {
        let mut builder = CircuitBuilder::<F, D>::new(CircuitConfig::default());
        let prev_pis = ValidityPublicInputsTarget::new(&mut builder, false);
        let new_pis = ValidityPublicInputsTarget::new(&mut builder, false);
        let concat_pis = vec![prev_pis.to_vec(), new_pis.to_vec()].concat();
        builder.register_public_inputs(&concat_pis);
        let data = builder.build::<C>();
        Self {
            data,
            prev_pis,
            new_pis,
        }
    }
}

impl<F, C, const D: usize> DummyTransitionWrapperCircuit<F, C, D>
where
    F: RichField + Extendable<D>,
    C: GenericConfig<D, F = F> + 'static,
    C::Hasher: AlgebraicHasher<F>,
{
    pub fn prove(
        &self,
        prev_block_witness: &BlockWitness,
        validity_witness: &ValidityWitness,
    ) -> Result<ProofWithPublicInputs<F, C, D>> {
        let prev_pis = prev_block_witness.to_validity_pis();
        let new_pis = validity_witness.block_witness.to_validity_pis();

        // assertion
        let new_roots = validity_witness.validity_transition_witness.new_roots();
        assert_eq!(
            new_pis.public_state.account_tree_root,
            new_roots.account_tree_root
        );
        assert_eq!(
            new_pis.public_state.block_tree_root,
            new_roots.block_tree_root
        );

        let mut pw = PartialWitness::<F>::new();
        self.prev_pis.set_witness(&mut pw, &prev_pis);
        self.new_pis.set_witness(&mut pw, &new_pis);
        self.data.prove(pw)
    }
}

impl<F, C, const D: usize> Recursivable<F, C, D> for DummyTransitionWrapperCircuit<F, C, D>
where
    F: RichField + Extendable<D>,
    C: GenericConfig<D, F = F> + 'static,
    C::Hasher: AlgebraicHasher<F>,
{
    fn circuit_data(&self) -> &CircuitData<F, C, D> {
        &self.data
    }
}
