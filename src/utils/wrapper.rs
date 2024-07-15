use std::marker::PhantomData;

use plonky2::{
    field::extension::Extendable,
    hash::hash_types::RichField,
    iop::witness::{PartialWitness, WitnessWrite as _},
    plonk::{
        circuit_builder::CircuitBuilder,
        circuit_data::{CircuitConfig, CircuitData},
        config::{AlgebraicHasher, GenericConfig},
        proof::{ProofWithPublicInputs, ProofWithPublicInputsTarget},
    },
};

use crate::utils::recursivable::Recursivable;

pub struct WrapperCircuit<F, InnerC, OuterC, const D: usize>
where
    F: RichField + Extendable<D>,
    InnerC: GenericConfig<D, F = F>,
    OuterC: GenericConfig<D, F = F>,
{
    pub data: CircuitData<F, OuterC, D>,
    pub wrap_proof: ProofWithPublicInputsTarget<D>,
    _maker: PhantomData<InnerC>,
}

impl<F, InnerC, OuterC, const D: usize> WrapperCircuit<F, InnerC, OuterC, D>
where
    F: RichField + Extendable<D>,
    OuterC: GenericConfig<D, F = F>,
    InnerC: GenericConfig<D, F = F> + 'static,
    InnerC::Hasher: AlgebraicHasher<F>,
{
    pub fn new(inner_circuit: &impl Recursivable<F, InnerC, D>) -> Self {
        let mut builder = CircuitBuilder::new(CircuitConfig::default());
        let wrap_proof = inner_circuit.add_proof_target_and_verify(&mut builder);
        builder.register_public_inputs(&wrap_proof.public_inputs);
        let data = builder.build();
        Self {
            data,
            wrap_proof,
            _maker: PhantomData,
        }
    }

    pub fn prove(
        &self,
        inner_proof: &ProofWithPublicInputs<F, InnerC, D>,
    ) -> anyhow::Result<ProofWithPublicInputs<F, OuterC, D>> {
        let mut pw = PartialWitness::new();
        pw.set_proof_with_pis_target(&self.wrap_proof, inner_proof);
        self.data.prove(pw)
    }
}

impl<F, InnerC, OuterC, const D: usize> Recursivable<F, OuterC, D>
    for WrapperCircuit<F, InnerC, OuterC, D>
where
    F: RichField + Extendable<D>,
    OuterC: GenericConfig<D, F = F> + 'static,
    OuterC::Hasher: AlgebraicHasher<F>,
    InnerC: GenericConfig<D, F = F> + 'static,
    InnerC::Hasher: AlgebraicHasher<F>,
{
    fn circuit_data(&self) -> &CircuitData<F, OuterC, D> {
        &self.data
    }
}
