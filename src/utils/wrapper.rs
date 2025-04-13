use std::marker::PhantomData;

use crate::utils::error::{Result, UtilsError, WrapperError};
use plonky2::{
    field::extension::Extendable,
    hash::hash_types::RichField,
    iop::witness::{PartialWitness, WitnessWrite as _},
    plonk::{
        circuit_builder::CircuitBuilder,
        circuit_data::{CircuitConfig, CircuitData, VerifierCircuitData},
        config::{AlgebraicHasher, GenericConfig},
        proof::{ProofWithPublicInputs, ProofWithPublicInputsTarget},
    },
};

use super::recursively_verifiable::add_proof_target_and_verify;

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
    pub fn new(inner_circuit_verifier_data: &VerifierCircuitData<F, InnerC, D>) -> Self {
        let mut builder = CircuitBuilder::new(CircuitConfig::default());
        let wrap_proof = add_proof_target_and_verify(inner_circuit_verifier_data, &mut builder);
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
    ) -> Result<ProofWithPublicInputs<F, OuterC, D>> {
        let mut pw = PartialWitness::new();
        pw.set_proof_with_pis_target(&self.wrap_proof, inner_proof);
        self.data
            .prove(pw)
            .map_err(|e| UtilsError::from(WrapperError::ProofGenerationFailed(format!("{}", e))))
    }
}
