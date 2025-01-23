use plonky2::{
    field::extension::Extendable,
    hash::hash_types::RichField,
    plonk::{
        circuit_data::VerifierCircuitData,
        config::{AlgebraicHasher, GenericConfig},
        proof::ProofWithPublicInputs,
    },
};

use super::{deposit_time::DepositTimeCircuit, single_claim_proof::SingleClaimCircuit};

#[derive(Debug)]
pub struct SingleClaimProcessor<F, C, const D: usize>
where
    F: RichField + Extendable<D>,
    C: GenericConfig<D, F = F>,
{
    pub start_time_circuit: DepositTimeCircuit<F, C, D>,
    pub single_claim_circuit: SingleClaimCircuit<F, C, D>,
}

impl<F, C, const D: usize> SingleClaimProcessor<F, C, D>
where
    F: RichField + Extendable<D>,
    C: GenericConfig<D, F = F> + 'static,
    <C as GenericConfig<D>>::Hasher: AlgebraicHasher<F>,
{
    pub fn new(validity_vd: &VerifierCircuitData<F, C, D>) -> Self {
        let start_time_circuit = DepositTimeCircuit::new();
        let single_claim_circuit =
            SingleClaimCircuit::new(validity_vd, &start_time_circuit.data.verifier_data());
        Self {
            start_time_circuit,
            single_claim_circuit,
        }
    }

    pub fn prove(&self) -> anyhow::Result<ProofWithPublicInputs<F, C, D>> {
        todo!()
    }
}
