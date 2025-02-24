use plonky2::{
    field::extension::Extendable,
    hash::hash_types::RichField,
    plonk::{
        circuit_data::VerifierCircuitData,
        config::{AlgebraicHasher, GenericConfig},
        proof::ProofWithPublicInputs,
    },
};

use crate::{
    circuits::claim::single_claim_proof::SingleClaimValue,
    common::witness::claim_witness::ClaimWitness,
};

use super::{deposit_time::DepositTimeCircuit, single_claim_proof::SingleClaimCircuit};

#[derive(Debug)]
pub struct SingleClaimProcessor<F, C, const D: usize>
where
    F: RichField + Extendable<D>,
    C: GenericConfig<D, F = F>,
{
    pub validity_vd: VerifierCircuitData<F, C, D>,
    pub deposit_time_circuit: DepositTimeCircuit<F, C, D>,
    pub single_claim_circuit: SingleClaimCircuit<F, C, D>,
}

impl<F, C, const D: usize> SingleClaimProcessor<F, C, D>
where
    F: RichField + Extendable<D>,
    C: GenericConfig<D, F = F> + 'static,
    <C as GenericConfig<D>>::Hasher: AlgebraicHasher<F>,
{
    pub fn new(validity_vd: &VerifierCircuitData<F, C, D>) -> Self {
        let deposit_time_circuit = DepositTimeCircuit::new();
        let single_claim_circuit =
            SingleClaimCircuit::new(validity_vd, &deposit_time_circuit.data.verifier_data());
        Self {
            validity_vd: validity_vd.clone(),
            deposit_time_circuit,
            single_claim_circuit,
        }
    }

    pub fn get_verifier_data(&self) -> VerifierCircuitData<F, C, D> {
        self.single_claim_circuit.data.verifier_data()
    }

    pub fn prove(
        &self,
        claim_witness: &ClaimWitness<F, C, D>,
    ) -> anyhow::Result<ProofWithPublicInputs<F, C, D>> {
        let deposit_time_value = claim_witness
            .deposit_time_witness
            .to_value()
            .map_err(|e| anyhow::anyhow!("failed to create deposit_time_value: {}", e))?;
        let deposit_time_proof = self.deposit_time_circuit.prove(&deposit_time_value)?;

        let single_claim_value = SingleClaimValue::new(
            &self.validity_vd,
            &self.deposit_time_circuit.data.verifier_data(),
            claim_witness.recipient,
            &claim_witness.update_witness.block_merkle_proof,
            &claim_witness.update_witness.account_membership_proof,
            &claim_witness.update_witness.validity_proof,
            &deposit_time_proof,
        )
        .map_err(|e| anyhow::anyhow!("failed to create single_claim_value: {}", e))?;
        let single_claim_proof = self.single_claim_circuit.prove(&single_claim_value)?;
        Ok(single_claim_proof)
    }
}
