use plonky2::{
    field::goldilocks_field::GoldilocksField,
    plonk::{config::PoseidonGoldilocksConfig, proof::ProofWithPublicInputs},
};

use crate::{
    circuits::{utils::wrapper::WrapperCircuit, validity::validity_circuit::ValidityCircuit},
    ethereum_types::address::Address,
    wrapper_config::plonky2_config::PoseidonBN128GoldilocksConfig,
};
use anyhow::Result;

use super::fraud_circuit::FraudCircuit;

type F = GoldilocksField;
const D: usize = 2;
type C = PoseidonGoldilocksConfig;
type OuterC = PoseidonBN128GoldilocksConfig;

pub struct FraudProcessor {
    pub fraud_circuit: FraudCircuit<F, C, D>,
    pub wrapper_circuit0: WrapperCircuit<F, C, C, D>,
    pub wrapper_circuit1: WrapperCircuit<F, C, OuterC, D>,
}

impl FraudProcessor {
    pub fn new(validity_circuit: &ValidityCircuit<F, C, D>) -> Self {
        let fraud_circuit = FraudCircuit::new(validity_circuit);
        let wrapper_circuit0 = WrapperCircuit::new(&fraud_circuit);
        let wrapper_circuit1 = WrapperCircuit::new(&wrapper_circuit0);
        Self {
            fraud_circuit,
            wrapper_circuit0,
            wrapper_circuit1,
        }
    }

    pub fn prove(
        &self,
        challenger: Address<u32>,
        validity_proof: &ProofWithPublicInputs<F, C, D>,
    ) -> Result<ProofWithPublicInputs<F, OuterC, D>> {
        let fraud_proof = self.fraud_circuit.prove(challenger, validity_proof)?;
        let wrapper_proof0 = self.wrapper_circuit0.prove(&fraud_proof)?;
        let wrapper_proof1 = self.wrapper_circuit1.prove(&wrapper_proof0)?;
        Ok(wrapper_proof1)
    }
}
