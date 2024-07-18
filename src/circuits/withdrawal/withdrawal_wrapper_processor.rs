use anyhow::Result;
use plonky2::{
    field::goldilocks_field::GoldilocksField,
    plonk::{config::PoseidonGoldilocksConfig, proof::ProofWithPublicInputs},
};

use crate::{
    ethereum_types::address::Address, utils::wrapper::WrapperCircuit,
    wrapper_config::plonky2_config::PoseidonBN128GoldilocksConfig,
};

use super::{
    withdrawal_circuit::WithdrawalCircuit, withdrawal_wrapper_circuit::WithdrawalWrapCircuit,
};

type F = GoldilocksField;
const D: usize = 2;
type C = PoseidonGoldilocksConfig;
type OuterC = PoseidonBN128GoldilocksConfig;

pub struct WithdrawalWrapperProcessor {
    pub withdrawal_wrapper_circuit: WithdrawalWrapCircuit<F, C, D>,
    pub wrapper_circuit0: WrapperCircuit<F, C, C, D>,
    pub wrapper_circuit1: WrapperCircuit<F, C, OuterC, D>,
}

impl WithdrawalWrapperProcessor {
    pub fn new(withdrawal_circuit: &WithdrawalCircuit<F, C, D>) -> Self {
        let withdrawal_wrapper_circuit = WithdrawalWrapCircuit::new(withdrawal_circuit);
        let wrapper_circuit0 = WrapperCircuit::new(&withdrawal_wrapper_circuit);
        let wrapper_circuit1 = WrapperCircuit::new(&wrapper_circuit0);
        Self {
            withdrawal_wrapper_circuit,
            wrapper_circuit0,
            wrapper_circuit1,
        }
    }

    pub fn prove(
        &self,
        withdrawal_proof: &ProofWithPublicInputs<F, C, D>,
        withdrawal_aggregator: Address,
    ) -> Result<ProofWithPublicInputs<F, OuterC, D>> {
        let withdrawal_wrapper_proof = self
            .withdrawal_wrapper_circuit
            .prove(withdrawal_proof, withdrawal_aggregator)?;
        let wrapper_proof0 = self.wrapper_circuit0.prove(&withdrawal_wrapper_proof)?;
        let wrapper_proof1 = self.wrapper_circuit1.prove(&wrapper_proof0)?;
        Ok(wrapper_proof1)
    }
}
