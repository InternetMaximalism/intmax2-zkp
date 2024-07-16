use anyhow::Result;
use plonky2::{
    field::goldilocks_field::GoldilocksField,
    plonk::{config::PoseidonGoldilocksConfig, proof::ProofWithPublicInputs},
};

use crate::{
    circuits::balance::balance_circuit::BalanceCircuit,
    common::witness::withdrawal_witness::WithdrawalWitness, utils::wrapper::WrapperCircuit,
    wrapper_config::plonky2_config::PoseidonBN128GoldilocksConfig,
};

use super::withdrawal_processor::WithdrawalProcessor;

type F = GoldilocksField;
const D: usize = 2;
type C = PoseidonGoldilocksConfig;
type OuterC = PoseidonBN128GoldilocksConfig;

pub struct WithdrawalWrapperProcessor {
    pub withdrawal_processor: WithdrawalProcessor<F, C, D>,
    pub wrapper_circuit0: WrapperCircuit<F, C, C, D>,
    pub wrapper_circuit1: WrapperCircuit<F, C, OuterC, D>,
}

impl WithdrawalWrapperProcessor {
    pub fn new(balance_circuit: &BalanceCircuit<F, C, D>) -> Self {
        let withdrawal_processor = WithdrawalProcessor::new(balance_circuit);
        let wrapper_circuit0 = WrapperCircuit::new(&withdrawal_processor.withdrawal_circuit);
        let wrapper_circuit1 = WrapperCircuit::new(&wrapper_circuit0);
        Self {
            withdrawal_processor,
            wrapper_circuit0,
            wrapper_circuit1,
        }
    }

    pub fn prove(
        &self,
        withdrawal_witness: &WithdrawalWitness<F, C, D>,
        prev_withdrawal_proof: &Option<ProofWithPublicInputs<F, C, D>>,
    ) -> Result<ProofWithPublicInputs<F, OuterC, D>> {
        let withdrawal_proof = self
            .withdrawal_processor
            .prove(withdrawal_witness, prev_withdrawal_proof)?;
        let wrapper_proof0 = self.wrapper_circuit0.prove(&withdrawal_proof)?;
        let wrapper_proof1 = self.wrapper_circuit1.prove(&wrapper_proof0)?;
        Ok(wrapper_proof1)
    }
}
