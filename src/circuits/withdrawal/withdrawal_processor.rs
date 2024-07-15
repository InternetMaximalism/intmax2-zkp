use plonky2::{field::goldilocks_field::GoldilocksField, plonk::config::PoseidonGoldilocksConfig};

use crate::{
    circuits::{balance::balance_circuit::BalanceCircuit, utils::wrapper::WrapperCircuit},
    wrapper_config::plonky2_config::PoseidonBN128GoldilocksConfig,
};

use super::withdrawal_circuit::WithdrawalCircuit;

type F = GoldilocksField;
const D: usize = 2;
type C = PoseidonGoldilocksConfig;
type OuterC = PoseidonBN128GoldilocksConfig;

pub struct WithdrawalProcessor {
    pub withdrawal_circuit: WithdrawalCircuit<F, C, D>,
    pub wrapper_circuit0: WrapperCircuit<F, C, C, D>,
    pub wrapper_circuit1: WrapperCircuit<F, C, OuterC, D>,
}

impl WithdrawalProcessor {
    pub fn new(balance_circuit: &BalanceCircuit<F, C, D>) -> Self {
        let withdrawal_circuit = WithdrawalCircuit::new(balance_circuit);
        let wrapper_circuit0 = WrapperCircuit::new(&withdrawal_circuit);
        let wrapper_circuit1 = WrapperCircuit::new(&wrapper_circuit0);
        Self {
            withdrawal_circuit,
            wrapper_circuit0,
            wrapper_circuit1,
        }
    }

    // pub fn prove(
    //     &self,
    //     challenger: Address<u32>,
    //     validity_proof: &ProofWithPublicInputs<F, C, D>,
    // ) -> Result<ProofWithPublicInputs<F, OuterC, D>> {
    //     let withdrawal_proof = self.withdrawal_circuit.prove(challenger, validity_proof)?;
    //     let wrapper_proof0 = self.wrapper_circuit0.prove(&withdrawal_proof)?;
    //     let wrapper_proof1 = self.wrapper_circuit1.prove(&wrapper_proof0)?;
    //     Ok(wrapper_proof1)
    // }
}
