use anyhow::Result;
use plonky2::{
    field::goldilocks_field::GoldilocksField,
    plonk::{config::PoseidonGoldilocksConfig, proof::ProofWithPublicInputs},
};

use crate::{
    circuits::{
        balance::{
            balance_circuit::BalanceCircuit,
            receive::receive_targets::transfer_inclusion::TransferInclusionValue,
        },
        utils::wrapper::WrapperCircuit,
    },
    ethereum_types::{
        bytes32::{Bytes32, BYTES32_LEN},
        u32limb_trait::U32LimbTrait as _,
    },
    utils::conversion::ToU64,
    wrapper_config::plonky2_config::PoseidonBN128GoldilocksConfig,
};

use super::{
    withdrawal_circuit::WithdrawalCircuit, withdrawal_inner_circuit::WithdrawalInnerCircuit,
};

type F = GoldilocksField;
const D: usize = 2;
type C = PoseidonGoldilocksConfig;
type OuterC = PoseidonBN128GoldilocksConfig;

pub struct WithdrawalProcessor {
    pub withdrawal_inner_circuit: WithdrawalInnerCircuit<F, C, D>,
    pub withdrawal_circuit: WithdrawalCircuit<F, C, D>,
    pub wrapper_circuit0: WrapperCircuit<F, C, C, D>,
    pub wrapper_circuit1: WrapperCircuit<F, C, OuterC, D>,
}

impl WithdrawalProcessor {
    pub fn new(balance_circuit: &BalanceCircuit<F, C, D>) -> Self {
        let withdrawal_inner_circuit = WithdrawalInnerCircuit::new(balance_circuit);
        let withdrawal_circuit = WithdrawalCircuit::new(&withdrawal_inner_circuit);
        let wrapper_circuit0 = WrapperCircuit::new(&withdrawal_circuit);
        let wrapper_circuit1 = WrapperCircuit::new(&wrapper_circuit0);
        Self {
            withdrawal_inner_circuit,
            withdrawal_circuit,
            wrapper_circuit0,
            wrapper_circuit1,
        }
    }

    pub fn prove(
        &self,
        transition_inclusion_value: &TransferInclusionValue<F, C, D>,
        prev_withdrawal_proof: &Option<ProofWithPublicInputs<F, C, D>>,
    ) -> Result<ProofWithPublicInputs<F, OuterC, D>> {
        let prev_withdrawal_hash = if prev_withdrawal_proof.is_some() {
            Bytes32::<u32>::from_u64_vec(
                &prev_withdrawal_proof.as_ref().unwrap().public_inputs[0..BYTES32_LEN].to_u64_vec(),
            )
        } else {
            Bytes32::<u32>::default()
        };
        let withdrawal_inner_proof = self
            .withdrawal_inner_circuit
            .prove(prev_withdrawal_hash, transition_inclusion_value)?;
        let withdrawal_proof = self
            .withdrawal_circuit
            .prove(&withdrawal_inner_proof, prev_withdrawal_proof)?;
        let wrapper_proof0 = self.wrapper_circuit0.prove(&withdrawal_proof)?;
        let wrapper_proof1 = self.wrapper_circuit1.prove(&wrapper_proof0)?;
        Ok(wrapper_proof1)
    }
}
