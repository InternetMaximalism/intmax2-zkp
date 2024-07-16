use anyhow::Result;
use plonky2::{
    field::extension::Extendable,
    hash::hash_types::RichField,
    plonk::{
        config::{AlgebraicHasher, GenericConfig},
        proof::ProofWithPublicInputs,
    },
};

use crate::{
    circuits::balance::{
        balance_circuit::BalanceCircuit,
        receive::receive_targets::transfer_inclusion::TransferInclusionValue,
    },
    ethereum_types::{
        bytes32::{Bytes32, BYTES32_LEN},
        u32limb_trait::U32LimbTrait as _,
    },
    utils::conversion::ToU64,
};

use super::{
    withdrawal_circuit::WithdrawalCircuit, withdrawal_inner_circuit::WithdrawalInnerCircuit,
};

pub struct WithdrawalProcessor<F, C, const D: usize>
where
    F: RichField + Extendable<D>,
    C: GenericConfig<D, F = F>,
{
    pub withdrawal_inner_circuit: WithdrawalInnerCircuit<F, C, D>,
    pub withdrawal_circuit: WithdrawalCircuit<F, C, D>,
}

impl<F, C, const D: usize> WithdrawalProcessor<F, C, D>
where
    F: RichField + Extendable<D>,
    C: GenericConfig<D, F = F> + 'static,
    <C as GenericConfig<D>>::Hasher: AlgebraicHasher<F>,
{
    pub fn new(balance_circuit: &BalanceCircuit<F, C, D>) -> Self {
        let withdrawal_inner_circuit = WithdrawalInnerCircuit::new(balance_circuit);
        let withdrawal_circuit = WithdrawalCircuit::new(&withdrawal_inner_circuit);
        Self {
            withdrawal_inner_circuit,
            withdrawal_circuit,
        }
    }

    pub fn prove(
        &self,
        transition_inclusion_value: &TransferInclusionValue<F, C, D>,
        prev_withdrawal_proof: &Option<ProofWithPublicInputs<F, C, D>>,
    ) -> Result<ProofWithPublicInputs<F, C, D>> {
        let prev_withdrawal_hash = if prev_withdrawal_proof.is_some() {
            Bytes32::from_u64_vec(
                &prev_withdrawal_proof.as_ref().unwrap().public_inputs[0..BYTES32_LEN].to_u64_vec(),
            )
        } else {
            Bytes32::default()
        };
        let withdrawal_inner_proof = self
            .withdrawal_inner_circuit
            .prove(prev_withdrawal_hash, transition_inclusion_value)?;
        let withdrawal_proof = self
            .withdrawal_circuit
            .prove(&withdrawal_inner_proof, prev_withdrawal_proof)?;
        Ok(withdrawal_proof)
    }
}
