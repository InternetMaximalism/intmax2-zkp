use anyhow::ensure;
use plonky2::{
    field::extension::Extendable,
    hash::hash_types::RichField,
    plonk::{
        circuit_data::CommonCircuitData,
        config::{AlgebraicHasher, GenericConfig},
        proof::ProofWithPublicInputs,
    },
};

use crate::{
    circuits::withdrawal::{
        single_withdrawal_circuit::SingleWithdrawalCircuit,
        withdrawal_processor::WithdrawalProcessor,
    },
    common::withdrawal::Withdrawal,
    ethereum_types::address::Address,
    utils::conversion::ToU64,
};

pub struct WithdrawalAggregator<F, C, const D: usize>
where
    F: RichField + Extendable<D>,
    C: GenericConfig<D, F = F>,
    <C as GenericConfig<D>>::Hasher: AlgebraicHasher<F>,
{
    withdrawal_processor: WithdrawalProcessor<F, C, D>,
    prev_withdrawal_proof: Option<ProofWithPublicInputs<F, C, D>>,
    withdrawals: Vec<Withdrawal>,
}

impl<F, C, const D: usize> WithdrawalAggregator<F, C, D>
where
    F: RichField + Extendable<D>,
    C: GenericConfig<D, F = F> + 'static,
    <C as GenericConfig<D>>::Hasher: AlgebraicHasher<F>,
{
    pub fn new(balance_common_data: &CommonCircuitData<F, D>) -> Self {
        Self {
            withdrawal_processor: WithdrawalProcessor::new(balance_common_data),
            prev_withdrawal_proof: None,
            withdrawals: vec![],
        }
    }

    pub fn add(
        &mut self,
        single_withdrawl_proof: &ProofWithPublicInputs<F, C, D>,
    ) -> anyhow::Result<()> {
        self.withdrawal_processor
            .single_withdrawal_circuit
            .verify(single_withdrawl_proof)
            .map_err(|e| anyhow::anyhow!("Invalid single withdrawal proof: {:?}", e))?;
        let withdrawal =
            Withdrawal::from_u64_slice(&single_withdrawl_proof.public_inputs.to_u64_vec());

        let withdrawal_proof = self
            .withdrawal_processor
            .prove_chain(single_withdrawl_proof, &self.prev_withdrawal_proof)
            .map_err(|e| anyhow::anyhow!("Failed to prove withdrawal chain: {}", e))?;

        self.prev_withdrawal_proof = Some(withdrawal_proof);
        self.withdrawals.push(withdrawal);
        Ok(())
    }

    pub fn wrap(
        &mut self,
        aggregator: Address,
    ) -> anyhow::Result<(Vec<Withdrawal>, ProofWithPublicInputs<F, C, D>)> {
        ensure!(
            !self.withdrawals.is_empty(),
            "No withdrawals to wrap into a proof"
        );

        let withdrawals = self.withdrawals.clone();
        let withdrawal_proof = self
            .withdrawal_processor
            .prove_wrap(&self.prev_withdrawal_proof.as_ref().unwrap(), aggregator)
            .map_err(|e| anyhow::anyhow!("Failed to prove withdrawal wrapper: {}", e))?;

        // reset state
        self.prev_withdrawal_proof = None;
        self.withdrawals.clear();

        Ok((withdrawals, withdrawal_proof))
    }

    pub fn single_withdrawal_circuit(&self) -> &SingleWithdrawalCircuit<F, C, D> {
        &self.withdrawal_processor.single_withdrawal_circuit
    }
}
