use std::sync::OnceLock;

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
    circuits::withdrawal::single_withdrawal_circuit::SingleWithdrawalCircuit,
    common::withdrawal::Withdrawal,
    ethereum_types::address::Address,
    utils::{conversion::ToU64, hash_chain::hash_chain_processor::HashChainProcessor},
};

pub struct WithdrawalAggregator<F, C, const D: usize>
where
    F: RichField + Extendable<D>,
    C: GenericConfig<D, F = F>,
    <C as GenericConfig<D>>::Hasher: AlgebraicHasher<F>,
{
    balance_common_data: CommonCircuitData<F, D>,
    single_withdrawal_circuit: OnceLock<SingleWithdrawalCircuit<F, C, D>>,
    withdrawal_processor: OnceLock<HashChainProcessor<F, C, D>>, // delayed initialization
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
            balance_common_data: balance_common_data.clone(),
            single_withdrawal_circuit: OnceLock::new(),
            withdrawal_processor: OnceLock::new(),
            prev_withdrawal_proof: None,
            withdrawals: vec![],
        }
    }

    pub fn reset(&mut self) {
        let single_withdrawal_circuit = std::mem::take(&mut self.single_withdrawal_circuit);
        let withdrawal_processor = std::mem::take(&mut self.withdrawal_processor);
        let balance_common_data = self.balance_common_data.clone();
        *self = Self {
            balance_common_data,
            single_withdrawal_circuit,
            withdrawal_processor,
            prev_withdrawal_proof: None,
            withdrawals: vec![],
        };
    }

    pub fn add(
        &mut self,
        single_withdrawal_proof: &ProofWithPublicInputs<F, C, D>,
    ) -> anyhow::Result<()> {
        self.single_withdrawal_circuit()
            .verify(single_withdrawal_proof)
            .map_err(|e| anyhow::anyhow!("Invalid single withdrawal proof: {:?}", e))?;
        let withdrawal =
            Withdrawal::from_u64_slice(&single_withdrawal_proof.public_inputs.to_u64_vec());

        let withdrawal_proof = self
            .withdrawal_processor()
            .prove_chain(single_withdrawal_proof, &self.prev_withdrawal_proof)
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
        let prev_withdrawal_proof = self.prev_withdrawal_proof.clone().unwrap();
        let withdrawal_proof = self
            .withdrawal_processor()
            .prove_end(&prev_withdrawal_proof, aggregator)
            .map_err(|e| anyhow::anyhow!("Failed to prove withdrawal wrapper: {}", e))?;

        // reset state
        self.prev_withdrawal_proof = None;
        self.withdrawals.clear();

        Ok((withdrawals, withdrawal_proof))
    }

    pub fn withdrawal_processor(&self) -> &HashChainProcessor<F, C, D> {
        self.withdrawal_processor.get_or_init(|| {
            let single_withdrawal_circuit = self.single_withdrawal_circuit();
            HashChainProcessor::new(&single_withdrawal_circuit.data.verifier_data())
        })
    }

    pub fn single_withdrawal_circuit(&self) -> &SingleWithdrawalCircuit<F, C, D> {
        self.single_withdrawal_circuit
            .get_or_init(|| SingleWithdrawalCircuit::new(&self.balance_common_data))
    }
}
