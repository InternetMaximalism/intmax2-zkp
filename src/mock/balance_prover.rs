use plonky2::{
    field::extension::Extendable,
    hash::hash_types::RichField,
    plonk::{
        config::{AlgebraicHasher, GenericConfig},
        proof::ProofWithPublicInputs,
    },
};

use super::{data::deposit_data::DepositData, sync_validity_prover::SyncValidityProver};

pub struct BalanceProver;

impl BalanceProver {
    pub fn process_deposit<F, C, const D: usize>(
        &self,
        validity_prover: &SyncValidityProver<F, C, D>,
        balance_proof: &ProofWithPublicInputs<F, C, D>,
        deposit_data: &DepositData,
    ) -> anyhow::Result<()>
    where
        F: RichField + Extendable<D>,
        C: GenericConfig<D, F = F> + 'static,
        <C as GenericConfig<D>>::Hasher: AlgebraicHasher<F>,
    {
        let account_id = sync_validity_prover
            .get_account_id(deposit.pubkey)
            .ok_or(anyhow::anyhow!("account not found"))?;
        let account = contract.get_account(account_id);
        let balance = account.balance;
        let new_balance = balance + deposit.amount;
        contract.set_account_balance(account_id, new_balance);
        Ok(())
    }
}
