use plonky2::{
    field::extension::Extendable,
    hash::hash_types::RichField,
    plonk::config::{AlgebraicHasher, GenericConfig},
};

use crate::common::signature::key_set::KeySet;

use crate::mock::{
    block_validity_prover::BlockValidityProver,
    data::{deposit_data::DepositData, meta_data::MetaData},
    store_vault_server::StoreVaultServer,
};

#[derive(Debug, Clone)]
pub struct DepositInfo {
    pub settled: Vec<(MetaData, DepositData)>,
    pub pending: Vec<MetaData>,
    pub rejected: Vec<MetaData>,
}

pub fn fetch_deposit_info<F, C, const D: usize>(
    store_vault_server: &StoreVaultServer<F, C, D>,
    validity_prover: &BlockValidityProver<F, C, D>,
    key: KeySet,
    deposit_lpt: u64,
    deposit_timeout: u64,
) -> anyhow::Result<DepositInfo>
where
    F: RichField + Extendable<D>,
    C: GenericConfig<D, F = F> + 'static,
    <C as GenericConfig<D>>::Hasher: AlgebraicHasher<F>,
{
    let mut settled = Vec::new();
    let mut pending = Vec::new();
    let mut rejected = Vec::new();

    let encrypted_data = store_vault_server.get_deposit_data_all_after(key.pubkey, deposit_lpt);
    for (meta, encrypted_data) in encrypted_data {
        match DepositData::decrypt(&encrypted_data, key) {
            Ok(deposit_data) => {
                if let Some((_deposit_index, block_number)) =
                    validity_prover.get_deposit_index_and_block_number(deposit_data.deposit_hash())
                {
                    // set block number
                    let mut meta = meta;
                    meta.block_number = Some(block_number);
                    settled.push((meta, deposit_data));
                } else {
                    if meta.timestamp + deposit_timeout < chrono::Utc::now().timestamp() as u64 {
                        // timeout
                        log::error!("Deposit {} is timeouted", meta.uuid);
                        rejected.push(meta);
                    } else {
                        // pending
                        log::info!("Deposit {} is pending", meta.uuid);
                        pending.push(meta);
                    }
                }
            }
            Err(e) => {
                log::error!("failed to decrypt deposit data: {}", e);
                rejected.push(meta);
            }
        };
    }

    // sort by block number
    settled.sort_by_key(|(meta, _)| meta.block_number.unwrap());

    Ok(DepositInfo {
        settled,
        pending,
        rejected,
    })
}
