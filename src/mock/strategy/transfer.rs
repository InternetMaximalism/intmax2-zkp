use plonky2::{
    field::extension::Extendable,
    hash::hash_types::RichField,
    plonk::config::{AlgebraicHasher, GenericConfig},
};

use crate::{common::signature::key_set::KeySet, mock::data::transfer_data::TransferData};

use crate::mock::{
    block_validity_prover::BlockValidityProver, data::meta_data::MetaData,
    store_vault_server::StoreVaultServer,
};

#[derive(Debug, Clone)]
pub struct TransferInfo<F, C, const D: usize>
where
    F: RichField + Extendable<D>,
    C: GenericConfig<D, F = F>,
{
    pub settled: Vec<(MetaData, TransferData<F, C, D>)>,
    pub pending: Vec<MetaData>,
    pub rejected: Vec<MetaData>,
}

pub fn fetch_transfer_info<F, C, const D: usize>(
    store_vault_server: &StoreVaultServer<F, C, D>,
    validity_prover: &BlockValidityProver<F, C, D>,
    key: KeySet,
    transfer_lpt: u64,
    tx_timeout: u64,
) -> anyhow::Result<TransferInfo<F, C, D>>
where
    F: RichField + Extendable<D>,
    C: GenericConfig<D, F = F> + 'static,
    <C as GenericConfig<D>>::Hasher: AlgebraicHasher<F>,
{
    let mut settled = Vec::new();
    let mut pending = Vec::new();
    let mut rejected = Vec::new();

    let encrypted_data = store_vault_server.get_transfer_data_all_after(key.pubkey, transfer_lpt);
    for (meta, encrypted_data) in encrypted_data {
        match TransferData::decrypt(&encrypted_data, key) {
            Ok(transfer_data) => {
                let tx_tree_root = transfer_data.tx_data.tx_tree_root;
                let block_number = validity_prover.get_block_number_by_tx_tree_root(tx_tree_root);
                if let Some(block_number) = block_number {
                    // set block number
                    let mut meta = meta;
                    meta.block_number = Some(block_number);
                    settled.push((meta, transfer_data));
                } else {
                    if meta.timestamp + tx_timeout < chrono::Utc::now().timestamp() as u64 {
                        // timeout
                        log::error!("Transfer {} is timeouted", meta.uuid);
                        rejected.push(meta);
                    } else {
                        // pending
                        log::info!("Transfer {} is pending", meta.uuid);
                        pending.push(meta);
                    }
                }
            }
            Err(e) => {
                log::error!("failed to decrypt transfer data: {}", e);
                rejected.push(meta);
            }
        };
    }

    // sort by block number
    settled.sort_by_key(|(meta, _)| meta.block_number.unwrap());

    Ok(TransferInfo {
        settled,
        pending,
        rejected,
    })
}
