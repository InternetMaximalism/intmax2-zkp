use crate::{common::signature::key_set::KeySet, mock::data::user_data::UserData};

use super::{
    data::meta_data::MetaData, data_store_server::DataStoreServer, strategy::Strategy,
    sync_validity_prover::SyncValidityProver,
};
use plonky2::{
    field::extension::Extendable,
    hash::hash_types::RichField,
    plonk::config::{AlgebraicHasher, GenericConfig},
};

pub struct Client;

impl Client {
    // generate strategy of the balance proof update process
    pub fn generate_strategy<F, C, const D: usize>(
        &self,
        data_store_sever: &DataStoreServer<F, C, D>,
        sync_validity_prover: &SyncValidityProver<F, C, D>,
        key: KeySet,
    ) -> anyhow::Result<Strategy<F, C, D>>
    where
        F: RichField + Extendable<D>,
        C: GenericConfig<D, F = F> + 'static,
        <C as GenericConfig<D>>::Hasher: AlgebraicHasher<F>,
    {
        // get user data from the data store server
        let user_data = data_store_sever
            .get_user_data(key)
            .map_err(|e| anyhow::anyhow!("failed to get user data: {}", e))?
            .unwrap_or(UserData::new(key.pubkey));

        // get transition data from the data store server
        let except_transfers = user_data.transfer_exception_uudis();
        let except_txs = user_data.tx_exception_uudis();
        let except_deposits = user_data.deposit_exception_uudis();
        let transition_data = data_store_sever
            .get_transition_data(key, except_deposits, except_transfers, except_txs)
            .map_err(|e| anyhow::anyhow!("failed to get transition data: {}", e))?;

        // fetch block numbers for each data
        let mut deposit_data = Vec::new();
        for (uuid, data) in transition_data.deposit_data {
            if let Some((_deposit_index, block_number)) =
                sync_validity_prover.get_deposit_index_and_block_number(data.deposit_id)
            {
                deposit_data.push((MetaData { uuid, block_number }, data));
            }
        }
        let mut transfer_data = Vec::new();
        for (uuid, data) in transition_data.transfer_data {
            let tx_tree_root = data.tx_data.tx_tree_root;
            let block_numbers =
                sync_validity_prover.get_block_numbers_by_tx_tree_root(tx_tree_root);
            if block_numbers.len() == 0 {
                // The tx is not included in any block
                // ignore this transfer
                continue;
            }
            if block_numbers.len() > 1 {
                // The tx is included in multiple blocks
                todo!("handle this case");
            }
            let block_number = block_numbers[0];
            transfer_data.push((MetaData { uuid, block_number }, data));
        }
        let mut tx_data = Vec::new();
        for (uuid, data) in transition_data.tx_data {
            let tx_tree_root = data.tx_tree_root;
            let block_numbers =
                sync_validity_prover.get_block_numbers_by_tx_tree_root(tx_tree_root);
            if block_numbers.len() == 0 {
                // The tx is not included in any block
                // ignore this tx
                continue;
            }
            if block_numbers.len() > 1 {
                // The tx is included in multiple blocks
                todo!("handle this case");
            }
            let block_number = block_numbers[0];
            tx_data.push((MetaData { uuid, block_number }, data));
        }

        // generate strategy
        let strategy = Strategy::generate(transfer_data, tx_data, deposit_data);
        Ok(strategy)
    }
}
