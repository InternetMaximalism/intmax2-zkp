use crate::{common::signature::key_set::KeySet, mock::data::user_data::UserData};

use super::{
    data::{
        deposit_data::DepositData, meta_data::MetaData, transfer_data::TransferData,
        tx_data::TxData,
    },
    data_store_server::DataStoreServer,
};
use plonky2::{
    field::extension::Extendable, hash::hash_types::RichField, plonk::config::GenericConfig,
};

pub struct Client;

impl Client {
    fn determin_strategy<F, C, const D: usize>(
        &self,
        data_store_sever: &DataStoreServer<F, C, D>,
        key: KeySet,
    ) -> anyhow::Result<Strategy<F, C, D>>
    where
        F: RichField + Extendable<D>,
        C: GenericConfig<D, F = F>,
    {
        let user_data = data_store_sever
            .get_user_data(key)
            .map_err(|e| anyhow::anyhow!("failed to get user data: {}", e))?
            .unwrap_or(UserData::new(key.pubkey));
        let except_transfers = user_data.transfer_exception_uudis();
        let except_txs = user_data.tx_exception_uudis();
        let except_deposits = user_data.deposit_exception_uudis();

        let (deposit_data, transfer_data, tx_data) = data_store_sever
            .get_transition_data(key, except_deposits, except_transfers, except_txs)
            .map_err(|e| anyhow::anyhow!("failed to get transition data: {}", e))?;
        

        todo!()
    }
}

struct Strategy<F, C, const D: usize>
where
    F: RichField + Extendable<D>,
    C: GenericConfig<D, F = F>,
{
    transfer_data: Vec<(MetaData, TransferData<F, C, D>)>,
    tx_data: Vec<(MetaData, TxData<F, C, D>)>,
    deposit_data: Vec<(MetaData, DepositData)>,

    actions: Vec<Action>,
}

enum Action {
    Transfer(usize),
    Tx(usize),
    Deposit(usize),
}
