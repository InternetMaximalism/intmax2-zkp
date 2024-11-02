use super::{
    data::{deposit_data::DepositData, transfer_data::TransferData, tx_data::TxData},
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
    ) -> Strategy<F, C, D>
    where
        F: RichField + Extendable<D>,
        C: GenericConfig<D, F = F>,
    {
        todo!()
    }
}

struct Strategy<F, C, const D: usize>
where
    F: RichField + Extendable<D>,
    C: GenericConfig<D, F = F>,
{
    transfer_data: Vec<(u32, TransferData<F, C, D>)>,
    tx_data: Vec<(u32, TxData<F, C, D>)>,
    deposit_data: Vec<(u32, DepositData)>,

    actions: Vec<Action>,
}

enum Action {
    Transfer(usize),
    Tx(usize),
    Deposit(usize),
}
