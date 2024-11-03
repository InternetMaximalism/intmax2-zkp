use plonky2::{
    field::extension::Extendable, hash::hash_types::RichField, plonk::config::GenericConfig,
};

use super::data::{
    deposit_data::DepositData, meta_data::MetaData, transfer_data::TransferData, tx_data::TxData,
};

pub enum Action {
    Transfer(usize),
    Tx(usize),
    Deposit(usize),
}

pub struct Strategy<F, C, const D: usize>
where
    F: RichField + Extendable<D>,
    C: GenericConfig<D, F = F>,
{
    pub deposit_data: Vec<(MetaData, DepositData)>,
    pub transfer_data: Vec<(MetaData, TransferData<F, C, D>)>,
    pub tx_data: Vec<(MetaData, TxData<F, C, D>)>,

    pub actions: Vec<Action>,
}

impl<F, C, const D: usize> Strategy<F, C, D>
where
    F: RichField + Extendable<D>,
    C: GenericConfig<D, F = F>,
{
    pub fn generate(
        transfer_data: Vec<(MetaData, TransferData<F, C, D>)>,
        tx_data: Vec<(MetaData, TxData<F, C, D>)>,
        deposit_data: Vec<(MetaData, DepositData)>,
    ) -> Self {
        // Collect all data into a single vector with block number and priority
        // priority: tx(1) -> deposit(2) -> transfer(3)
        let mut all_data: Vec<(u32, u8, Action)> = Vec::new();

        // Add tx data with priority 1
        for (i, (meta, _)) in tx_data.iter().enumerate() {
            all_data.push((meta.block_number, 1, Action::Tx(i)));
        }

        // Add deposit data with priority 2
        for (i, (meta, _)) in deposit_data.iter().enumerate() {
            all_data.push((meta.block_number, 2, Action::Deposit(i)));
        }

        // Add transfer data with priority 3
        for (i, (meta, _)) in transfer_data.iter().enumerate() {
            all_data.push((meta.block_number, 3, Action::Transfer(i)));
        }

        // Sort by block number first, then by priority
        all_data.sort_by_key(|(block_num, priority, _)| (*block_num, *priority));
        let actions = all_data.into_iter().map(|(_, _, action)| action).collect();

        Self {
            deposit_data,
            transfer_data,
            tx_data,
            actions,
        }
    }
}
