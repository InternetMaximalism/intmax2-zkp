use plonky2::{
    field::extension::Extendable,
    hash::hash_types::RichField,
    plonk::config::{AlgebraicHasher, GenericConfig},
};

use crate::common::signature::key_set::KeySet;

use crate::mock::{
    block_validity_prover::BlockValidityProver,
    data::{
        deposit_data::DepositData, meta_data::MetaData, transfer_data::TransferData,
        tx_data::TxData, user_data::UserData,
    },
    store_vault_server::StoreVaultServer,
    strategy::deposit::fetch_deposit_info,
};

use super::{transfer::fetch_transfer_info, tx::fetch_tx_info};

// Next sync action
#[derive(Debug, Clone)]
pub enum Action<F, C, const D: usize>
where
    F: RichField + Extendable<D>,
    C: GenericConfig<D, F = F>,
{
    Deposit(MetaData, DepositData),            // Receive deposit
    Transfer(MetaData, TransferData<F, C, D>), // Receive transfer
    Tx(MetaData, TxData<F, C, D>),             // Send tx
}

#[derive(Debug, Clone)]
pub struct NextAction<F, C, const D: usize>
where
    F: RichField + Extendable<D>,
    C: GenericConfig<D, F = F>,
{
    pub action: Option<Action<F, C, D>>,
    pub pending_deposits: Vec<MetaData>,
    pub pending_transfers: Vec<MetaData>,
    pub pending_txs: Vec<MetaData>,
}

// generate strategy of the balance proof update process
pub fn determin_next_action<F, C, const D: usize>(
    store_vault_server: &StoreVaultServer<F, C, D>,
    validity_prover: &BlockValidityProver<F, C, D>,
    key: KeySet,
    deposit_timeout: u64,
    tx_timeout: u64,
) -> anyhow::Result<NextAction<F, C, D>>
where
    F: RichField + Extendable<D>,
    C: GenericConfig<D, F = F> + 'static,
    <C as GenericConfig<D>>::Hasher: AlgebraicHasher<F>,
{
    // get user data from the data store server
    let user_data = store_vault_server
        .get_user_data(key.pubkey)
        .map(|encrypted| UserData::decrypt(&encrypted, key))
        .transpose()
        .map_err(|e| anyhow::anyhow!("failed to decrypt user data: {}", e))?
        .unwrap_or(UserData::new(key.pubkey));

    let deposit_info = fetch_deposit_info(
        store_vault_server,
        validity_prover,
        key,
        user_data.deposit_lpt,
        deposit_timeout,
    )
    .map_err(|e| anyhow::anyhow!("failed to fetch deposit info: {}", e))?;

    let transfer_info = fetch_transfer_info(
        store_vault_server,
        validity_prover,
        key,
        user_data.transfer_lpt,
        tx_timeout,
    )
    .map_err(|e| anyhow::anyhow!("failed to fetch transfer info: {}", e))?;

    let tx_info = fetch_tx_info(
        store_vault_server,
        validity_prover,
        key,
        user_data.tx_lpt,
        tx_timeout,
    )
    .map_err(|e| anyhow::anyhow!("failed to fetch tx info: {}", e))?;

    let mut all_actions: Vec<(u32, u8, Action<F, C, D>)> = Vec::new();

    // Add tx data with priority 1
    for (meta, data) in tx_info.settled.into_iter() {
        all_actions.push((meta.block_number.unwrap(), 1, Action::Tx(meta, data)));
    }
    // Add deposit data with priority 2
    for (meta, data) in deposit_info.settled.into_iter() {
        all_actions.push((meta.block_number.unwrap(), 2, Action::Deposit(meta, data)));
    }
    // Add transfer data with priority 3
    for (meta, data) in transfer_info.settled.into_iter() {
        all_actions.push((meta.block_number.unwrap(), 3, Action::Transfer(meta, data)));
    }

    // Sort by block number first, then by priority
    all_actions.sort_by_key(|(block_num, priority, _)| (*block_num, *priority));

    // Get the next action
    let next_action = all_actions.first().map(|(_, _, action)| action.clone());

    Ok(NextAction {
        action: next_action,
        pending_deposits: deposit_info.pending,
        pending_transfers: transfer_info.pending,
        pending_txs: tx_info.pending,
    })
}
