use plonky2::{
    field::extension::Extendable,
    hash::hash_types::RichField,
    plonk::config::{AlgebraicHasher, GenericConfig},
};

use crate::common::signature::key_set::KeySet;

use super::{
    block_validity_prover::BlockValidityProver,
    data::{
        deposit_data::DepositData, meta_data::MetaData, transfer_data::TransferData,
        tx_data::TxData, user_data::UserData,
    },
    store_vault_server::StoreVaultServer,
};

// Return type of fetch_sync_info
pub struct SyncInfo<F, C, const D: usize>
where
    F: RichField + Extendable<D>,
    C: GenericConfig<D, F = F>,
{
    pub next_action: Option<Action<F, C, D>>,
    pub pending_actions: Vec<Action<F, C, D>>,
    pub rejected_actions: Vec<RejectedAction>,
}

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
pub enum RejectedAction {
    Transfer(MetaData),
    Tx(MetaData),
    Deposit(MetaData),
}

// generate strategy of the balance proof update process
pub fn fetch_sync_info<F, C, const D: usize>(
    store_vault_server: &StoreVaultServer<F, C, D>,
    sync_validity_prover: &BlockValidityProver<F, C, D>,
    key: KeySet,
    deposit_timeout: u64,
    tx_timeout: u64,
) -> anyhow::Result<SyncInfo<F, C, D>>
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

    let mut pending_actions = Vec::new();
    let mut rejected_actions = Vec::new();

    let deposit_data_with_meta =
        store_vault_server.get_next_deposit_data(key.pubkey, user_data.deposit_lpt);
    if let Some((meta, encrypted_data)) = deposit_data_with_meta {
        match DepositData::decrypt(&encrypted_data, key) {
            Ok(deposit_data) => {
                if let Some((_deposit_index, block_number)) = sync_validity_prover
                    .get_deposit_index_and_block_number(deposit_data.deposit_hash())
                {
                    // set block number
                    let mut meta = meta;
                    meta.block_number = Some(block_number);
                    let next_action = Action::Deposit(meta, deposit_data);
                    return Ok(SyncInfo {
                        next_action: Some(next_action),
                        pending_actions,
                        rejected_actions,
                    });
                } else {
                    if meta.timestamp + deposit_timeout < chrono::Utc::now().timestamp() as u64 {
                        // timeout
                        log::error!("Deposit {} is timeouted", meta.uuid);
                        rejected_actions.push(RejectedAction::Deposit(meta));
                    } else {
                        // pending
                        log::info!("Deposit {} is pending", meta.uuid);
                        pending_actions.push(Action::Deposit(meta, deposit_data));
                    }
                }
            }
            Err(e) => {
                log::error!("failed to decrypt deposit data: {}", e);
                rejected_actions.push(RejectedAction::Deposit(meta));
            }
        };
    }

    let transfer_data_with_meta =
        store_vault_server.get_next_transfer_data(key.pubkey, user_data.transfer_lpt);
    if let Some((meta, encrypted_data)) = transfer_data_with_meta {
        match TransferData::decrypt(&encrypted_data, key) {
            Ok(transfer_data) => {
                let tx_tree_root = transfer_data.tx_data.tx_tree_root;
                let block_number =
                    sync_validity_prover.get_block_number_by_tx_tree_root(tx_tree_root);
                if let Some(block_number) = block_number {
                    // set block number
                    let mut meta = meta;
                    meta.block_number = Some(block_number);
                    let next_action = Action::Transfer(meta, transfer_data);
                    return Ok(SyncInfo {
                        next_action: Some(next_action),
                        pending_actions,
                        rejected_actions,
                    });
                } else {
                    if meta.timestamp + tx_timeout < chrono::Utc::now().timestamp() as u64 {
                        // timeout
                        log::error!("Transfer {} is timeouted", meta.uuid);
                        rejected_actions.push(RejectedAction::Transfer(meta));
                    } else {
                        // pending
                        log::info!("Transfer {} is pending", meta.uuid);
                        pending_actions.push(Action::Transfer(meta, transfer_data));
                    }
                }
            }
            Err(e) => {
                log::error!("failed to decrypt transfer data: {}", e);
                rejected_actions.push(RejectedAction::Transfer(meta));
            }
        };
    }

    // If there is any pending incoming fund, it is not safe to proceed tx because
    // the tx may be cause insufficient fund
    // todo: proceed tx if the tx is not related to the pending fund
    if !pending_actions.is_empty() {
        return Ok(SyncInfo {
            next_action: None,
            pending_actions,
            rejected_actions,
        });
    }

    let tx_data_with_meta = store_vault_server.get_next_tx_data(key.pubkey, user_data.tx_lpt);
    if let Some((meta, encrypted_data)) = tx_data_with_meta {
        match TxData::decrypt(&encrypted_data, key) {
            Ok(tx_data) => {
                let tx_tree_root = tx_data.common.tx_tree_root;
                let block_number =
                    sync_validity_prover.get_block_number_by_tx_tree_root(tx_tree_root);
                if let Some(block_number) = block_number {
                    // set block number
                    let mut meta = meta;
                    meta.block_number = Some(block_number);
                    let next_action = Action::Tx(meta, tx_data);
                    return Ok(SyncInfo {
                        next_action: Some(next_action),
                        pending_actions,
                        rejected_actions,
                    });
                } else {
                    // pending
                    log::info!("Tx {} is pending", meta.uuid);
                    pending_actions.push(Action::Tx(meta, tx_data));
                }
            }
            Err(e) => {
                log::error!("failed to decrypt tx data: {}", e);
                rejected_actions.push(RejectedAction::Tx(meta));
            }
        };
    }

    Ok(SyncInfo {
        next_action: None,
        pending_actions,
        rejected_actions,
    })
}

#[derive(Debug, Clone)]
pub struct WithdrawalInfo<F, C, const D: usize>
where
    F: RichField + Extendable<D>,
    C: GenericConfig<D, F = F>,
{
    pub withdrawals: Vec<(MetaData, TransferData<F, C, D>)>,
    pub pending_withdrawals: Vec<(MetaData, TransferData<F, C, D>)>,
    pub rejected_withdrawals: Vec<MetaData>,
}

pub fn fetch_withdrawals<F, C, const D: usize>(
    store_vault_server: &mut StoreVaultServer<F, C, D>,
    sync_validity_prover: &BlockValidityProver<F, C, D>,
    key: KeySet,
    tx_timeout: u64,
) -> anyhow::Result<WithdrawalInfo<F, C, D>>
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

    let mut withdrawals = Vec::new();
    let mut pending_withdrawals = Vec::new();
    let mut rejected_withdrawals = Vec::new();

    let withdrawal_data_with_meta =
        store_vault_server.get_all_withdrawal_data(key.pubkey, user_data.withdrawal_lpt);
    for (meta, encrypted_data) in withdrawal_data_with_meta {
        match TransferData::decrypt(&encrypted_data, key) {
            Ok(transfer_data) => {
                let tx_tree_root = transfer_data.tx_data.tx_tree_root;
                let block_number =
                    sync_validity_prover.get_block_number_by_tx_tree_root(tx_tree_root);
                if let Some(block_number) = block_number {
                    // set block number
                    let mut meta = meta;
                    meta.block_number = Some(block_number);
                    withdrawals.push((meta, transfer_data));
                } else {
                    if meta.timestamp + tx_timeout < chrono::Utc::now().timestamp() as u64 {
                        // timeout
                        log::error!("Withdrawal {} is timeouted", meta.uuid);
                        rejected_withdrawals.push(meta);
                    } else {
                        // pending
                        log::info!("Withdrawal {} is pending", meta.uuid);
                        pending_withdrawals.push((meta, transfer_data));
                    }
                }
            }
            Err(e) => {
                log::error!("failed to decrypt withdrawal data: {}", e);
                rejected_withdrawals.push(meta);
            }
        }
    }

    Ok(WithdrawalInfo {
        withdrawals,
        pending_withdrawals,
        rejected_withdrawals,
    })
}
