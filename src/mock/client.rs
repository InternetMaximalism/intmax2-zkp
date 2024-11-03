use crate::{
    circuits::balance::{
        balance_pis::BalancePublicInputs, balance_processor::BalanceProcessor,
        send::spent_circuit::SpentPublicInputs,
    },
    common::{
        deposit::{get_pubkey_salt_hash, Deposit},
        salt::Salt,
        signature::key_set::KeySet,
        transfer::Transfer,
        trees::transfer_tree::TransferTree,
        tx::Tx,
        witness::spent_witness::SpentWitness,
    },
    constants::{NUM_TRANSFERS_IN_TX, TRANSFER_TREE_HEIGHT},
    ethereum_types::{bytes32::Bytes32, u256::U256},
    mock::{
        balance_logic::process_transfer, data::user_data::UserData, strategy,
        tx_request::MockTxRequest,
    },
};

use super::{
    balance_logic::{process_common_tx, process_deposit},
    block_builder::BlockBuilder,
    contract::MockContract,
    data::{
        common_tx_data::CommonTxData, deposit_data::DepositData, meta_data::MetaData,
        transfer_data::TransferData, tx_data::TxData,
    },
    data_store_server::DataStoreServer,
    strategy::Strategy,
    sync_validity_prover::SyncValidityProver,
};
use anyhow::ensure;
use plonky2::{
    field::extension::Extendable,
    hash::hash_types::RichField,
    plonk::{
        config::{AlgebraicHasher, GenericConfig},
        proof::ProofWithPublicInputs,
    },
};

pub struct Client;

impl Client {
    pub fn deposit<F, C, const D: usize>(
        &self,
        key: KeySet,
        contract: &mut MockContract,
        data_store_server: &mut DataStoreServer<F, C, D>,
        token_index: u32,
        amount: U256,
    ) -> anyhow::Result<()>
    where
        F: RichField + Extendable<D>,
        C: GenericConfig<D, F = F> + 'static,
        <C as GenericConfig<D>>::Hasher: AlgebraicHasher<F>,
    {
        // todo: improve the way to choose deposit salt
        let deposit_salt = generate_salt(key, 0);

        // backup before contract call
        let pubkey_salt_hash = get_pubkey_salt_hash(key.pubkey, deposit_salt);
        let deposit = Deposit {
            pubkey_salt_hash,
            token_index,
            amount,
        };
        let deposit_data = DepositData {
            deposit_salt,
            deposit,
        };
        data_store_server.save_deposit_data(key.pubkey, deposit_data);

        // call contract
        contract.deposit(pubkey_salt_hash, token_index, amount);

        Ok(())
    }

    pub fn send_tx<F, C, const D: usize>(
        &self,
        key: KeySet,
        contract: &mut MockContract,
        block_builder: &BlockBuilder,
        data_store_sever: &mut DataStoreServer<F, C, D>,
        validity_prover: &SyncValidityProver<F, C, D>,
        balance_processor: &BalanceProcessor<F, C, D>,
        transfers: Vec<Transfer>,
    ) -> anyhow::Result<()>
    where
        F: RichField + Extendable<D>,
        C: GenericConfig<D, F = F> + 'static,
        <C as GenericConfig<D>>::Hasher: AlgebraicHasher<F>,
    {
        // input validation
        ensure!(transfers.len() > 0, "transfers is empty");
        ensure!(
            transfers.len() <= NUM_TRANSFERS_IN_TX,
            "transfers is too long"
        );

        // sync balance proof
        self.sync_balance_proof(key, data_store_sever, validity_prover, balance_processor)
            .map_err(|e| anyhow::anyhow!("failed to sync balance proof: {}", e))?;

        let user_data = data_store_sever
            .get_user_data(key)
            .map_err(|e| anyhow::anyhow!("failed to get user data: {}", e))?
            .unwrap_or(UserData::new(key.pubkey));
        let _balance_proof = data_store_sever
            .get_balance_proof(
                key.pubkey,
                user_data.block_number,
                user_data.private_commitment(),
            )
            .map_err(|e| anyhow::anyhow!("failed to get balance proof: {}", e))?
            .ok_or_else(|| anyhow::anyhow!("balance proof not found"))?;

        // balance check
        let balances = user_data.balances();
        for transfer in &transfers {
            let balance = balances
                .get(&(transfer.token_index as usize))
                .cloned()
                .unwrap_or_default();
            ensure!(
                !balance.is_insufficient,
                "already insufficient: token index {}",
                transfer.token_index
            );
            ensure!(
                balance.amount >= transfer.amount,
                "insufficient balance: {} < {} for token index {}",
                balance.amount,
                transfer.amount,
                transfer.token_index
            );
        }

        // generate spent proof
        let transfer_tree = generate_transfer_tree(&transfers);
        let tx = Tx {
            nonce: user_data.full_private_state.nonce,
            transfer_tree_root: transfer_tree.get_root(),
        };
        let new_salt = generate_salt(key, user_data.full_private_state.nonce);
        let spent_witness = SpentWitness::new(
            &user_data.full_private_state.asset_tree,
            &user_data.full_private_state.to_private_state(),
            &transfer_tree.leaves(), // this is padded
            tx,
            new_salt,
        )
        .map_err(|e| anyhow::anyhow!("SpentWitness::new failed: {:?}", e))?;
        let spent_proof = balance_processor
            .balance_transition_processor
            .sender_processor
            .prove_spent(&spent_witness)
            .map_err(|e| anyhow::anyhow!("prove_spent failed: {:?}", e))?;

        // post block
        let is_first_time = validity_prover.get_account_id(key.pubkey).is_none();
        let tx_request = MockTxRequest {
            tx,
            sender: key,
            will_return_signature: true,
        };
        let (tx_tree, sender_leaves) = block_builder
            .post_block(contract, validity_prover, is_first_time, vec![tx_request])
            .map_err(|e| anyhow::anyhow!("failed to post block: {}", e))?;
        let tx_index = tx_tree.get_tx_index(&tx).unwrap();
        let tx_merkle_proof = tx_tree.prove(tx_index);
        let tx_tree_root: Bytes32 = tx_tree.get_root().into();
        let common_tx_data = CommonTxData {
            spent_proof,
            sender_prev_block_number: user_data.block_number,
            tx,
            tx_index,
            tx_merkle_proof,
            tx_tree_root,
            sender_leaves,
        };

        // save tx data
        let tx_data = TxData {
            common: common_tx_data.clone(),
            spent_witness,
        };
        data_store_sever.save_tx_data(key.pubkey, tx_data);

        // save transfer data
        for (i, transfer) in transfers.iter().enumerate() {
            let transfer_merkle_proof = transfer_tree.prove(i);
            let transfer_data = TransferData {
                sender: key.pubkey,
                prev_block_number: user_data.block_number,
                prev_private_commitment: user_data.private_commitment(),
                tx_data: common_tx_data.clone(),
                transfer: transfer.clone(),
                transfer_index: i,
                transfer_merkle_proof,
            };
            if transfer.recipient.is_pubkey {
                data_store_sever
                    .save_transfer_data(transfer.recipient.to_pubkey().unwrap(), transfer_data);
            } else {
                // todo: save withdrawal data to data store server
            }
        }
        Ok(())
    }

    pub fn sync_balance_proof<F, C, const D: usize>(
        &self,
        key: KeySet,
        data_store_server: &mut DataStoreServer<F, C, D>,
        validity_prover: &SyncValidityProver<F, C, D>,
        balance_processor: &BalanceProcessor<F, C, D>,
    ) -> anyhow::Result<()>
    where
        F: RichField + Extendable<D>,
        C: GenericConfig<D, F = F> + 'static,
        <C as GenericConfig<D>>::Hasher: AlgebraicHasher<F>,
    {
        let strategy = self
            .generate_strategy(data_store_server, validity_prover, key)
            .map_err(|e| {
                anyhow::anyhow!(
                    "failed to generate strategy for balance proof update: {}",
                    e
                )
            })?;

        for action in strategy.actions {
            match action {
                strategy::Action::Transfer(i) => {
                    let (meta, data) = &strategy.transfer_data[i];
                    self.sync_transfer(
                        data_store_server,
                        validity_prover,
                        balance_processor,
                        key,
                        meta,
                        data,
                    )
                    .map_err(|e| anyhow::anyhow!("failed to sync transfer: {}", e))?;
                }
                strategy::Action::Tx(i) => {
                    let (meta, data) = &strategy.tx_data[i];
                    self.sync_tx(
                        data_store_server,
                        validity_prover,
                        balance_processor,
                        key,
                        meta,
                        data,
                    )
                    .map_err(|e| anyhow::anyhow!("failed to sync tx: {}", e))?;
                }
                strategy::Action::Deposit(i) => {
                    let (meta, data) = &strategy.deposit_data[i];
                    self.sync_deposit(
                        data_store_server,
                        validity_prover,
                        balance_processor,
                        key,
                        meta,
                        data,
                    )
                    .map_err(|e| anyhow::anyhow!("failed to sync deposit: {}", e))?;
                }
            }
        }
        Ok(())
    }

    fn sync_deposit<F, C, const D: usize>(
        &self,
        data_store_sever: &mut DataStoreServer<F, C, D>,
        validity_prover: &SyncValidityProver<F, C, D>,
        balance_processor: &BalanceProcessor<F, C, D>,
        key: KeySet,
        meta: &MetaData,
        deposit_data: &DepositData,
    ) -> anyhow::Result<()>
    where
        F: RichField + Extendable<D>,
        C: GenericConfig<D, F = F> + 'static,
        <C as GenericConfig<D>>::Hasher: AlgebraicHasher<F>,
    {
        let mut user_data = data_store_sever
            .get_user_data(key)
            .map_err(|e| anyhow::anyhow!("failed to get user data: {}", e))?
            .unwrap_or(UserData::new(key.pubkey));

        // user's balance proof before applying the tx
        let prev_balance_proof = data_store_sever
            .get_balance_proof(
                key.pubkey,
                user_data.block_number,
                user_data.private_commitment(),
            )
            .map_err(|e| anyhow::anyhow!("failed to get balance proof: {}", e))?;

        let new_salt = generate_salt(key, user_data.full_private_state.nonce);
        let new_balance_proof = process_deposit(
            validity_prover,
            balance_processor,
            &mut user_data,
            new_salt,
            &prev_balance_proof,
            meta.block_number,
            meta.uuid,
            deposit_data,
        )
        .map_err(|e| anyhow::anyhow!("failed to process transfer: {}", e))?;

        // save proof and user data
        data_store_sever.save_balance_proof(key.pubkey, meta.block_number, new_balance_proof);
        data_store_sever.save_user_data(key.pubkey, user_data);

        Ok(())
    }

    fn sync_transfer<F, C, const D: usize>(
        &self,
        data_store_sever: &mut DataStoreServer<F, C, D>,
        validity_prover: &SyncValidityProver<F, C, D>,
        balance_processor: &BalanceProcessor<F, C, D>,
        key: KeySet,
        meta: &MetaData,
        transfer_data: &TransferData<F, C, D>,
    ) -> anyhow::Result<()>
    where
        F: RichField + Extendable<D>,
        C: GenericConfig<D, F = F> + 'static,
        <C as GenericConfig<D>>::Hasher: AlgebraicHasher<F>,
    {
        log::info!("sync_transfer: {:?}", meta);
        let mut user_data = data_store_sever
            .get_user_data(key)
            .map_err(|e| anyhow::anyhow!("failed to get user data: {}", e))?
            .unwrap_or(UserData::new(key.pubkey));

        // user's balance proof before applying the tx
        let prev_balance_proof = data_store_sever
            .get_balance_proof(
                key.pubkey,
                user_data.block_number,
                user_data.private_commitment(),
            )
            .map_err(|e| anyhow::anyhow!("failed to get balance proof: {}", e))?;

        // sender balance proof after applying the tx
        let new_sender_balance_proof = self.generate_new_sender_balance_proof(
            data_store_sever,
            validity_prover,
            balance_processor,
            transfer_data.sender,
            meta.block_number,
            &transfer_data.tx_data,
        )?;

        let new_salt = generate_salt(key, user_data.full_private_state.nonce);
        let new_balance_proof = process_transfer(
            validity_prover,
            balance_processor,
            &mut user_data,
            new_salt,
            &new_sender_balance_proof,
            &prev_balance_proof,
            meta.block_number,
            meta.uuid,
            &transfer_data,
        )
        .map_err(|e| anyhow::anyhow!("failed to process transfer: {}", e))?;

        // save proof and user data
        data_store_sever.save_balance_proof(key.pubkey, meta.block_number, new_balance_proof);
        data_store_sever.save_user_data(key.pubkey, user_data);

        Ok(())
    }

    fn sync_tx<F, C, const D: usize>(
        &self,
        data_store_sever: &mut DataStoreServer<F, C, D>,
        validity_prover: &SyncValidityProver<F, C, D>,
        balance_processor: &BalanceProcessor<F, C, D>,
        key: KeySet,
        meta: &MetaData,
        tx_data: &TxData<F, C, D>,
    ) -> anyhow::Result<()>
    where
        F: RichField + Extendable<D>,
        C: GenericConfig<D, F = F> + 'static,
        <C as GenericConfig<D>>::Hasher: AlgebraicHasher<F>,
    {
        log::info!("sync_tx: {:?}", meta);
        let mut user_data = data_store_sever
            .get_user_data(key)
            .map_err(|e| anyhow::anyhow!("failed to get user data: {}", e))?
            .unwrap_or(UserData::new(key.pubkey));
        let balance_proof = self.generate_new_sender_balance_proof(
            data_store_sever,
            validity_prover,
            balance_processor,
            key.pubkey,
            meta.block_number,
            &tx_data.common,
        )?;
        let balance_pis = BalancePublicInputs::from_pis(&balance_proof.public_inputs);
        ensure!(
            balance_pis.public_state.block_number == meta.block_number,
            "block number mismatch"
        );

        // update user data
        user_data.block_number = meta.block_number;
        tx_data
            .spent_witness
            .update_private_state(&mut user_data.full_private_state)?;
        user_data.processed_tx_uuids.push(meta.uuid);

        // validation
        ensure!(
            balance_pis.private_commitment == user_data.private_commitment(),
            "private commitment mismatch"
        );

        // save user data
        data_store_sever.save_user_data(key.pubkey, user_data);
        Ok(())
    }

    // generate sender's balance proof after applying the tx
    // save the proof to the data store server
    fn generate_new_sender_balance_proof<F, C, const D: usize>(
        &self,
        data_store_sever: &mut DataStoreServer<F, C, D>,
        validity_prover: &SyncValidityProver<F, C, D>,
        balance_processor: &BalanceProcessor<F, C, D>,
        sender: U256,
        block_number: u32,
        common_tx_data: &CommonTxData<F, C, D>,
    ) -> anyhow::Result<ProofWithPublicInputs<F, C, D>>
    where
        F: RichField + Extendable<D>,
        C: GenericConfig<D, F = F> + 'static,
        <C as GenericConfig<D>>::Hasher: AlgebraicHasher<F>,
    {
        log::info!(
            "generate_new_sender_balance_proof: sender {}, block_number {}",
            sender,
            block_number
        );
        let spent_proof_pis =
            SpentPublicInputs::from_pis(&common_tx_data.spent_proof.public_inputs);

        let new_sender_balance_proof = data_store_sever
            .get_balance_proof(sender, block_number, spent_proof_pis.new_private_commitment)
            .map_err(|e| anyhow::anyhow!("failed to get new balance proof: {}", e))?;
        if new_sender_balance_proof.is_some() {
            // already updated
            return Ok(new_sender_balance_proof.unwrap());
        }

        let prev_sender_balance_proof = data_store_sever
            .get_balance_proof(
                sender,
                common_tx_data.sender_prev_block_number,
                spent_proof_pis.prev_private_commitment,
            )
            .map_err(|e| anyhow::anyhow!("failed to get balance proof: {}", e))?
            .ok_or_else(|| anyhow::anyhow!("prev balance proof not found"))?;

        let new_sender_balance_proof = process_common_tx(
            validity_prover,
            balance_processor,
            sender,
            &Some(prev_sender_balance_proof),
            block_number,
            common_tx_data,
        )
        .map_err(|e| anyhow::anyhow!("failed to process tx: {}", e))?;

        data_store_sever.save_balance_proof(sender, block_number, new_sender_balance_proof.clone());

        Ok(new_sender_balance_proof)
    }

    // generate strategy of the balance proof update process
    fn generate_strategy<F, C, const D: usize>(
        &self,
        data_store_sever: &mut DataStoreServer<F, C, D>,
        sync_validity_prover: &SyncValidityProver<F, C, D>,
        key: KeySet,
    ) -> anyhow::Result<Strategy<F, C, D>>
    where
        F: RichField + Extendable<D>,
        C: GenericConfig<D, F = F> + 'static,
        <C as GenericConfig<D>>::Hasher: AlgebraicHasher<F>,
    {
        // get user data from the data store server
        let mut user_data = data_store_sever
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
        // add rejected data to user data
        user_data
            .rejected_deposit_uuids
            .extend(transition_data.rejected_deposits);
        user_data
            .rejected_transfer_uuids
            .extend(transition_data.rejected_transfers);
        user_data
            .rejected_processed_tx_uuids
            .extend(transition_data.rejected_txs);
        // save user data
        data_store_sever.save_user_data(key.pubkey, user_data);

        // fetch block numbers for each data
        let mut deposit_data = Vec::new();
        for (uuid, data) in transition_data.deposit_data {
            if let Some((_deposit_index, block_number)) =
                sync_validity_prover.get_deposit_index_and_block_number(data.deposit_hash())
            {
                deposit_data.push((MetaData { uuid, block_number }, data));
            } else {
                log::warn!("Deposit {} is not included in block tree", uuid);
            }
        }
        let mut transfer_data = Vec::new();
        for (uuid, data) in transition_data.transfer_data {
            let tx_tree_root = data.tx_data.tx_tree_root;
            let block_numbers =
                sync_validity_prover.get_block_numbers_by_tx_tree_root(tx_tree_root);
            if block_numbers.len() == 0 {
                log::warn!("Transfer {} is not included in any block", uuid);
                continue;
            }
            if block_numbers.len() > 1 {
                todo!("The tx is included in multiple blocks");
            }
            let block_number = block_numbers[0];
            transfer_data.push((MetaData { uuid, block_number }, data));
        }
        let mut tx_data = Vec::new();
        for (uuid, data) in transition_data.tx_data {
            let tx_tree_root = data.common.tx_tree_root;
            let block_numbers =
                sync_validity_prover.get_block_numbers_by_tx_tree_root(tx_tree_root);
            if block_numbers.len() == 0 {
                log::warn!("Tx {} is not included in any block", uuid);
                continue;
            }
            if block_numbers.len() > 1 {
                todo!("The tx is included in multiple blocks");
            }
            let block_number = block_numbers[0];
            tx_data.push((MetaData { uuid, block_number }, data));
        }

        // generate strategy
        let strategy = Strategy::generate(deposit_data, transfer_data, tx_data);
        Ok(strategy)
    }

    pub fn get_user_data<F, C, const D: usize>(
        &self,
        key: KeySet,
        data_store_server: &DataStoreServer<F, C, D>,
    ) -> anyhow::Result<UserData>
    where
        F: RichField + Extendable<D>,
        C: GenericConfig<D, F = F> + 'static,
        <C as GenericConfig<D>>::Hasher: AlgebraicHasher<F>,
    {
        let user_data = data_store_server
            .get_user_data(key)
            .map_err(|e| anyhow::anyhow!("failed to get user data: {}", e))?
            .unwrap_or(UserData::new(key.pubkey));
        Ok(user_data)
    }
}

pub fn generate_salt(_key: KeySet, _nonce: u32) -> Salt {
    // todo: deterministic salt generation
    let mut rng = rand::thread_rng();
    Salt::rand(&mut rng)
}

pub fn generate_transfer_tree(transfers: &[Transfer]) -> TransferTree {
    let mut transfers = transfers.to_vec();
    transfers.resize(NUM_TRANSFERS_IN_TX, Transfer::default());
    let mut transfer_tree = TransferTree::new(TRANSFER_TREE_HEIGHT);
    for transfer in &transfers {
        transfer_tree.push(transfer.clone());
    }
    transfer_tree
}
