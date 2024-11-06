use std::f128::consts::E;

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
        witness::{
            spent_witness::SpentWitness, transfer_witness::TransferWitness,
            withdrawal_witness::WithdrawalWitness,
        },
    },
    constants::{NUM_TRANSFERS_IN_TX, TRANSFER_TREE_HEIGHT},
    ethereum_types::u256::U256,
    mock::{balance_logic::process_transfer, data::user_data::UserData, sync_strategy},
};

use super::{
    balance_logic::{process_common_tx, process_deposit},
    block_builder::BlockBuilder,
    block_validity_prover::BlockValidityProver,
    contract::MockContract,
    data::{
        common_tx_data::CommonTxData, deposit_data::DepositData, meta_data::MetaData,
        transfer_data::TransferData, tx_data::TxData,
    },
    store_vault_server::StoreVaultServer,
    sync_strategy::{fetch_sync_info, Action},
    withdrawal_aggregator::WithdrawalAggregator,
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

#[derive(Debug, Clone, Copy, PartialEq)]
pub enum SyncStatus {
    Continue, // continue syncing
    Complete, // sync completed
    Pending,  // there are pending actions
}

impl Client {
    pub fn deposit<F, C, const D: usize>(
        &self,
        key: KeySet,
        contract: &mut MockContract,
        store_vault_server: &mut StoreVaultServer<F, C, D>,
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
        store_vault_server.save_deposit_data(key.pubkey, deposit_data.encrypt(key.pubkey));

        // call contract
        contract.deposit(pubkey_salt_hash, token_index, amount);

        Ok(())
    }

    pub fn send_tx<F, C, const D: usize>(
        &self,
        key: KeySet,
        contract: &mut MockContract,
        block_builder: &mut BlockBuilder,
        store_vault_server: &mut StoreVaultServer<F, C, D>,
        validity_prover: &BlockValidityProver<F, C, D>,
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
        self.sync(key, store_vault_server, validity_prover, balance_processor)
            .map_err(|e| anyhow::anyhow!("failed to sync balance proof: {}", e))?;

        let user_data = self
            .get_user_data(key, store_vault_server)
            .map_err(|e| anyhow::anyhow!("failed to get user data: {}", e))?;
        let _balance_proof = store_vault_server
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

        let is_first_time = validity_prover.get_account_id(key.pubkey).is_none();

        // get block proposal & verify it
        let proposals = block_builder
            .propose(
                contract,
                validity_prover,
                is_first_time, // Use registration block for the first tx
                vec![(key.pubkey, tx)],
            )
            .map_err(|e| anyhow::anyhow!("failed to propose block: {}", e))?;
        let proposal = &proposals[0]; // first tx
        proposal
            .verify(tx)
            .map_err(|e| anyhow::anyhow!("failed to verify proposal: {}", e))?;

        // backup before posting block
        let common_tx_data = CommonTxData {
            spent_proof,
            sender_prev_block_number: user_data.block_number,
            tx,
            tx_index: proposal.tx_index,
            tx_merkle_proof: proposal.tx_merkle_proof.clone(),
            tx_tree_root: proposal.tx_tree_root,
        };
        // save tx data
        let tx_data = TxData {
            common: common_tx_data.clone(),
            spent_witness,
        };
        store_vault_server.save_tx_data(key.pubkey, tx_data.encrypt(key.pubkey));
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
                let recipient = transfer.recipient.to_pubkey().unwrap();
                store_vault_server.save_transfer_data(
                    transfer.recipient.to_pubkey().unwrap(),
                    transfer_data.encrypt(recipient),
                );
            } else {
                store_vault_server
                    .save_withdrawal_data(key.pubkey, transfer_data.encrypt(key.pubkey));
            }
        }

        // sign and post block
        let signature = proposal.sign(key);
        block_builder
            .post_block(contract, validity_prover, vec![signature])
            .map_err(|e| anyhow::anyhow!("failed to post block: {}", e))?;
        Ok(())
    }

    pub fn sync<F, C, const D: usize>(
        &self,
        key: KeySet,
        store_vault_server: &mut StoreVaultServer<F, C, D>,
        validity_prover: &BlockValidityProver<F, C, D>,
        balance_processor: &BalanceProcessor<F, C, D>,
        deposit_timeout: u64,
        tx_timeout: u64,
    ) -> anyhow::Result<()>
    where
        F: RichField + Extendable<D>,
        C: GenericConfig<D, F = F> + 'static,
        <C as GenericConfig<D>>::Hasher: AlgebraicHasher<F>,
    {
        let mut sync_status = SyncStatus::Continue;
        while sync_status == SyncStatus::Continue {
            sync_status = self.sync_single(
                key,
                store_vault_server,
                validity_prover,
                balance_processor,
                deposit_timeout,
                tx_timeout,
            )?;
        }
        if sync_status == SyncStatus::Pending {
            todo!("handle pending actions")
        }
        Ok(())
    }

    pub fn sync_single<F, C, const D: usize>(
        &self,
        key: KeySet,
        store_vault_server: &mut StoreVaultServer<F, C, D>,
        validity_prover: &BlockValidityProver<F, C, D>,
        balance_processor: &BalanceProcessor<F, C, D>,
        deposit_timeout: u64,
        tx_timeout: u64,
    ) -> anyhow::Result<SyncStatus>
    where
        F: RichField + Extendable<D>,
        C: GenericConfig<D, F = F> + 'static,
        <C as GenericConfig<D>>::Hasher: AlgebraicHasher<F>,
    {
        let sync_info = fetch_sync_info(
            store_vault_server,
            validity_prover,
            key,
            deposit_timeout,
            tx_timeout,
        )?;

        if sync_info.next_action.is_none() {
            if sync_info.pending_actions.is_empty() {
                return Ok(SyncStatus::Complete);
            } else {
                return Ok(SyncStatus::Pending);
            }
        }

        match sync_info.next_action.unwrap() {
            Action::Deposit(meta, deposit_data) => {
                self.sync_deposit(
                    store_vault_server,
                    validity_prover,
                    balance_processor,
                    key,
                    &meta,
                    &deposit_data,
                )
                .map_err(|e| anyhow::anyhow!("failed to sync deposit: {}", e))?;
            }
            Action::Transfer(meta, transfer_data) => {
                self.sync_transfer(
                    store_vault_server,
                    validity_prover,
                    balance_processor,
                    key,
                    &meta,
                    &transfer_data,
                )
                .map_err(|e| anyhow::anyhow!("failed to sync transfer: {}", e))?;
            }
            Action::Tx(meta, tx_data) => {
                self.sync_tx(
                    store_vault_server,
                    validity_prover,
                    balance_processor,
                    key,
                    &meta,
                    &tx_data,
                )
                .map_err(|e| anyhow::anyhow!("failed to sync tx: {}", e))?;
            }
        }

        Ok(SyncStatus::Continue)
    }

    pub fn sync_withdrawals<F, C, const D: usize>(
        &self,
        key: KeySet,
        store_vault_server: &mut StoreVaultServer<F, C, D>,
        withdrawal_aggregator: &mut WithdrawalAggregator<F, C, D>,
        validity_prover: &BlockValidityProver<F, C, D>,
        balance_processor: &BalanceProcessor<F, C, D>,
    ) -> anyhow::Result<()>
    where
        F: RichField + Extendable<D>,
        C: GenericConfig<D, F = F> + 'static,
        <C as GenericConfig<D>>::Hasher: AlgebraicHasher<F>,
    {
        let withdrawal_data = self.get_withdrawal_data(store_vault_server, validity_prover, key)?;
        for (meta, data) in &withdrawal_data {
            self.sync_withdrawal(
                store_vault_server,
                withdrawal_aggregator,
                validity_prover,
                balance_processor,
                key,
                meta,
                data,
            )
            .map_err(|e| anyhow::anyhow!("failed to sync withdrawal: {}", e))?;
        }
        Ok(())
    }

    fn sync_deposit<F, C, const D: usize>(
        &self,
        store_vault_server: &mut StoreVaultServer<F, C, D>,
        validity_prover: &BlockValidityProver<F, C, D>,
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
        let mut user_data = self.get_user_data(key, store_vault_server)?;

        // user's balance proof before applying the tx
        let prev_balance_proof = store_vault_server
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
            meta.block_number.unwrap(),
            meta.uuid.clone(),
            deposit_data,
        )
        .map_err(|e| anyhow::anyhow!("failed to process transfer: {}", e))?;

        // save proof and user data
        store_vault_server.save_balance_proof(key.pubkey, new_balance_proof);
        store_vault_server.save_user_data(key.pubkey, user_data.encrypt(key.pubkey));

        Ok(())
    }

    fn sync_transfer<F, C, const D: usize>(
        &self,
        store_vault_server: &mut StoreVaultServer<F, C, D>,
        validity_prover: &BlockValidityProver<F, C, D>,
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
        let mut user_data = self.get_user_data(key, store_vault_server)?;
        // user's balance proof before applying the tx
        let prev_balance_proof = store_vault_server
            .get_balance_proof(
                key.pubkey,
                user_data.block_number,
                user_data.private_commitment(),
            )
            .map_err(|e| anyhow::anyhow!("failed to get balance proof: {}", e))?;

        // sender balance proof after applying the tx
        let new_sender_balance_proof = self.generate_new_sender_balance_proof(
            store_vault_server,
            validity_prover,
            balance_processor,
            transfer_data.sender,
            meta.block_number.unwrap(),
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
            meta.block_number.unwrap(),
            meta.uuid.clone(),
            &transfer_data,
        )
        .map_err(|e| anyhow::anyhow!("failed to process transfer: {}", e))?;

        // save proof and user data
        store_vault_server.save_balance_proof(key.pubkey, new_balance_proof);
        store_vault_server.save_user_data(key.pubkey, user_data.encrypt(key.pubkey));

        Ok(())
    }

    fn sync_tx<F, C, const D: usize>(
        &self,
        store_vault_server: &mut StoreVaultServer<F, C, D>,
        validity_prover: &BlockValidityProver<F, C, D>,
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
        let mut user_data = self.get_user_data(key, store_vault_server)?;
        let balance_proof = self.generate_new_sender_balance_proof(
            store_vault_server,
            validity_prover,
            balance_processor,
            key.pubkey,
            meta.block_number.unwrap(),
            &tx_data.common,
        )?;
        let balance_pis = BalancePublicInputs::from_pis(&balance_proof.public_inputs);
        ensure!(
            balance_pis.public_state.block_number == meta.block_number.unwrap(),
            "block number mismatch"
        );

        // update user data
        user_data.block_number = meta.block_number.unwrap();
        tx_data
            .spent_witness
            .update_private_state(&mut user_data.full_private_state)?;
        user_data.processed_tx_uuids.push(meta.uuid.clone());

        // validation
        ensure!(
            balance_pis.private_commitment == user_data.private_commitment(),
            "private commitment mismatch"
        );

        // save user data
        store_vault_server.save_user_data(key.pubkey, user_data.encrypt(key.pubkey));
        Ok(())
    }

    fn sync_withdrawal<F, C, const D: usize>(
        &self,
        store_vault_server: &mut StoreVaultServer<F, C, D>,
        withdrawal_aggregator: &mut WithdrawalAggregator<F, C, D>,
        validity_prover: &BlockValidityProver<F, C, D>,
        balance_processor: &BalanceProcessor<F, C, D>,
        key: KeySet,
        meta: &MetaData,
        withdrawal_data: &TransferData<F, C, D>,
    ) -> anyhow::Result<()>
    where
        F: RichField + Extendable<D>,
        C: GenericConfig<D, F = F> + 'static,
        <C as GenericConfig<D>>::Hasher: AlgebraicHasher<F>,
    {
        log::info!("sync_withdrawal: {:?}", meta);
        ensure!(meta.block_number.is_some(), "block number is not set");

        let mut user_data = self
            .get_user_data(key, store_vault_server)
            .map_err(|e| anyhow::anyhow!("failed to get user data: {}", e))?;

        let new_user_balance_proof = self.generate_new_sender_balance_proof(
            store_vault_server,
            validity_prover,
            balance_processor,
            key.pubkey,
            meta.block_number.unwrap(),
            &withdrawal_data.tx_data,
        )?;

        let withdrawal_witness = WithdrawalWitness {
            transfer_witness: TransferWitness {
                transfer: withdrawal_data.transfer.clone(),
                transfer_index: withdrawal_data.transfer_index,
                transfer_merkle_proof: withdrawal_data.transfer_merkle_proof.clone(),
                tx: withdrawal_data.tx_data.tx.clone(),
            },
            balance_proof: new_user_balance_proof,
        };
        let transition_inclusion_value = withdrawal_witness
            .to_transition_inclusion_value(&balance_processor.get_verifier_data())
            .map_err(|e| anyhow::anyhow!("failed to create transition inclusion value: {}", e))?;
        let single_withdrawal_circuit = withdrawal_aggregator.single_withdrawal_circuit();
        let single_withdrawal_proof = single_withdrawal_circuit
            .prove(&transition_inclusion_value)
            .map_err(|e| anyhow::anyhow!("failed to prove single withdrawal: {}", e))?;
        withdrawal_aggregator
            .add(&single_withdrawal_proof)
            .map_err(|e| anyhow::anyhow!("failed to add withdrawal: {}", e))?;

        // update user data
        user_data.processed_withdrawal_uuids.push(meta.uuid.clone());

        // save user data
        store_vault_server.save_user_data(key.pubkey, user_data.encrypt(key.pubkey));

        Ok(())
    }

    // generate sender's balance proof after applying the tx
    // save the proof to the data store server
    fn generate_new_sender_balance_proof<F, C, const D: usize>(
        &self,
        store_vault_server: &mut StoreVaultServer<F, C, D>,
        validity_prover: &BlockValidityProver<F, C, D>,
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

        let new_sender_balance_proof = store_vault_server
            .get_balance_proof(sender, block_number, spent_proof_pis.new_private_commitment)
            .map_err(|e| anyhow::anyhow!("failed to get new balance proof: {}", e))?;
        if new_sender_balance_proof.is_some() {
            // already updated
            return Ok(new_sender_balance_proof.unwrap());
        }

        let prev_sender_balance_proof = store_vault_server
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

        store_vault_server.save_balance_proof(sender, new_sender_balance_proof.clone());

        Ok(new_sender_balance_proof)
    }

    pub fn get_user_data<F, C, const D: usize>(
        &self,
        key: KeySet,
        store_vault_server: &StoreVaultServer<F, C, D>,
    ) -> anyhow::Result<UserData>
    where
        F: RichField + Extendable<D>,
        C: GenericConfig<D, F = F> + 'static,
        <C as GenericConfig<D>>::Hasher: AlgebraicHasher<F>,
    {
        let user_data = store_vault_server
            .get_user_data(key.pubkey)
            .map(|encrypted| UserData::decrypt(&encrypted, key))
            .transpose()
            .map_err(|e| anyhow::anyhow!("failed to decrypt user data: {}", e))?
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
