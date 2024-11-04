use anyhow::Ok;
use hashbrown::HashMap;
use plonky2::{
    field::extension::Extendable,
    hash::hash_types::RichField,
    plonk::{config::GenericConfig, proof::ProofWithPublicInputs},
};
use uuid::Uuid;

use crate::{
    circuits::balance::balance_pis::BalancePublicInputs, common::signature::key_set::KeySet,
    ethereum_types::u256::U256, utils::poseidon_hash_out::PoseidonHashOut,
};

use super::data::{
    deposit_data::DepositData, transfer_data::TransferData, tx_data::TxData, user_data::UserData,
};

// The proof of transfer is encrypted with the public key of the person who uses it. The
// balance proof is stored without encryption because the private state is hidden.
pub struct StoreVaultServer<F, C, const D: usize>
where
    F: RichField + Extendable<D>,
    C: GenericConfig<D, F = F>,
{
    balance_proofs: HashMap<U256, HashMap<u32, Vec<ProofWithPublicInputs<F, C, D>>>>, /* pubkey -> block_number -> proof */
    encrypted_deposit_data: HashMap<U256, HashMap<Uuid, Vec<u8>>>, /* receiver's pubkey -> uuid
                                                                    * -> encrypted_deposit_data */
    encrypted_tranfer_data: HashMap<U256, HashMap<Uuid, Vec<u8>>>, /* receiver's pubkey -> uuid
                                                                    * -> encrypted_trasfer_data */
    encrypted_tx_data: HashMap<U256, HashMap<Uuid, Vec<u8>>>, /* sender's pubkey -> uuid ->
                                                               * encrypted_tx_data */

    encrypted_withdrawal_data: HashMap<U256, HashMap<Uuid, Vec<u8>>>, /* receiver's pubkey -> uuid -> encrypted_withdrawal_data */

    encrypted_user_data: HashMap<U256, Vec<u8>>, /* pubkey -> encrypted_user_data */
}

// todo: dont repeat the same code for different data types
impl<F, C, const D: usize> StoreVaultServer<F, C, D>
where
    F: RichField + Extendable<D>,
    C: GenericConfig<D, F = F>,
{
    pub fn new() -> Self {
        Self {
            balance_proofs: HashMap::new(),
            encrypted_deposit_data: HashMap::new(),
            encrypted_tranfer_data: HashMap::new(),
            encrypted_tx_data: HashMap::new(),
            encrypted_withdrawal_data: HashMap::new(),
            encrypted_user_data: HashMap::new(),
        }
    }

    pub fn save_balance_proof(
        &mut self,
        pubkey: U256,
        block_number: u32,
        proof: ProofWithPublicInputs<F, C, D>,
    ) {
        let balance_pis = BalancePublicInputs::from_pis(&proof.public_inputs);
        log::info!(
            "saving balance proof for pubkey: {}, block_number: {}, private commitment: {}",
            pubkey,
            block_number,
            balance_pis.private_commitment
        );
        // todo: add proof verification & duplicate check
        self.balance_proofs
            .entry(pubkey)
            .or_insert_with(HashMap::new)
            .entry(block_number)
            .or_insert_with(Vec::new)
            .push(proof);
    }

    pub fn get_balance_proof(
        &self,
        pubkey: U256,
        block_number: u32,
        private_commitment: PoseidonHashOut,
    ) -> anyhow::Result<Option<ProofWithPublicInputs<F, C, D>>> {
        log::info!(
            "getting balance proof for pubkey: {}, block_number: {}, private commitment: {}",
            pubkey,
            block_number,
            private_commitment
        );
        let empty = HashMap::new();
        let proofs = self.balance_proofs.get(&pubkey).unwrap_or(&empty);

        let empty = Vec::new();
        let proofs = proofs.get(&block_number).unwrap_or(&empty);

        for proof in proofs.iter() {
            let balance_pis = BalancePublicInputs::from_pis(&proof.public_inputs);
            if balance_pis.private_commitment == private_commitment {
                return Ok(Some(proof.clone()));
            }
        }
        Ok(None)
    }

    pub fn save_deposit_data(&mut self, pubkey: U256, deposit_data: DepositData) {
        let encrypted = deposit_data.encrypt(pubkey);
        let uuid = Uuid::new_v4();
        self.encrypted_deposit_data
            .entry(pubkey)
            .or_insert_with(HashMap::new)
            .insert(uuid, encrypted);
    }

    fn get_deposit_data(
        &self,
        key: KeySet,
        exceptions: Vec<Uuid>,
    ) -> anyhow::Result<(Vec<(Uuid, DepositData)>, Vec<Uuid>)> {
        let empty = HashMap::new();
        let list = self
            .encrypted_deposit_data
            .get(&key.pubkey)
            .unwrap_or(&empty);

        let mut decrypted = Vec::new();
        let mut rejected = Vec::new();
        for (uuid, encrypted) in list.iter() {
            if exceptions.contains(uuid) {
                continue;
            }
            match DepositData::decrypt(encrypted, key) {
                std::result::Result::Ok(data) => decrypted.push((*uuid, data)),
                Err(e) => {
                    log::error!("failed to decrypt deposit data: {}", e);
                    rejected.push(*uuid);
                }
            }
        }
        Ok((decrypted, rejected))
    }

    pub fn save_transfer_data(&mut self, pubkey: U256, transfer_data: TransferData<F, C, D>) {
        let encrypted = transfer_data.encrypt(pubkey);
        let uuid = Uuid::new_v4();
        self.encrypted_tranfer_data
            .entry(pubkey)
            .or_insert_with(HashMap::new)
            .insert(uuid, encrypted);
    }

    fn get_transfer_data(
        &self,
        key: KeySet,
        exceptions: Vec<Uuid>,
    ) -> anyhow::Result<(Vec<(Uuid, TransferData<F, C, D>)>, Vec<Uuid>)> {
        let empty = HashMap::new();
        let list = self
            .encrypted_tranfer_data
            .get(&key.pubkey)
            .unwrap_or(&empty);

        let mut decrypted = Vec::new();
        let mut rejected = Vec::new();
        for (uuid, encrypted) in list.iter() {
            if exceptions.contains(uuid) {
                continue;
            }
            match TransferData::decrypt(encrypted, key) {
                std::result::Result::Ok(data) => decrypted.push((*uuid, data)),
                Err(e) => {
                    log::error!("failed to decrypt transfer data: {}", e);
                    rejected.push(*uuid);
                }
            }
        }
        Ok((decrypted, rejected))
    }

    pub fn save_tx_data(&mut self, pubkey: U256, tx_data: TxData<F, C, D>) {
        let encrypted = tx_data.encrypt(pubkey);
        let uuid = Uuid::new_v4();
        self.encrypted_tx_data
            .entry(pubkey)
            .or_insert_with(HashMap::new)
            .insert(uuid, encrypted);
    }

    fn get_tx_data(
        &self,
        key: KeySet,
        exceptions: Vec<Uuid>,
    ) -> anyhow::Result<(Vec<(Uuid, TxData<F, C, D>)>, Vec<Uuid>)> {
        let empty = HashMap::new();
        let list = self.encrypted_tx_data.get(&key.pubkey).unwrap_or(&empty);

        let mut decrypted = Vec::new();
        let mut rejected = Vec::new();
        for (uuid, encrypted) in list.iter() {
            if exceptions.contains(uuid) {
                continue;
            }
            match TxData::decrypt(encrypted, key) {
                std::result::Result::Ok(data) => decrypted.push((*uuid, data)),
                Err(e) => {
                    log::error!("failed to decrypt tx data: {}", e);
                    rejected.push(*uuid);
                }
            }
        }
        Ok((decrypted, rejected))
    }

    pub fn save_withdrawal_data(&mut self, pubkey: U256, withdrawal_data: TransferData<F, C, D>) {
        let encrypted = withdrawal_data.encrypt(pubkey);
        let uuid = Uuid::new_v4();
        self.encrypted_withdrawal_data
            .entry(pubkey)
            .or_insert_with(HashMap::new)
            .insert(uuid, encrypted);
    }

    pub fn get_withdrawal_data(
        &self,
        key: KeySet,
        except: Vec<Uuid>,
    ) -> anyhow::Result<(Vec<(Uuid, TransferData<F, C, D>)>, Vec<Uuid>)> {
        let empty = HashMap::new();
        let list = self
            .encrypted_withdrawal_data
            .get(&key.pubkey)
            .unwrap_or(&empty);

        let mut decrypted = Vec::new();
        let mut rejected = Vec::new();
        for (uuid, encrypted) in list.iter() {
            if except.contains(uuid) {
                continue;
            }
            match TransferData::decrypt(encrypted, key) {
                std::result::Result::Ok(data) => decrypted.push((*uuid, data)),
                Err(e) => {
                    log::error!("failed to decrypt withdrawal data: {}", e);
                    rejected.push(*uuid);
                }
            }
        }
        Ok((decrypted, rejected))
    }

    pub fn save_user_data(&mut self, pubkey: U256, user_data: UserData) {
        let encrypted = user_data.encrypt(pubkey);
        self.encrypted_user_data.insert(pubkey, encrypted);
    }

    pub fn get_user_data(&self, key: KeySet) -> anyhow::Result<Option<UserData>> {
        let encrypted = self.encrypted_user_data.get(&key.pubkey);
        if encrypted.is_none() {
            return Ok(None);
        }
        let user_data = UserData::decrypt(&encrypted.unwrap(), key)
            .map_err(|e| anyhow::anyhow!("failed to decrypt user data{}", e))?;
        Ok(Some(user_data))
    }

    pub fn get_transition_data(
        &self,
        key: KeySet,
        except_deposits: Vec<Uuid>,
        except_transfers: Vec<Uuid>,
        except_txs: Vec<Uuid>,
    ) -> anyhow::Result<TransitionData<F, C, D>> {
        let (deposit_data, rejected_deposits) = self.get_deposit_data(key, except_deposits)?;
        let (transfer_data, rejected_transfers) = self.get_transfer_data(key, except_transfers)?;
        let (tx_data, rejected_txs) = self.get_tx_data(key, except_txs)?;
        Ok(TransitionData {
            deposit_data,
            transfer_data,
            tx_data,
            rejected_deposits,
            rejected_transfers,
            rejected_txs,
        })
    }
}

pub struct TransitionData<F, C, const D: usize>
where
    F: RichField + Extendable<D>,
    C: GenericConfig<D, F = F>,
{
    pub deposit_data: Vec<(Uuid, DepositData)>,
    pub transfer_data: Vec<(Uuid, TransferData<F, C, D>)>,
    pub tx_data: Vec<(Uuid, TxData<F, C, D>)>,
    pub rejected_deposits: Vec<Uuid>,
    pub rejected_transfers: Vec<Uuid>,
    pub rejected_txs: Vec<Uuid>,
}
