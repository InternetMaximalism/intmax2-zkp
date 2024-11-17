use anyhow::Ok;
use hashbrown::HashMap;
use plonky2::{
    field::extension::Extendable,
    hash::hash_types::RichField,
    plonk::{config::GenericConfig, proof::ProofWithPublicInputs},
};
use uuid::Uuid;

use crate::{
    circuits::balance::balance_pis::BalancePublicInputs, ethereum_types::u256::U256,
    utils::poseidon_hash_out::PoseidonHashOut,
};

use super::data::meta_data::MetaData;

// The proof of transfer is encrypted with the public key of the person who uses it. The
// balance proof is stored without encryption because the private state is hidden.
pub struct StoreVaultServer<F, C, const D: usize>
where
    F: RichField + Extendable<D>,
    C: GenericConfig<D, F = F>,
{
    encrypted_user_data: HashMap<U256, Vec<u8>>, /* pubkey -> encrypted_user_data */
    balance_proofs: HashMap<U256, HashMap<u32, Vec<ProofWithPublicInputs<F, C, D>>>>, /* pubkey -> block_number -> proof */

    encrypted_deposit_data: EncryptedDataMap, /* receiver's pubkey ->
                                               * encrypted_deposit_data */
    encrypted_tranfer_data: EncryptedDataMap, /* receiver's pubkey ->
                                               * encrypted_transfer_data */
    encrypted_tx_data: EncryptedDataMap, /* sender's pubkey ->
                                          * encrypted_tx_data */
    encrypted_withdrawal_data: EncryptedDataMap, /* receiver's pubkey ->
                                                  * encrypted_withdrawal_data */
}

impl<F, C, const D: usize> StoreVaultServer<F, C, D>
where
    F: RichField + Extendable<D>,
    C: GenericConfig<D, F = F>,
{
    pub fn new() -> Self {
        Self {
            encrypted_user_data: HashMap::new(),
            balance_proofs: HashMap::new(),
            encrypted_deposit_data: EncryptedDataMap::new(),
            encrypted_tranfer_data: EncryptedDataMap::new(),
            encrypted_tx_data: EncryptedDataMap::new(),
            encrypted_withdrawal_data: EncryptedDataMap::new(),
        }
    }

    pub fn reset(&mut self) {
        *self = Self::new();
    }

    pub fn save_balance_proof(&mut self, pubkey: U256, proof: ProofWithPublicInputs<F, C, D>) {
        let balance_pis = BalancePublicInputs::from_pis(&proof.public_inputs);
        log::info!(
            "saving balance proof for pubkey: {}, block_number: {}, private commitment: {}",
            pubkey,
            balance_pis.public_state.block_number,
            balance_pis.private_commitment
        );
        // todo: add proof verification & duplicate check
        self.balance_proofs
            .entry(pubkey)
            .or_insert_with(HashMap::new)
            .entry(balance_pis.public_state.block_number)
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

    pub fn save_deposit_data(&mut self, pubkey: U256, encypted_data: Vec<u8>) {
        self.encrypted_deposit_data.insert(pubkey, encypted_data);
    }

    pub fn get_deposit_data_all_after(
        &self,
        pubkey: U256,
        timestamp: u64,
    ) -> Vec<(MetaData, Vec<u8>)> {
        self.encrypted_deposit_data.get_all_after(pubkey, timestamp)
    }

    pub fn get_deposit_data(&self, uuid: &str) -> Option<(MetaData, Vec<u8>)> {
        self.encrypted_deposit_data.get(uuid)
    }

    pub fn save_transfer_data(&mut self, pubkey: U256, encypted_data: Vec<u8>) {
        self.encrypted_tranfer_data.insert(pubkey, encypted_data);
    }

    pub fn get_transfer_data(&self, uuid: &str) -> Option<(MetaData, Vec<u8>)> {
        self.encrypted_tranfer_data.get(uuid)
    }

    pub fn get_transfer_data_all_after(
        &self,
        pubkey: U256,
        timestamp: u64,
    ) -> Vec<(MetaData, Vec<u8>)> {
        self.encrypted_tranfer_data.get_all_after(pubkey, timestamp)
    }

    pub fn save_tx_data(&mut self, pubkey: U256, encypted_data: Vec<u8>) {
        self.encrypted_tx_data.insert(pubkey, encypted_data);
    }

    pub fn get_tx_data(&self, uuid: &str) -> Option<(MetaData, Vec<u8>)> {
        self.encrypted_tx_data.get(uuid)
    }

    pub fn get_tx_data_all_after(&self, pubkey: U256, timestamp: u64) -> Vec<(MetaData, Vec<u8>)> {
        self.encrypted_tx_data.get_all_after(pubkey, timestamp)
    }

    pub fn save_withdrawal_data(&mut self, pubkey: U256, encypted_data: Vec<u8>) {
        self.encrypted_withdrawal_data.insert(pubkey, encypted_data);
    }

    pub fn get_withdrawal_data(&self, uuid: &str) -> Option<(MetaData, Vec<u8>)> {
        self.encrypted_withdrawal_data.get(uuid)
    }

    pub fn get_withdrawal_data_all_after(
        &self,
        pubkey: U256,
        timestamp: u64,
    ) -> Vec<(MetaData, Vec<u8>)> {
        self.encrypted_withdrawal_data
            .get_all_after(pubkey, timestamp)
    }

    pub fn save_user_data(&mut self, pubkey: U256, encrypted_data: Vec<u8>) {
        self.encrypted_user_data.insert(pubkey, encrypted_data);
    }

    pub fn get_user_data(&self, pubkey: U256) -> Option<Vec<u8>> {
        self.encrypted_user_data.get(&pubkey).cloned()
    }
}

struct EncryptedDataMap(HashMap<U256, Vec<(MetaData, Vec<u8>)>>);

impl EncryptedDataMap {
    pub fn new() -> Self {
        Self(HashMap::new())
    }

    pub fn insert(&mut self, pubkey: U256, encrypted_data: Vec<u8>) {
        let meta_data = MetaData {
            uuid: Uuid::new_v4().to_string(),
            timestamp: chrono::Utc::now().timestamp() as u64,
            block_number: None,
        };
        self.0
            .entry(pubkey)
            .or_insert_with(Vec::new)
            .push((meta_data, encrypted_data));
    }

    pub fn get_all_after(&self, pubkey: U256, timestamp: u64) -> Vec<(MetaData, Vec<u8>)> {
        let empty = Vec::new();
        let list = self.0.get(&pubkey).unwrap_or(&empty);
        let mut result = Vec::new();
        for (meta_data, data) in list.iter() {
            if meta_data.timestamp > timestamp {
                result.push((meta_data.clone(), data.clone()));
            }
        }
        // sort by timestamp
        result.sort_by(|a, b| a.0.timestamp.cmp(&b.0.timestamp));

        result
    }

    pub fn get(&self, uuid: &str) -> Option<(MetaData, Vec<u8>)> {
        for (_, list) in self.0.iter() {
            for (meta_data, data) in list.iter() {
                if meta_data.uuid == uuid {
                    return Some((meta_data.clone(), data.clone()));
                }
            }
        }
        None
    }
}
