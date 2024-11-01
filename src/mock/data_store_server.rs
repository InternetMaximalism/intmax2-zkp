use anyhow::Ok;
use hashbrown::HashMap;
use plonky2::{
    field::extension::Extendable,
    hash::hash_types::RichField,
    plonk::{config::GenericConfig, proof::ProofWithPublicInputs},
};
use uuid::Uuid;

use crate::{common::signature::key_set::KeySet, ethereum_types::u256::U256};

use super::data::user_data::UserData;

// The proof of transfer is encrypted with the public key of the person who uses it. The
// balance proof is stored without encryption because the private state is hidden.
pub struct DataStoreServer<F, C, const D: usize>
where
    F: RichField + Extendable<D>,
    C: GenericConfig<D, F = F>,
{
    balance_proofs: HashMap<U256, HashMap<u32, Vec<ProofWithPublicInputs<F, C, D>>>>, /* pubkey -> block_number -> proof */
    encrypted_deposit_data: HashMap<U256, HashMap<Uuid, Vec<u8>>>,                    /* receiver's
                                                                                       * pubkey ->
                                                                                       * deposit_id
                                                                                       * ->
                                                                                       * encrypted_deposit_data */
    encrypted_tranfer_data: HashMap<U256, HashMap<Uuid, Vec<u8>>>, /* receiver's
                                                                    * pubkey ->
                                                                    * transfer_id
                                                                    * ->
                                                                    * encrypted_trasfer_data */
    encrypted_tx_data: HashMap<U256, HashMap<Uuid, Vec<u8>>>, /* sender's pubkey -> tx_id ->
                                                               * encrypted_tx_data */

    encrypted_user_data: HashMap<U256, Vec<u8>>, /* pubkey -> encrypted_user_data */
}

impl<F, C, const D: usize> DataStoreServer<F, C, D>
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
            encrypted_user_data: HashMap::new(),
        }
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
}
