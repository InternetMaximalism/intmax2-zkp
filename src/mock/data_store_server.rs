use hashbrown::HashMap;
use plonky2::{
    field::extension::Extendable,
    hash::hash_types::RichField,
    plonk::{config::GenericConfig, proof::ProofWithPublicInputs},
};
use uuid::Uuid;

use crate::ethereum_types::u256::U256;

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
}
