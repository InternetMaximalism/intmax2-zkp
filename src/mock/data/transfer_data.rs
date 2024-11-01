use plonky2::{
    field::extension::Extendable, hash::hash_types::RichField, plonk::config::GenericConfig,
};
use serde::{Deserialize, Serialize};

use crate::{
    common::{
        signature::key_set::KeySet, transfer::Transfer, trees::transfer_tree::TransferMerkleProof,
    },
    ethereum_types::u256::U256,
    utils::poseidon_hash_out::PoseidonHashOut,
};

use super::tx_data::TxData;

// backup data for receiving transfers
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
#[serde(bound = "")]
pub struct TransferData<F, C, const D: usize>
where
    F: RichField + Extendable<D>,
    C: GenericConfig<D, F = F>,
{
    // Info to query the sender's prev balance proof
    pub sender: U256,
    pub prev_block_number: u32,
    pub prev_private_commitment: PoseidonHashOut,

    // Info to update the sender's balance proof
    pub tx_data: TxData<F, C, D>,

    // Used for updating receiver's balance proof
    pub transfer: Transfer,
    pub transfer_index: usize,
    pub transfer_merkle_proof: TransferMerkleProof,
}

impl<F, C, const D: usize> TransferData<F, C, D>
where
    F: RichField + Extendable<D>,
    C: GenericConfig<D, F = F>,
{
    fn to_bytes(&self) -> Vec<u8> {
        bincode::serialize(self).unwrap()
    }

    fn from_bytes(bytes: &[u8]) -> anyhow::Result<Self> {
        let data = bincode::deserialize(bytes)?;
        Ok(data)
    }

    pub fn encrypt(&self, _pubkey: U256) -> Vec<u8> {
        let bytes = self.to_bytes();
        bytes
    }

    pub fn decrypt(bytes: &[u8], _key: KeySet) -> anyhow::Result<Self> {
        let data = Self::from_bytes(bytes)?;
        Ok(data)
    }
}
