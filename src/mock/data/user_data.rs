use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::{
    common::{
        private_state::{FullPrivateState, FullPrivateStatePacked, PrivateState},
        signature::key_set::KeySet,
    },
    ethereum_types::u256::U256,
};

#[derive(Debug, Clone)]
pub struct UserData {
    pub pubkey: U256,

    pub block_number: u32,
    pub full_private_state: FullPrivateState,

    // processed data
    pub processed_deposit_uuids: Vec<Uuid>,
    pub processed_transfer_uuids: Vec<Uuid>,
    pub processed_tx_uuids: Vec<Uuid>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct UserDataPacked {
    pubkey: U256,

    block_number: u32,
    full_private_state: FullPrivateStatePacked,

    // processed data
    processed_deposit_uuids: Vec<String>,
    processed_transfer_uuids: Vec<String>,
    processed_tx_uuids: Vec<String>,
}

impl UserData {
    fn to_bytes(&self) -> Vec<u8> {
        let packed = UserDataPacked {
            pubkey: self.pubkey,
            block_number: self.block_number,
            full_private_state: self.full_private_state.pack(),
            processed_deposit_uuids: self
                .processed_deposit_uuids
                .iter()
                .map(|uuid| uuid.to_string())
                .collect(),
            processed_transfer_uuids: self
                .processed_transfer_uuids
                .iter()
                .map(|uuid| uuid.to_string())
                .collect(),
            processed_tx_uuids: self
                .processed_tx_uuids
                .iter()
                .map(|uuid| uuid.to_string())
                .collect(),
        };
        bincode::serialize(&packed).unwrap()
    }

    fn from_bytes(bytes: &[u8]) -> anyhow::Result<Self> {
        let packed: UserDataPacked = bincode::deserialize(bytes)?;
        let full_private_state = FullPrivateState::unpack(packed.full_private_state);
        let processed_deposit_uuids = packed
            .processed_deposit_uuids
            .iter()
            .map(|uuid| Uuid::parse_str(uuid).unwrap())
            .collect();
        let processed_transfer_uuids = packed
            .processed_transfer_uuids
            .iter()
            .map(|uuid| Uuid::parse_str(uuid).unwrap())
            .collect();
        let processed_tx_uuids = packed
            .processed_tx_uuids
            .iter()
            .map(|uuid| Uuid::parse_str(uuid).unwrap())
            .collect();
        Ok(Self {
            pubkey: packed.pubkey,
            block_number: packed.block_number,
            full_private_state,
            processed_deposit_uuids,
            processed_transfer_uuids,
            processed_tx_uuids,
        })
    }

    pub fn encrypt(&self, _pubkey: U256) -> Vec<u8> {
        // this is a mock encryption
        let bytes = self.to_bytes();
        bytes
    }

    pub fn decrypt(bytes: &[u8], _key: KeySet) -> anyhow::Result<Self> {
        // this is a mock decryption
        let user_data = UserData::from_bytes(bytes)?;
        Ok(user_data)
    }

    pub fn private_state(&self) -> PrivateState {
        self.full_private_state.to_private_state()
    }
}
