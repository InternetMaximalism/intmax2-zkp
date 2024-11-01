use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::{
    common::{
        private_state::PrivateState,
        salt::Salt,
        signature::key_set::KeySet,
        trees::{
            asset_tree::{AssetTree, AssetTreePacked},
            nullifier_tree::{NullifierTree, NullifierTreePacked},
        },
    },
    ethereum_types::u256::U256,
};

#[derive(Debug, Clone)]
pub struct UserData {
    pub block_number: u32,
    pub asset_tree: AssetTree,
    pub nullifiers: NullifierTree,
    pub nonce: u32,
    pub salt: Salt,

    // processed data
    pub processed_deposit_uuids: Vec<Uuid>,
    pub processed_transfer_uuids: Vec<Uuid>,
    pub processed_tx_uuids: Vec<Uuid>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct UserDataPacked {
    block_number: u32,
    asset_tree: AssetTreePacked,
    nullifier_tree: NullifierTreePacked,
    nonce: u32,
    salt: Salt,

    // processed data
    processed_deposit_uuids: Vec<String>,
    processed_transfer_uuids: Vec<String>,
    processed_tx_uuids: Vec<String>,
}

impl UserData {
    fn to_bytes(&self) -> Vec<u8> {
        let packed = UserDataPacked {
            block_number: self.block_number,
            asset_tree: self.asset_tree.pack(),
            nullifier_tree: self.nullifiers.pack(),
            nonce: self.nonce,
            salt: self.salt,
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
        let asset_tree = AssetTree::unpack(packed.asset_tree);
        let nullifiers = NullifierTree::unpack(packed.nullifier_tree);
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
            block_number: packed.block_number,
            asset_tree,
            nullifiers,
            nonce: packed.nonce,
            salt: packed.salt,
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
        PrivateState {
            asset_tree_root: self.asset_tree.get_root(),
            nullifier_tree_root: self.nullifiers.get_root(),
            nonce: self.nonce,
            salt: self.salt,
        }
    }
}
