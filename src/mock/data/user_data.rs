use hashbrown::HashMap;
use serde::{Deserialize, Serialize};

use crate::{
    common::{
        private_state::{FullPrivateState, FullPrivateStatePacked, PrivateState},
        signature::key_set::KeySet,
        trees::asset_tree::AssetLeaf,
    },
    ethereum_types::u256::U256,
    utils::poseidon_hash_out::PoseidonHashOut,
};

#[derive(Debug, Clone)]
pub struct UserData {
    pub pubkey: U256,

    pub block_number: u32,
    pub full_private_state: FullPrivateState,

    // The latest unix timestamp of processed (incorporated into the balance proof or rejected)
    // actions
    pub deposit_lpt: u64,
    pub transfer_lpt: u64,
    pub tx_lpt: u64,
    pub withdrawal_lpt: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct UserDataPacked {
    pubkey: U256,
    block_number: u32,
    full_private_state: FullPrivateStatePacked,

    pub deposit_lpt: u64,
    pub transfer_lpt: u64,
    pub tx_lpt: u64,
    pub withdrawal_lpt: u64,
}

impl UserData {
    pub fn new(pubkey: U256) -> Self {
        Self {
            pubkey,
            block_number: 0,
            full_private_state: FullPrivateState::new(),

            deposit_lpt: 0,
            transfer_lpt: 0,
            tx_lpt: 0,
            withdrawal_lpt: 0,
        }
    }

    fn to_bytes(&self) -> Vec<u8> {
        let packed = UserDataPacked {
            pubkey: self.pubkey,
            block_number: self.block_number,
            full_private_state: self.full_private_state.pack(),
            deposit_lpt: self.deposit_lpt,
            transfer_lpt: self.transfer_lpt,
            tx_lpt: self.tx_lpt,
            withdrawal_lpt: self.withdrawal_lpt,
        };
        bincode::serialize(&packed).unwrap()
    }

    fn from_bytes(bytes: &[u8]) -> anyhow::Result<Self> {
        let packed: UserDataPacked = bincode::deserialize(bytes)?;
        let full_private_state = FullPrivateState::unpack(packed.full_private_state);
        Ok(Self {
            pubkey: packed.pubkey,
            block_number: packed.block_number,
            full_private_state,
            deposit_lpt: packed.deposit_lpt,
            transfer_lpt: packed.transfer_lpt,
            tx_lpt: packed.tx_lpt,
            withdrawal_lpt: packed.withdrawal_lpt,
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

    pub fn private_commitment(&self) -> PoseidonHashOut {
        self.full_private_state.to_private_state().commitment()
    }

    pub fn balances(&self) -> HashMap<usize, AssetLeaf> {
        self.full_private_state.asset_tree.leaves()
    }
}
