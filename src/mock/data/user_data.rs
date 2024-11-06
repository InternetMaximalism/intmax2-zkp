use hashbrown::HashMap;
use serde::{Deserialize, Serialize};
use uuid::Uuid;

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

    // last processed timestamps
    pub deposit_lpt: u64,
    pub transfer_lpt: u64,
    pub tx_lpt: u64,
    pub withdrawal_lpt: u64,

    // processed data
    pub processed_deposit_uuids: Vec<Uuid>,
    pub processed_transfer_uuids: Vec<Uuid>,
    pub processed_tx_uuids: Vec<Uuid>,
    pub processed_withdrawal_uuids: Vec<Uuid>,

    // rejected data
    pub rejected_deposit_uuids: Vec<Uuid>,
    pub rejected_transfer_uuids: Vec<Uuid>,
    pub rejected_processed_tx_uuids: Vec<Uuid>,
    pub rejected_withdrawal_uuids: Vec<Uuid>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct UserDataPacked {
    pubkey: U256,
    block_number: u32,
    full_private_state: FullPrivateStatePacked,

    // last processed timestamps
    pub deposit_lpt: u64,
    pub transfer_lpt: u64,
    pub tx_lpt: u64,
    pub withdrawal_lpt: u64,

    // processed data
    pub processed_deposit_uuids: Vec<Uuid>,
    pub processed_transfer_uuids: Vec<Uuid>,
    pub processed_tx_uuids: Vec<Uuid>,
    pub processed_withdrawal_uuids: Vec<Uuid>,

    // rejected data
    pub rejected_deposit_uuids: Vec<Uuid>,
    pub rejected_transfer_uuids: Vec<Uuid>,
    pub rejected_processed_tx_uuids: Vec<Uuid>,
    pub rejected_withdrawal_uuids: Vec<Uuid>,
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
            processed_deposit_uuids: vec![],
            processed_transfer_uuids: vec![],
            processed_tx_uuids: vec![],
            processed_withdrawal_uuids: vec![],
            rejected_deposit_uuids: vec![],
            rejected_transfer_uuids: vec![],
            rejected_processed_tx_uuids: vec![],
            rejected_withdrawal_uuids: vec![],
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
            processed_deposit_uuids: self.processed_deposit_uuids.clone(),
            processed_transfer_uuids: self.processed_transfer_uuids.clone(),
            processed_tx_uuids: self.processed_tx_uuids.clone(),
            processed_withdrawal_uuids: self.processed_withdrawal_uuids.clone(),
            rejected_deposit_uuids: self.rejected_deposit_uuids.clone(),
            rejected_transfer_uuids: self.rejected_transfer_uuids.clone(),
            rejected_processed_tx_uuids: self.rejected_processed_tx_uuids.clone(),
            rejected_withdrawal_uuids: self.rejected_withdrawal_uuids.clone(),
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
            processed_deposit_uuids: packed.processed_deposit_uuids.clone(),
            processed_transfer_uuids: packed.processed_transfer_uuids.clone(),
            processed_tx_uuids: packed.processed_tx_uuids.clone(),
            processed_withdrawal_uuids: packed.processed_withdrawal_uuids.clone(),
            rejected_deposit_uuids: packed.rejected_deposit_uuids.clone(),
            rejected_transfer_uuids: packed.rejected_transfer_uuids.clone(),
            rejected_processed_tx_uuids: packed.rejected_processed_tx_uuids.clone(),
            rejected_withdrawal_uuids: packed.rejected_withdrawal_uuids.clone(),
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

    pub fn deposit_exception_uudis(&self) -> Vec<Uuid> {
        self.processed_deposit_uuids
            .iter()
            .chain(self.rejected_deposit_uuids.iter())
            .cloned()
            .collect()
    }

    pub fn transfer_exception_uudis(&self) -> Vec<Uuid> {
        self.processed_transfer_uuids
            .iter()
            .chain(self.rejected_transfer_uuids.iter())
            .cloned()
            .collect()
    }

    pub fn tx_exception_uudis(&self) -> Vec<Uuid> {
        self.processed_tx_uuids
            .iter()
            .chain(self.rejected_processed_tx_uuids.iter())
            .cloned()
            .collect()
    }

    pub fn withdrawal_exception_uudis(&self) -> Vec<Uuid> {
        self.processed_withdrawal_uuids
            .iter()
            .chain(self.rejected_withdrawal_uuids.iter())
            .cloned()
            .collect()
    }

    pub fn private_commitment(&self) -> PoseidonHashOut {
        self.full_private_state.to_private_state().commitment()
    }

    pub fn balances(&self) -> HashMap<usize, AssetLeaf> {
        self.full_private_state.asset_tree.leaves()
    }
}
