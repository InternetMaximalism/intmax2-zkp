use serde::{Deserialize, Serialize};

use crate::{
    common::{salt::Salt, trees::asset_tree::AssetLeaf},
    ethereum_types::bytes32::Bytes32,
};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UserData {
    pub block_number: u32,
    pub asset_leaves: Vec<AssetLeaf>,
    pub nullifiers: Vec<Bytes32>,
    pub nonce: u32,
    pub salt: Salt,

    // processed data
    pub processed_deposit_uuids: Vec<String>,
    pub processed_transfer_uuids: Vec<String>,
    pub processed_tx_uuids: Vec<String>,
}

impl UserData {}
