use serde::{Deserialize, Serialize};

use crate::{
    common::{block::Block, deposit::Deposit, salt::Salt, trees::deposit_tree::DepositMerkleProof},
    ethereum_types::u256::U256,
};

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct DepositTimeWitness {
    pub prev_block: Block,
    pub block: Block,
    pub prev_deposit_merkle_proof: DepositMerkleProof,
    pub deposit_merkle_proof: DepositMerkleProof,
    pub deposit_index: u32,
    pub deposit_salt: Salt,
    pub deposit: Deposit,
    pub pubkey: U256,
}
