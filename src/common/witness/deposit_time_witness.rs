use serde::{Deserialize, Serialize};

use crate::{
    circuits::claim::deposit_time::DepositTimeValue,
    common::{
        block::Block, 
        deposit::Deposit, 
        error::CommonError, 
        salt::Salt, 
        trees::deposit_tree::DepositMerkleProof
    },
    ethereum_types::u256::U256,
};

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct DepositTimePublicWitness {
    pub prev_block: Block,
    pub block: Block,
    pub prev_deposit_merkle_proof: DepositMerkleProof,
    pub deposit_merkle_proof: DepositMerkleProof,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct DepositTimeWitness {
    pub public_witness: DepositTimePublicWitness,
    pub deposit_index: u32,
    pub deposit: Deposit,
    pub deposit_salt: Salt,
    pub pubkey: U256,
}

impl DepositTimeWitness {
    pub fn to_value(&self) -> Result<DepositTimeValue, CommonError> {
        DepositTimeValue::new(
            &self.public_witness.prev_block,
            &self.public_witness.block,
            &self.public_witness.prev_deposit_merkle_proof,
            &self.public_witness.deposit_merkle_proof,
            &self.deposit,
            self.deposit_index,
            self.deposit_salt,
            self.pubkey,
        )
    }
}
