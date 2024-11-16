use serde::{Deserialize, Serialize};

use crate::common::{deposit::Deposit, salt::Salt, trees::deposit_tree::DepositMerkleProof};

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct DepositWitness {
    pub deposit_salt: Salt,
    pub deposit_index: u32,
    pub deposit: Deposit,
    pub deposit_merkle_proof: DepositMerkleProof,
}

// without deposit_merkle_proof
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct DepositCase {
    pub deposit_salt: Salt,
    pub deposit_index: u32,
    pub deposit: Deposit,
}
