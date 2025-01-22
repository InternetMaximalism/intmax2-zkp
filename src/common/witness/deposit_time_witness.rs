use serde::{Deserialize, Serialize};

use crate::common::{block::Block, trees::deposit_tree::DepositMerkleProof};

use super::deposit_witness::DepositWitness;

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct DepositTimeWitness {
    pub prev_block: Block,
    pub block: Block,
    pub prev_deposit_merkle_proof: DepositMerkleProof,
    pub deposit_witness: DepositWitness,
}
