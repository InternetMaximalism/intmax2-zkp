use serde::{Deserialize, Serialize};

use crate::common::{transfer::Transfer, trees::transfer_tree::TransferMerkleProof, tx::Tx};

/// All the information needed to incorporate a transfer into a balance proof.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct TransferWitness {
    pub tx: Tx,
    pub transfer: Transfer,
    pub transfer_index: u32,
    pub transfer_merkle_proof: TransferMerkleProof,
}
