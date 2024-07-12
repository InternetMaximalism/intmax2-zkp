use crate::common::{transfer::Transfer, trees::transfer_tree::TransferMerkleProof};

use super::tx_witness::TxWitness;

/// All the information needed to incorporate a transfer into a balance proof.
#[derive(Debug, Clone)]
pub struct TransferWitness {
    pub tx_witness: TxWitness,
    pub transfer: Transfer,
    pub transfer_index: usize,
    pub transfer_merkle_proof: TransferMerkleProof,
}
