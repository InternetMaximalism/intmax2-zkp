use crate::common::{trees::tx_tree::TxMerkleProof, tx::Tx};

use super::validity_witness::ValidityWitness;

/// Information needed to prove that a tx has been included in a block
#[derive(Debug, Clone)]
pub struct TxWitness {
    pub validity_witness: ValidityWitness,
    pub tx: Tx,
    pub tx_index: usize,
    pub tx_merkle_proof: TxMerkleProof,
}
