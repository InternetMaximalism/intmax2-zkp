use crate::common::{
    trees::{transfer_tree::TransferTree, tx_tree::TxMerkleProof},
    tx::Tx,
};

use super::{block_witness::BlockWitness, transfer_witness::TransferWitness};

/// Information needed to prove that a tx has been included in a block
#[derive(Debug, Clone)]
pub struct TxWitness {
    pub block_witness: BlockWitness,
    pub tx: Tx,
    pub tx_index: usize,
    pub tx_merkle_proof: TxMerkleProof,
}

#[derive(Debug, Clone)]
pub struct TxInfo {
    pub tx_witness: TxWitness,
    pub transfer_tree: TransferTree,
}

impl TxInfo {
    pub fn generate_transfer_witnesses(&self) -> Vec<TransferWitness> {
        return self
            .transfer_tree
            .leaves()
            .into_iter()
            .enumerate()
            .map(|(transfer_index, transfer)| {
                let transfer_merkle_proof = self.transfer_tree.prove(transfer_index);
                TransferWitness {
                    tx_witness: self.tx_witness.clone(),
                    transfer: transfer.clone(),
                    transfer_index,
                    transfer_merkle_proof,
                }
            })
            .collect();
    }
}
