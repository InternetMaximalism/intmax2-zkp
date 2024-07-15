use crate::{
    circuits::validity::validity_pis::ValidityPublicInputs,
    common::{
        trees::{
            sender_tree::{SenderLeaf, SenderTree},
            tx_tree::TxMerkleProof,
        },
        tx::Tx,
    },
    constants::SENDER_TREE_HEIGHT,
};

/// Information needed to prove that a tx has been included in a block
#[derive(Debug, Clone)]
pub struct TxWitness {
    pub validity_pis: ValidityPublicInputs,
    pub sender_leaves: Vec<SenderLeaf>,
    pub tx: Tx,
    pub tx_index: usize,
    pub tx_merkle_proof: TxMerkleProof,
}

impl TxWitness {
    pub fn get_sender_tree(&self) -> SenderTree {
        let mut sender_tree = SenderTree::new(SENDER_TREE_HEIGHT);
        for sender_leaf in self.sender_leaves.clone() {
            sender_tree.push(sender_leaf);
        }
        sender_tree
    }
}
