use crate::{
    common::trees::{
        account_tree::{AccountRegistorationProof, AccountUpdateProof},
        block_hash_tree::{BlockHashMerkleProof, BlockHashTree},
        sender_tree::SenderLeaf,
    },
    constants::BLOCK_HASH_TREE_HEIGHT,
};

/// A structure that holds all the information needed to produce transition proof besides the
/// block_witness
#[derive(Debug, Clone)]
pub struct ValidityTransitionWitness {
    pub sender_leaves: Vec<SenderLeaf>,
    pub block_merkle_proof: BlockHashMerkleProof,
    pub account_registoration_proofs: Option<Vec<AccountRegistorationProof>>,
    pub account_update_proofs: Option<Vec<AccountUpdateProof>>,
}

impl ValidityTransitionWitness {
    pub fn genesis() -> Self {
        let block_tree = BlockHashTree::new(BLOCK_HASH_TREE_HEIGHT);
        let block_merkle_proof = block_tree.prove(0);
        Self {
            sender_leaves: vec![],
            block_merkle_proof,
            account_registoration_proofs: None,
            account_update_proofs: None,
        }
    }
}
