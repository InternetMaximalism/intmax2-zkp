use serde::{Deserialize, Serialize};

use crate::{
    common::trees::{
        account_tree::{AccountRegistrationProof, AccountUpdateProof},
        block_hash_tree::{BlockHashMerkleProof, BlockHashTree},
        sender_tree::SenderLeaf,
    },
    constants::BLOCK_HASH_TREE_HEIGHT,
    utils::trees::indexed_merkle_tree::{leaf::IndexedMerkleLeaf, IndexedMerkleProof},
};

/// A structure that holds all the information needed to produce transition proof besides the
/// block_witness
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ValidityTransitionWitness {
    pub sender_leaves: Vec<SenderLeaf>,
    pub block_merkle_proof: BlockHashMerkleProof,
    pub account_registration_proofs: Option<Vec<AccountRegistrationProof>>,
    pub account_update_proofs: Option<Vec<AccountUpdateProof>>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AccountRegistrationProofOrDummy {
    pub index: u64,
    pub low_leaf_index: u64,
    pub prev_low_leaf: IndexedMerkleLeaf,

    // None if it is a dummy proof
    pub low_leaf_proof: Option<IndexedMerkleProof>,

    // None if it is a dummy proof
    pub leaf_proof: Option<IndexedMerkleProof>,
}

impl ValidityTransitionWitness {
    pub fn genesis() -> Self {
        let block_tree = BlockHashTree::new(BLOCK_HASH_TREE_HEIGHT);
        let block_merkle_proof = block_tree.prove(0);
        Self {
            sender_leaves: vec![],
            block_merkle_proof,
            account_registration_proofs: None,
            account_update_proofs: None,
        }
    }
}
