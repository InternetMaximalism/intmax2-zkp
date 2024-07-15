use crate::common::trees::{
    account_tree::{AccountRegistorationProof, AccountUpdateProof},
    block_hash_tree::BlockHashMerkleProof,
    sender_tree::SenderLeaf,
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
