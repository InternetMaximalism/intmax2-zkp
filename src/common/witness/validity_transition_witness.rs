use crate::common::trees::{
    account_tree::{AccountRegistorationProof, AccountUpdateProof},
    block_hash_tree::BlockHashMerkleProof,
};

use super::block_witness::BlockWitness;

pub struct ValidityTransitionWitness {
    pub prev_block_witness: BlockWitness,
    pub new_block_witness: BlockWitness,
    pub account_registoration_proofs: Option<Vec<AccountRegistorationProof>>,
    pub account_update_proofs: Option<Vec<AccountUpdateProof>>,
    pub block_hash_merkle_proof: BlockHashMerkleProof,
}
