use crate::{
    circuits::validity::validity_pis::ValidityPublicInputs,
    common::trees::{
        account_tree::{AccountRegistorationProof, AccountUpdateProof},
        block_hash_tree::BlockHashMerkleProof,
    },
};

/// A structure that holds all the information needed to produce transition proof besides the
/// block_witness
#[derive(Debug, Clone)]
pub struct ValidityTransitionWitness {
    pub prev_pis: ValidityPublicInputs,
    pub block_merkle_proof: BlockHashMerkleProof,
    pub account_registoration_proofs: Option<Vec<AccountRegistorationProof>>,
    pub account_update_proofs: Option<Vec<AccountUpdateProof>>,
}
