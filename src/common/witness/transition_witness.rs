use crate::{
    circuits::validity::validity_pis::ValidityPublicInputs,
    common::trees::account_tree::{AccountRegistorationProof, AccountUpdateProof},
};

/// A structure that holds all the information needed to produce transition proof besides the
/// block_witness
#[derive(Debug, Clone)]
pub struct TransitionWitness {
    pub prev_pis: ValidityPublicInputs,
    pub account_registoration_proofs: Option<Vec<AccountRegistorationProof>>,
    pub account_update_proofs: Option<Vec<AccountUpdateProof>>,
}
