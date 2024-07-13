use crate::common::{
    private_state::PrivateState,
    transfer::Transfer,
    trees::asset_tree::{AssetLeaf, AssetMerkleProof},
};

use super::tx_witness::TxWitness;

/// Information needed to prove that a balance has been sent
#[derive(Debug, Clone)]
pub struct SendWitness {
    pub prev_private_state: PrivateState,
    pub prev_balances: Vec<AssetLeaf>,
    pub asset_merkle_proofs: Vec<AssetMerkleProof>,
    pub transfers: Vec<Transfer>,
    pub tx_witness: TxWitness,
}
