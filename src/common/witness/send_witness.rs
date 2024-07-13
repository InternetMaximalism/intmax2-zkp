use crate::{
    circuits::balance::balance_pis::BalancePublicInputs,
    common::{
        private_state::PrivateState,
        transfer::Transfer,
        trees::asset_tree::{AssetLeaf, AssetMerkleProof},
    },
};

use super::tx_witness::TxWitness;

/// Information needed to prove that a balance has been sent
#[derive(Debug, Clone)]
pub struct SendWitness {
    pub prev_balance_pis: BalancePublicInputs,
    pub prev_private_state: PrivateState,
    pub prev_balances: Vec<AssetLeaf>,
    pub asset_merkle_proofs: Vec<AssetMerkleProof>,
    pub transfers: Vec<Transfer>,
    pub tx_witness: TxWitness,
}

impl SendWitness {
    /// get block number of the block that contains the tx.
    pub fn get_included_block_number(&self) -> u32 {
        self.tx_witness.block_witness.block.block_number
    }

    /// get block number of the previous balance pis
    pub fn get_prev_block_number(&self) -> u32 {
        self.prev_balance_pis.public_state.block_number
    }
}
