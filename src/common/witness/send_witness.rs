use crate::{
    circuits::balance::{balance_pis::BalancePublicInputs, send::spent_circuit::SpentValue},
    common::{
        insufficient_flags::InsufficientFlags,
        private_state::PrivateState,
        salt::Salt,
        transfer::Transfer,
        trees::asset_tree::{AssetLeaf, AssetMerkleProof},
    },
    utils::{leafable::Leafable, poseidon_hash_out::PoseidonHashOut},
};

use super::tx_witness::TxWitness;

/// Information needed to prove that a balance has been sent
#[derive(Debug, Clone)]
pub struct SendWitness {
    pub prev_balance_pis: BalancePublicInputs,
    pub prev_private_state: PrivateState,
    pub prev_balances: Vec<AssetLeaf>,
    pub asset_merkle_proofs: Vec<AssetMerkleProof>,
    pub insufficient_flags: InsufficientFlags,
    pub transfers: Vec<Transfer>,
    pub tx_witness: TxWitness,
    pub new_salt: Salt,
}

#[derive(Debug, Clone)]
pub struct SendWitnessResult {
    pub is_valid: bool,
    pub last_tx_hash: PoseidonHashOut,
    pub last_tx_insufficient_flags: InsufficientFlags,
}

impl SendWitness {
    /// get block number of the block that contains the tx.
    pub fn get_included_block_number(&self) -> u32 {
        self.tx_witness
            .validity_witness
            .block_witness
            .block
            .block_number
    }

    /// get block number of the previous balance pis
    pub fn get_prev_block_number(&self) -> u32 {
        self.prev_balance_pis.public_state.block_number
    }

    // get last_tx_hash and last_tx_insufficient_flags
    // assuming that the tx is included in the block
    // TODO: consider include validity proof verification
    pub fn get_next_last_tx(&self) -> SendWitnessResult {
        let spent_value = SpentValue::new(
            &self.prev_private_state,
            &self.prev_balances,
            self.new_salt,
            &self.transfers,
            &self.asset_merkle_proofs,
            self.tx_witness.tx.nonce,
        );
        let is_valid = spent_value.is_valid;
        let last_tx_hash = if is_valid {
            spent_value.tx.hash()
        } else {
            self.prev_balance_pis.last_tx_hash
        };
        let last_tx_insufficient_flags = if is_valid {
            spent_value.insufficient_flags
        } else {
            self.prev_balance_pis.last_tx_insufficient_flags
        };
        SendWitnessResult {
            is_valid,
            last_tx_hash,
            last_tx_insufficient_flags,
        }
    }
}
