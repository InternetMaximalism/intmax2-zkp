use serde::{Deserialize, Serialize};

use crate::{
    circuits::balance::receive::receive_targets::{
        error::ReceiveTargetsError, private_state_transition::PrivateStateTransitionValue,
    },
    common::{
        deposit::Deposit,
        error::CommonError,
        private_state::{FullPrivateState, PrivateState},
        salt::Salt,
        transfer::Transfer,
        trees::{
            asset_tree::{AssetLeaf, AssetMerkleProof},
            nullifier_tree::NullifierInsertionProof,
        },
    },
    ethereum_types::{bytes32::Bytes32, u256::U256},
};

// A witness to update the private state when a new transfer/deposit is received
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PrivateTransitionWitness {
    pub token_index: u32,
    pub amount: U256,
    pub nullifier: Bytes32,
    pub new_salt: Salt,
    pub prev_private_state: PrivateState,
    pub nullifier_proof: NullifierInsertionProof,
    pub prev_asset_leaf: AssetLeaf,
    pub asset_merkle_proof: AssetMerkleProof,
}

impl PrivateTransitionWitness {
    pub fn new(
        full_private_state: &mut FullPrivateState,
        token_index: u32,
        amount: U256,
        nullifier: Bytes32,
        new_salt: Salt,
    ) -> Result<Self, CommonError> {
        let prev_private_state = full_private_state.to_private_state();
        let prev_asset_leaf = full_private_state.asset_tree.get_leaf(token_index as u64);
        let asset_merkle_proof = full_private_state.asset_tree.prove(token_index as u64);
        let new_asset_leaf = prev_asset_leaf.add(amount); // receiving token
        full_private_state
            .asset_tree
            .update(token_index as u64, new_asset_leaf);
        let nullifier_proof = full_private_state
            .nullifier_tree
            .prove_and_insert(nullifier)
            .map_err(|e| CommonError::NullifierAlreadyExists(e.to_string()))?;
        full_private_state.salt = new_salt;
        full_private_state.prev_private_commitment = prev_private_state.commitment();
        Ok(PrivateTransitionWitness {
            token_index,
            amount,
            nullifier,
            new_salt,
            prev_private_state,
            nullifier_proof,
            prev_asset_leaf,
            asset_merkle_proof,
        })
    }

    pub fn from_transfer(
        full_private_state: &mut FullPrivateState,
        transfer: Transfer,
        new_salt: Salt,
    ) -> Result<Self, CommonError> {
        let nullifier: Bytes32 = transfer.commitment().into();
        Self::new(
            full_private_state,
            transfer.token_index,
            transfer.amount,
            nullifier,
            new_salt,
        )
    }

    pub fn from_deposit(
        full_private_state: &mut FullPrivateState,
        deposit: &Deposit,
        new_salt: Salt,
    ) -> Result<Self, CommonError> {
        let nullifier: Bytes32 = deposit.poseidon_hash().into();
        Self::new(
            full_private_state,
            deposit.token_index,
            deposit.amount,
            nullifier,
            new_salt,
        )
    }

    pub fn to_value(&self) -> Result<PrivateStateTransitionValue, ReceiveTargetsError> {
        PrivateStateTransitionValue::new(
            self.token_index,
            self.amount,
            self.nullifier,
            self.new_salt,
            &self.prev_private_state,
            &self.nullifier_proof,
            &self.prev_asset_leaf,
            &self.asset_merkle_proof,
        )
    }
}
