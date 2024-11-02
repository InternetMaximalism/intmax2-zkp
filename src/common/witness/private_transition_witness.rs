use serde::{Deserialize, Serialize};

use crate::{
    common::{
        private_state::{FullPrivateState, PrivateState},
        salt::Salt,
        trees::{
            asset_tree::{AssetLeaf, AssetMerkleProof},
            nullifier_tree::NullifierInsersionProof,
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
    pub nullifier_proof: NullifierInsersionProof,
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
    ) -> anyhow::Result<Self> {
        let prev_private_state = full_private_state.to_private_state();
        let prev_asset_leaf = full_private_state.asset_tree.get_leaf(token_index as usize);
        let asset_merkle_proof = full_private_state.asset_tree.prove(token_index as usize);
        let new_asset_leaf = prev_asset_leaf.add(amount); // receiving token
        full_private_state
            .asset_tree
            .update(token_index as usize, new_asset_leaf);
        let nullifier_proof = full_private_state
            .nullifier_tree
            .prove_and_insert(nullifier)
            .map_err(|e| anyhow::anyhow!("nullifier already exists: {}", e))?;
        full_private_state.salt = new_salt;
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
}
