use anyhow::ensure;
use serde::{Deserialize, Serialize};

use crate::{
    circuits::balance::send::spent_circuit::SpentValue,
    common::{
        private_state::PrivateState,
        salt::Salt,
        transfer::Transfer,
        trees::asset_tree::{AssetLeaf, AssetMerkleProof, AssetTree},
        tx::Tx,
    },
    constants::{NUM_TRANSFERS_IN_TX, TRANSFER_TREE_HEIGHT},
    utils::trees::get_root::get_merkle_root_from_leaves,
};

/// Information needed to generate spent value
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SpentWitness {
    pub prev_private_state: PrivateState,
    pub prev_balances: Vec<AssetLeaf>,
    pub asset_merkle_proofs: Vec<AssetMerkleProof>,
    pub transfers: Vec<Transfer>,
    pub tx: Tx,
    pub new_private_state_salt: Salt,
}

impl SpentWitness {
    // instantiate a new spent witness, while checking the validity of the inputs
    pub fn new(
        asset_tree: &AssetTree,
        prev_private_state: &PrivateState,
        transfers: &[Transfer],
        tx: Tx,
        new_private_state_salt: Salt,
    ) -> anyhow::Result<Self> {
        ensure!(
            transfers.len() == NUM_TRANSFERS_IN_TX,
            "invalid number of transfers"
        );
        let transfer_tree_root = get_merkle_root_from_leaves(TRANSFER_TREE_HEIGHT, transfers);
        ensure!(
            transfer_tree_root == tx.transfer_tree_root,
            "transfer tree root mismatch"
        );
        let mut temp_asset_tree = asset_tree.clone();
        let mut asset_merkle_proofs = vec![];
        let mut prev_balances = vec![];
        for transfer in transfers {
            let prev_balance = temp_asset_tree.get_leaf(transfer.token_index as usize);
            let proof = temp_asset_tree.prove(transfer.token_index as usize);
            let new_balance = prev_balance.sub(transfer.amount);
            temp_asset_tree.update(transfer.token_index as usize, new_balance);
            prev_balances.push(prev_balance);
            asset_merkle_proofs.push(proof);
        }
        Ok(Self {
            prev_private_state: prev_private_state.clone(),
            prev_balances,
            asset_merkle_proofs,
            transfers: transfers.to_vec(),
            tx,
            new_private_state_salt,
        })
    }

    pub fn value(&self) -> SpentValue {
        SpentValue::new(
            &self.prev_private_state,
            &self.prev_balances,
            self.new_private_state_salt,
            &self.transfers,
            &self.asset_merkle_proofs,
            self.tx.nonce,
        )
    }
}
