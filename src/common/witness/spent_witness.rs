use anyhow::ensure;
use serde::{Deserialize, Serialize};

use crate::{
    circuits::balance::send::spent_circuit::SpentValue,
    common::{
        private_state::{FullPrivateState, PrivateState},
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
        let mut asset_merkle_proofs = vec![];
        let mut prev_balances = vec![];
        let mut asset_tree = asset_tree.clone();
        for transfer in transfers {
            let prev_balance = asset_tree.get_leaf(transfer.token_index as u64);
            let proof = asset_tree.prove(transfer.token_index as u64);
            let new_balance = prev_balance.sub(transfer.amount);
            asset_tree.update(transfer.token_index as u64, new_balance);
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

    pub fn to_value(&self) -> anyhow::Result<SpentValue> {
        SpentValue::new(
            &self.prev_private_state,
            &self.prev_balances,
            self.new_private_state_salt,
            &self.transfers,
            &self.asset_merkle_proofs,
            self.tx.nonce,
        )
    }

    /// Update the private state of the full private state
    pub fn update_private_state(
        &self,
        full_private_state: &mut FullPrivateState,
    ) -> anyhow::Result<()> {
        ensure!(
            full_private_state.to_private_state() == self.prev_private_state,
            "prev private state mismatch"
        );
        let prev_private_commitment = full_private_state.to_private_state().commitment();

        let value = self
            .to_value()
            .map_err(|e| anyhow::anyhow!("Invalid spent value: {}", e))?;
        if !value.is_valid {
            // if the nonce is invalid, do nothing
            return Ok(());
        }

        // update the asset tree
        for transfer in &self.transfers {
            let prev_balance = full_private_state
                .asset_tree
                .get_leaf(transfer.token_index as u64);
            let new_balance = prev_balance.sub(transfer.amount);
            full_private_state
                .asset_tree
                .update(transfer.token_index as u64, new_balance);
        }

        full_private_state.nonce += 1;
        full_private_state.salt = self.new_private_state_salt;
        full_private_state.prev_private_commitment = prev_private_commitment;

        ensure!(
            full_private_state.to_private_state().commitment() == value.new_private_commitment,
            "new private state mismatch"
        );
        Ok(())
    }
}
