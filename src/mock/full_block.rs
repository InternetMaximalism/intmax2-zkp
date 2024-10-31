use anyhow::ensure;
use serde::{Deserialize, Serialize};

use crate::{
    common::{
        block::Block,
        signature::SignatureContent,
        trees::{account_tree::AccountTree, block_hash_tree::BlockHashTree},
        witness::block_witness::BlockWitness,
    },
    constants::NUM_SENDERS_IN_BLOCK,
    ethereum_types::{account_id_packed::AccountIdPacked, u256::U256},
};
// A subset of `BlockWitness` that only contains the information to be submitted to the contract
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct FullBlock {
    pub block: Block,
    pub signature: SignatureContent,
    pub pubkeys: Option<Vec<U256>>,   // pubkeys trimmed dummy pubkeys
    pub account_ids: Option<Vec<u8>>, // account ids trimmed dummy pubkeys
}

impl FullBlock {
    /// Generates block witness. Account/Block trees are the latest trees before relfecting the
    /// block.
    pub fn to_block_witness(
        &self,
        account_tree: &AccountTree,
        block_tree: &BlockHashTree,
    ) -> anyhow::Result<BlockWitness> {
        let is_registration_block = self.signature.is_registration_block;
        let (pubkeys, account_id_packed, account_merkle_proofs, account_membership_proofs) =
            if is_registration_block {
                let mut pubkeys = self.pubkeys.clone().ok_or(anyhow::anyhow!(
                    "pubkeys is not given while it is registration block"
                ))?;
                pubkeys.resize(NUM_SENDERS_IN_BLOCK, U256::dummy_pubkey());
                let mut account_membership_proofs = Vec::new();
                for pubkey in pubkeys.iter() {
                    let is_dummy = pubkey.is_dummy_pubkey();
                    ensure!(
                        account_tree.index(*pubkey).is_none() || is_dummy,
                        "account already exists"
                    );
                    let proof = account_tree.prove_membership(*pubkey);
                    account_membership_proofs.push(proof);
                }
                (pubkeys, None, None, Some(account_membership_proofs))
            } else {
                let account_id_trimmed_bytes = self.account_ids.clone().ok_or(anyhow::anyhow!(
                    "account_ids is not given while it is non-registration block"
                ))?;
                let account_id_packed = AccountIdPacked::from_trimmed_bytes(
                    &account_id_trimmed_bytes,
                )
                .map_err(|e| anyhow::anyhow!("error while recovering packed account ids {}", e))?;
                let account_ids = account_id_packed.unpack();
                let mut account_merkle_proofs = Vec::new();
                let mut pubkeys = Vec::new();
                for account_id in account_ids {
                    let pubkey = account_tree.key(account_id);
                    let proof = account_tree.prove_inclusion(account_id);
                    pubkeys.push(pubkey);
                    account_merkle_proofs.push(proof);
                }
                (
                    pubkeys,
                    Some(account_id_packed),
                    Some(account_merkle_proofs),
                    None,
                )
            };
        let prev_account_tree_root = account_tree.get_root();
        let prev_block_tree_root = block_tree.get_root();
        let block_witness = BlockWitness {
            block: self.block.clone(),
            signature: self.signature.clone(),
            pubkeys: pubkeys.clone(),
            prev_account_tree_root,
            prev_block_tree_root,
            account_id_packed,
            account_merkle_proofs,
            account_membership_proofs,
        };
        Ok(block_witness)
    }
}
