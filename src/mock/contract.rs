use super::full_block::FullBlock;
use crate::{
    common::{
        block::Block,
        signature::{
            flatten::{FlatG1, FlatG2},
            utils::get_pubkey_hash,
            SignatureContent,
        },
        trees::deposit_tree::DepositTree,
    },
    constants::NUM_SENDERS_IN_BLOCK,
    ethereum_types::{bytes16::Bytes16, bytes32::Bytes32, u256::U256},
};

pub struct MockContract {
    pub full_blocks: Vec<FullBlock>,
    pub deposit_tree: DepositTree,
}

impl MockContract {
    // returns the next block number
    pub fn get_block_number(&self) -> u32 {
        self.full_blocks.len() as u32
    }

    pub fn get_prev_block_hash(&self) -> Bytes32 {
        self.full_blocks
            .last()
            .map(|full_block| full_block.block.hash())
            .unwrap_or_default()
    }

    /// Posts registration block. Same interface as the contract.
    pub fn post_registration_block(
        &mut self,
        tx_tree_root: Bytes32,
        sender_flag: Bytes16,
        agg_pubkey: FlatG1,
        agg_signature: FlatG2,
        message_point: FlatG2,
        sender_public_keys: Vec<U256>, // dummy pubkeys are trimmed
    ) -> anyhow::Result<()> {
        let mut padded_pubkeys = sender_public_keys.clone();
        padded_pubkeys.resize(NUM_SENDERS_IN_BLOCK, U256::dummy_pubkey());
        let pubkey_hash = get_pubkey_hash(&padded_pubkeys);
        let signature = SignatureContent {
            is_registration_block: true,
            tx_tree_root,
            sender_flag,
            pubkey_hash,
            account_id_hash: Bytes32::default(),
            agg_pubkey,
            agg_signature,
            message_point,
        };

        let block = Block {
            prev_block_hash: self.get_prev_block_hash(),
            deposit_tree_root: self.deposit_tree.get_root(),
            signature_hash: signature.hash(),
            block_number: self.get_block_number(),
        };
        let full_block = FullBlock {
            block,
            signature,
            pubkeys: Some(sender_public_keys), // trimmed public keys
            account_ids: None,
        };
        self.full_blocks.push(full_block);
        
        Ok(())
    }
}
