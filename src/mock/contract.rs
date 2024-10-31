use anyhow::ensure;
use ark_bn254::{Bn254, G1Affine, G2Affine};
use ark_ec::{pairing::Pairing as _, AffineRepr};

use super::full_block::FullBlock;
use crate::{
    common::{
        block::Block,
        deposit::Deposit,
        signature::{
            flatten::{FlatG1, FlatG2},
            utils::get_pubkey_hash,
            SignatureContent,
        },
        trees::deposit_tree::DepositTree,
    },
    constants::NUM_SENDERS_IN_BLOCK,
    ethereum_types::{
        account_id_packed::AccountIdPacked, bytes16::Bytes16, bytes32::Bytes32, u256::U256,
    },
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

    /// Simpler interface for depositing tokens. Returns the index of the deposit in the deposit
    /// tree.
    pub fn deposit(&mut self, pubkey_salt_hash: Bytes32, token_index: u32, amount: U256) -> usize {
        self.deposit_tree.push(Deposit {
            pubkey_salt_hash,
            token_index,
            amount,
        });
        let deposit_index = self.deposit_tree.len() - 1;
        deposit_index
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
        ensure!(
            pairing_check(
                agg_pubkey.clone(),
                agg_signature.clone(),
                message_point.clone()
            ),
            "invalid signature"
        );
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

    /// Posts registration block. Same interface as the contract.
    pub fn post_non_registration_block(
        &mut self,
        tx_tree_root: Bytes32,
        sender_flag: Bytes16,
        agg_pubkey: FlatG1,
        agg_signature: FlatG2,
        message_point: FlatG2,
        public_keys_hash: Bytes32,
        account_ids: Vec<u8>, // dummy accounts are trimmed
    ) -> anyhow::Result<()> {
        ensure!(
            pairing_check(
                agg_pubkey.clone(),
                agg_signature.clone(),
                message_point.clone()
            ),
            "invalid signature"
        );
        let account_ids_packed = AccountIdPacked::from_trimmed_bytes(&account_ids)
            .map_err(|e| anyhow::anyhow!("error while recovering packed account ids {}", e))?;
        let signature = SignatureContent {
            is_registration_block: false,
            tx_tree_root,
            sender_flag,
            pubkey_hash: public_keys_hash,
            account_id_hash: account_ids_packed.hash(),
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
            pubkeys: None,
            account_ids: Some(account_ids),
        };
        self.full_blocks.push(full_block);
        Ok(())
    }
}

fn pairing_check(agg_pubkey: FlatG1, agg_signature: FlatG2, message_point: FlatG2) -> bool {
    let agg_pubkey: G1Affine = agg_pubkey.into();
    let agg_signature: G2Affine = agg_signature.into();
    let message_point: G2Affine = message_point.into();
    Bn254::pairing(agg_pubkey, message_point)
        == Bn254::pairing(G1Affine::generator(), agg_signature)
}
