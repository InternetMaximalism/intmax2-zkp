use anyhow::ensure;
use ark_bn254::{Bn254, G1Affine, G2Affine};
use ark_ec::{pairing::Pairing as _, AffineRepr};
use hashbrown::HashMap;

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
        witness::full_block::FullBlock,
    },
    constants::{DEPOSIT_TREE_HEIGHT, NUM_SENDERS_IN_BLOCK},
    ethereum_types::{
        account_id_packed::AccountIdPacked, bytes16::Bytes16, bytes32::Bytes32, u256::U256,
        u64::U64,
    },
    utils::leafable::Leafable,
};

pub struct MockContract {
    pub full_blocks: Vec<FullBlock>,
    pub deposit_tree: DepositTree,
    pub deposit_trees: HashMap<u32, DepositTree>, // snap shot of deposit tree at each block
    pub deposit_correspondence: HashMap<Bytes32, (u32, u32)>, /* deposit_hash -> (deposit_index,
                                                   * block_number) */
}

impl MockContract {
    pub fn new() -> Self {
        let full_blocks = vec![FullBlock::genesis()];
        let deposit_tree = DepositTree::new(DEPOSIT_TREE_HEIGHT);
        let mut deposit_trees = HashMap::new();
        deposit_trees.insert(0, deposit_tree.clone());
        let deposit_correspondence = HashMap::new();
        Self {
            full_blocks,
            deposit_tree,
            deposit_trees,
            deposit_correspondence,
        }
    }

    pub fn reset(&mut self) {
        *self = Self::new();
    }

    pub fn get_next_block_number(&self) -> u32 {
        self.full_blocks.len() as u32
    }

    pub fn get_last_block_number(&self) -> u32 {
        self.get_next_block_number() - 1
    }

    pub fn get_full_block(&self, block_number: u32) -> anyhow::Result<FullBlock> {
        ensure!(
            block_number < self.get_next_block_number(),
            "block number {} is out of range",
            block_number
        );
        Ok(self.full_blocks[block_number as usize].clone())
    }

    pub fn get_prev_block_hash(&self) -> Bytes32 {
        self.full_blocks
            .last()
            .map(|full_block| full_block.block.hash())
            .unwrap_or_default()
    }

    /// Simpler interface for depositing tokens. Returns the id of deposit
    pub fn deposit(&mut self, pubkey_salt_hash: Bytes32, token_index: u32, amount: U256) {
        let deposit_index = self.deposit_tree.len() as u32;
        let deposit = Deposit {
            pubkey_salt_hash,
            token_index,
            amount,
        };
        self.deposit_tree.push(deposit.clone());
        let block_number = self.get_next_block_number();
        self.deposit_correspondence
            .insert(deposit.hash(), (deposit_index, block_number));
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
        if sender_flag != Bytes16::default() {
            ensure!(
                pairing_check(
                    agg_pubkey.clone(),
                    agg_signature.clone(),
                    message_point.clone()
                ),
                "invalid signature"
            );
        }
        log::info!("post registration block");
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
            timestamp: timestamp(),
            block_number: self.get_next_block_number(),
        };
        let full_block = FullBlock {
            block: block.clone(),
            signature,
            pubkeys: Some(sender_public_keys), // trimmed public keys
            account_ids: None,
        };
        self.deposit_trees
            .insert(block.block_number, self.deposit_tree.clone());
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
        if sender_flag != Bytes16::default() {
            ensure!(
                pairing_check(
                    agg_pubkey.clone(),
                    agg_signature.clone(),
                    message_point.clone()
                ),
                "invalid signature"
            );
        }

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
            timestamp: timestamp(),
            block_number: self.get_next_block_number(),
        };
        let full_block = FullBlock {
            block: block.clone(),
            signature,
            pubkeys: None,
            account_ids: Some(account_ids),
        };
        self.deposit_trees
            .insert(block.block_number, self.deposit_tree.clone());
        self.full_blocks.push(full_block);
        Ok(())
    }
}

fn pairing_check(agg_pubkey: FlatG1, agg_signature: FlatG2, message_point: FlatG2) -> bool {
    log::info!("pairing check");
    let agg_pubkey: G1Affine = agg_pubkey.into();
    let agg_signature: G2Affine = agg_signature.into();
    let message_point: G2Affine = message_point.into();
    Bn254::pairing(agg_pubkey, message_point)
        == Bn254::pairing(G1Affine::generator(), agg_signature)
}

fn timestamp() -> U64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs()
        .into()
}
