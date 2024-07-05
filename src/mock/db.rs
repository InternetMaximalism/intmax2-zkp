use crate::{
    common::{
        block::Block,
        trees::{account_tree::AccountTree, block_hash_tree::BlockHashTree, tx_tree::TxTree},
        witness::block_witness::BlockWitness,
    },
    constants::{ACCOUNT_TREE_HEIGHT, BLOCK_HASH_TREE_HEIGHT, TX_TREE_HEIGHT},
    ethereum_types::bytes32::Bytes32,
};

#[derive(Clone, Debug)]
pub struct BlockInfo {
    pub block_witness: BlockWitness,
    pub tx_tree: TxTree,
}

pub struct MockDB {
    pub account_tree: AccountTree,
    pub block_hash_tree: BlockHashTree,
    pub prev_account_tree: Option<AccountTree>,
    pub prev_block_hash_tree: Option<BlockHashTree>,
    pub block_info: Vec<BlockInfo>,
    pub current_deposit_root: Bytes32<u32>,
}

impl MockDB {
    pub fn new() -> Self {
        let account_tree = AccountTree::new(ACCOUNT_TREE_HEIGHT);
        let block_hash_tree = BlockHashTree::new(BLOCK_HASH_TREE_HEIGHT);
        let block_info = vec![BlockInfo {
            block_witness: BlockWitness::default(),
            tx_tree: TxTree::new(TX_TREE_HEIGHT),
        }];
        Self {
            account_tree,
            block_hash_tree,
            prev_account_tree: None,
            prev_block_hash_tree: None,
            block_info,
            current_deposit_root: Bytes32::default(),
        }
    }

    pub fn save_prev_state(&mut self) {
        self.prev_account_tree = Some(self.account_tree.clone());
        self.prev_block_hash_tree = Some(self.block_hash_tree.clone());
    }

    pub fn get_last_block(&self) -> Block {
        let last_block_witness = self.block_info.last().unwrap();
        last_block_witness.block_witness.block.clone()
    }

    pub fn push_block_info(&mut self, block_info: BlockInfo) {
        self.block_info.push(block_info);
    }

    pub fn get_last_block_witness(&self) -> BlockWitness {
        self.block_info.last().unwrap().block_witness.clone()
    }
}
