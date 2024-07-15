use crate::{
    common::trees::{
        account_tree::AccountMembershipProof, block_hash_tree::BlockHashMerkleProof,
        deposit_tree::DepositLeaf,
    },
    ethereum_types::u256::U256,
};

use super::block_builder::MockBlockBuilder;

// Provides methods required for balance proof etc.
impl MockBlockBuilder {
    pub fn get_block_merkle_proof(
        &self,
        current_block_number: u32,
        target_block_number: u32,
    ) -> BlockHashMerkleProof {
        assert!(current_block_number >= target_block_number);
        let block_tree = &self
            .aux_info
            .get(&current_block_number)
            .expect("current block number not found")
            .block_tree;
        block_tree.prove(target_block_number as usize)
    }

    pub fn get_account_membership_proof(
        &self,
        current_block_number: u32,
        pubkey: U256<u32>,
    ) -> AccountMembershipProof {
        let account_tree = &self
            .aux_info
            .get(&current_block_number)
            .expect("current block number not found")
            .account_tree;
        account_tree.prove_membership(pubkey)
    }

    pub fn last_block_number(&self) -> u32 {
        self.last_block_number
    }

    pub fn deposit(&mut self, deposit: &DepositLeaf) -> usize {
        self.deposit_tree.push(deposit.clone());
        let deposit_index = self.deposit_tree.len() - 1;
        deposit_index
    }
}
