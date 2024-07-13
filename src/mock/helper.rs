use crate::common::trees::block_hash_tree::BlockHashMerkleProof;

use super::block_builder::MockBlockBuilder;

// Provides methods required for balance proof etc.
impl MockBlockBuilder {
    pub fn get_block_merkle_proof(
        &self,
        current_block_number: u32,
        target_block_number: u32,
    ) -> BlockHashMerkleProof {
        assert!(current_block_number > target_block_number);
        let block_tree = &self
            .aux_info
            .get(&current_block_number)
            .expect("current block number not found")
            .block_tree;
        block_tree.prove(target_block_number as usize)
    }

    pub fn last_block_number(&self) -> u32 {
        self.block_witnesses.len() as u32 - 1
    }
}
