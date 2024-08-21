use plonky2::util::serialization::{Buffer, IoResult, Read, Write};

use crate::{
    common::tx::{Tx, TxTarget},
    utils::{
        poseidon_hash_out::PoseidonHashOutTarget,
        trees::{
            incremental_merkle_tree::{
                IncrementalMerkleProof, IncrementalMerkleProofTarget, IncrementalMerkleTree,
            },
            merkle_tree::MerkleProofTarget,
        },
    },
};

pub type TxTree = IncrementalMerkleTree<Tx>;
pub type TxMerkleProof = IncrementalMerkleProof<Tx>;
pub type TxMerkleProofTarget = IncrementalMerkleProofTarget<TxTarget>;

impl TxMerkleProofTarget {
    pub fn to_buffer(&self, buffer: &mut Vec<u8>) -> IoResult<()> {
        buffer.write_usize(self.0.siblings.len())?;
        for sibling in self.0.siblings.iter() {
            sibling.to_buffer(buffer)?;
        }

        Ok(())
    }

    pub fn from_buffer(buffer: &mut Buffer) -> IoResult<Self> {
        let siblings_len = buffer.read_usize()?;
        let mut siblings = Vec::with_capacity(siblings_len);
        for _ in 0..siblings_len {
            let sibling = PoseidonHashOutTarget::from_buffer(buffer)?;
            siblings.push(sibling);
        }

        Ok(IncrementalMerkleProofTarget(MerkleProofTarget { siblings }))
    }
}

impl TxTree {
    pub fn get_tx_index(&self, tx: &Tx) -> Option<usize> {
        self.leaves().iter().position(|leaf| leaf == tx)
    }
}
