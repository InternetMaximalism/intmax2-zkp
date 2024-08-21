use plonky2::util::serialization::{Buffer, IoResult, Read, Write};

use crate::{
    ethereum_types::bytes32::{Bytes32, Bytes32Target},
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

pub type BlockHashTree = IncrementalMerkleTree<Bytes32>;
pub type BlockHashMerkleProof = IncrementalMerkleProof<Bytes32>;
pub type BlockHashMerkleProofTarget = IncrementalMerkleProofTarget<Bytes32Target>;

impl BlockHashMerkleProofTarget {
    pub fn to_buffer(&self, buffer: &mut Vec<u8>) -> IoResult<()> {
        buffer.write_usize(self.0.siblings.len())?;
        for sibling in &self.0.siblings {
            sibling.to_buffer(buffer)?;
        }

        Ok(())
    }

    pub fn from_buffer(buffer: &mut Buffer) -> IoResult<Self> {
        let siblings_len = buffer.read_usize()?;
        let mut siblings = vec![];
        for _ in 0..siblings_len {
            siblings.push(PoseidonHashOutTarget::from_buffer(buffer)?);
        }

        Ok(IncrementalMerkleProofTarget(MerkleProofTarget { siblings }))
    }
}
