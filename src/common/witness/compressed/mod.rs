use crate::utils::{leafable::Leafable, trees::incremental_merkle_tree::IncrementalMerkleProof};

pub mod compressed_block_witness;
pub mod compressed_transition_witness;
pub mod compressed_validity_witness;

pub(crate) fn effective_bits(n: usize) -> u32 {
    if n == 0 {
        0
    } else {
        64 - n.leading_zeros()
    }
}

pub(crate) fn is_dummy_incremental_merkle_proof<V: Leafable>(
    proof: &IncrementalMerkleProof<V>,
    height: usize,
) -> bool {
    let dummy_proof = IncrementalMerkleProof::<V>::dummy(height);
    for i in 0..height {
        if proof.0.siblings[i] != dummy_proof.0.siblings[i] {
            return false;
        }
    }

    true
}
