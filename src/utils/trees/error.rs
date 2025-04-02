#[derive(Debug, thiserror::Error)]
pub enum MerkleProofError {
    #[error("Merkle proof verification failed: {0}")]
    VerificationFailed(String),
}
