#[derive(Debug, thiserror::Error)]
pub enum MerkleProofError {
    #[error("Merkle proof verification failed: {0}")]
    VerificationFailed(String),
}

#[derive(Debug, thiserror::Error)]
pub enum GetRootFromLeavesError {
    #[error("Too many leaves: {0}")]
    TooManyLeaves(usize),
}
