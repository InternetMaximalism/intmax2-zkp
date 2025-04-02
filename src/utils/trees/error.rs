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

#[derive(Debug, thiserror::Error)]
pub enum IndexedMerkleTreeError {
    #[error("Key already exists")]
    KeyAlreadyExists,
    
    #[error("Key doesn't exist")]
    KeyDoesNotExist,
    
    #[error("Key is not lower-bounded")]
    KeyNotLowerBounded,
    
    #[error("Key is not upper-bounded")]
    KeyNotUpperBounded,
    
    #[error("Key mismatch")]
    KeyMismatch,
    
    #[error("Value mismatch")]
    ValueMismatch,
    
    #[error("New root mismatch")]
    NewRootMismatch,
    
    #[error("Too many candidates: {0}")]
    TooManyCandidates(String),
    
    #[error("Merkle proof error: {0}")]
    MerkleProofError(#[from] MerkleProofError),
}
