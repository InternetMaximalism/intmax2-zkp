#[derive(Debug, thiserror::Error)]
pub enum MerkleProofError {
    #[error("Merkle proof verification failed: {0}")]
    VerificationFailed(String),
}

#[derive(Debug, thiserror::Error)]
pub enum GetRootFromLeavesError {
    #[error("Too many leaves: {0}")]
    TooManyLeaves(usize),

    #[error("Leaves count is not a power of 2: {0}")]
    NotPowerOfTwo(usize),
}

#[derive(Debug, thiserror::Error)]
pub enum IndexedMerkleTreeError {
    #[error("Key already exists: {0}")]
    KeyAlreadyExists(String),

    #[error("Key doesn't exist: {0}")]
    KeyDoesNotExist(String),

    #[error("Key is not lower-bounded: {0}")]
    KeyNotLowerBounded(String),

    #[error("Key is not upper-bounded: {0}")]
    KeyNotUpperBounded(String),

    #[error("Key mismatch: expected {expected}, got {actual}")]
    KeyMismatch { expected: String, actual: String },

    #[error("Value mismatch: expected {expected}, got {actual}")]
    ValueMismatch { expected: u64, actual: u64 },

    #[error("New root mismatch: expected {expected}, got {actual}")]
    NewRootMismatch { expected: String, actual: String },

    #[error("Too many candidates: {0}")]
    TooManyCandidates(String),

    #[error("Merkle proof error: {0}")]
    MerkleProofError(#[from] MerkleProofError),
}
