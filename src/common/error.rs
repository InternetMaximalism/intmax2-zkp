#[derive(Debug, thiserror::Error)]
pub enum CommonError {
    #[error("Invalid length: {0}")]
    InvalidLength(usize),

    #[error("Invalid signature")]
    InvalidSignature,

    #[error("Failed to verify tx merkle proof: {0}")]
    TxMerkleProofVerificationFailed(String),

    #[error("Failed to verify signature: {0}")]
    SignatureVerificationFailed(String),

    #[error("Missing data: {0}")]
    MissingData(String),

    #[error("Invalid data: {0}")]
    InvalidData(String),

    #[error("Conversion error: {0}")]
    ConversionError(String),

    #[error("Failed to prove and insert account tree: {0}")]
    AccountTreeProveAndInsertFailed(String),

    #[error("Failed to prove and update account tree: {0}")]
    AccountTreeProveAndUpdateFailed(String),

    #[error("Failed to create transfer inclusion value: {0}")]
    TransferInclusionValueCreationFailed(String),

    #[error("Nullifier already exists: {0}")]
    NullifierAlreadyExists(String),

    #[error("Invalid spent value: {0}")]
    InvalidSpentValue(String),

    #[error("Failed to convert block witness to main validation pis: {0}")]
    BlockWitnessConversionFailed(String),

    #[error("Error while recovering packed account ids: {0}")]
    PackedAccountIdsRecoveryFailed(String),

    #[error("Genesis block is not allowed")]
    GenesisBlockNotAllowed,

    #[error("Invalid block: {0}")]
    InvalidBlock(String),

    #[error("Invalid account: {0}")]
    InvalidAccount(String),

    #[error("Invalid transaction: {0}")]
    InvalidTransaction(String),

    #[error("Invalid witness: {0}")]
    InvalidWitness(String),

    #[error("Invalid proof: {0}")]
    InvalidProof(String),
}

impl From<std::io::Error> for CommonError {
    fn from(err: std::io::Error) -> Self {
        CommonError::InvalidData(err.to_string())
    }
}

impl From<crate::circuits::validity::block_validation::error::BlockValidationError> for CommonError {
    fn from(err: crate::circuits::validity::block_validation::error::BlockValidationError) -> Self {
        CommonError::InvalidData(err.to_string())
    }
}
