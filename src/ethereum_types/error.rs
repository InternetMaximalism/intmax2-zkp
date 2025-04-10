use thiserror::Error;

#[derive(Debug, Error)]
pub enum EthereumTypeError {
    #[error("Failed to parse hex string: {0}")]
    HexParseError(String),

    #[error("Failed to parse integer: {0}")]
    IntegerParseError(String),

    #[error("Value too large: {0}")]
    ValueTooLarge(String),

    #[error("Invalid length: expected {expected}, got {actual}")]
    InvalidLength { expected: String, actual: usize },

    #[error("Invalid length: {0}")]
    InvalidLengthSimple(usize),

    #[error("Out of u32 range")]
    OutOfU32Range,

    #[error("Invalid hex")]
    InvalidHex(#[from] hex::FromHexError),

    #[error("Conversion error: {0}")]
    ConversionError(String),

    #[error("Serialization error: {0}")]
    SerializationError(String),

    #[error("Deserialization error: {0}")]
    DeserializationError(#[from] bincode::Error),
}
