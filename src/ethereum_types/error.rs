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

#[cfg(test)]
mod tests {
    use super::*;
    use std::error::Error;

    #[test]
    fn test_ethereum_type_error_hex_parse() {
        let error = EthereumTypeError::HexParseError("Invalid hex character".to_string());
        assert_eq!(
            error.to_string(),
            "Failed to parse hex string: Invalid hex character"
        );
    }

    #[test]
    fn test_ethereum_type_error_integer_parse() {
        let error = EthereumTypeError::IntegerParseError("Not a number".to_string());
        assert_eq!(
            error.to_string(),
            "Failed to parse integer: Not a number"
        );
    }

    #[test]
    fn test_ethereum_type_error_value_too_large() {
        let error = EthereumTypeError::ValueTooLarge("Value exceeds maximum".to_string());
        assert_eq!(
            error.to_string(),
            "Value too large: Value exceeds maximum"
        );
    }

    #[test]
    fn test_ethereum_type_error_invalid_length() {
        let error = EthereumTypeError::InvalidLength {
            expected: "32".to_string(),
            actual: 16,
        };
        assert_eq!(
            error.to_string(),
            "Invalid length: expected 32, got 16"
        );
    }

    #[test]
    fn test_ethereum_type_error_invalid_length_simple() {
        let error = EthereumTypeError::InvalidLengthSimple(16);
        assert_eq!(
            error.to_string(),
            "Invalid length: 16"
        );
    }

    #[test]
    fn test_ethereum_type_error_out_of_u32_range() {
        let error = EthereumTypeError::OutOfU32Range;
        assert_eq!(
            error.to_string(),
            "Out of u32 range"
        );
    }

    #[test]
    fn test_ethereum_type_error_invalid_hex() {
        let hex_error = hex::FromHexError::OddLength;
        let error = EthereumTypeError::InvalidHex(hex_error);
        assert_eq!(
            error.to_string(),
            "Invalid hex"
        );
    }

    #[test]
    fn test_ethereum_type_error_conversion() {
        let error = EthereumTypeError::ConversionError("Failed to convert".to_string());
        assert_eq!(
            error.to_string(),
            "Conversion error: Failed to convert"
        );
    }

    #[test]
    fn test_ethereum_type_error_serialization() {
        let error = EthereumTypeError::SerializationError("Failed to serialize".to_string());
        assert_eq!(
            error.to_string(),
            "Serialization error: Failed to serialize"
        );
    }

    #[test]
    fn test_ethereum_type_error_deserialization() {
        let bincode_error = bincode::Error::new(bincode::ErrorKind::SizeLimit);
        let error = EthereumTypeError::DeserializationError(bincode_error);
        assert_eq!(
            error.to_string(),
            "Deserialization error: the size limit has been reached"
        );
    }

    #[test]
    fn test_ethereum_type_error_is_error() {
        let error = EthereumTypeError::OutOfU32Range;
        let error_ref: &dyn Error = &error;
        assert!(error_ref.source().is_none());
    }

    #[test]
    fn test_ethereum_type_error_from_hex_error() {
        let hex_error = hex::FromHexError::OddLength;
        let error: EthereumTypeError = hex_error.into();
        if let EthereumTypeError::InvalidHex(_) = error {
            // Expected variant
        } else {
            panic!("Expected InvalidHex variant");
        }
    }

    #[test]
    fn test_ethereum_type_error_from_bincode_error() {
        let bincode_error = bincode::Error::new(bincode::ErrorKind::SizeLimit);
        let error: EthereumTypeError = bincode_error.into();
        if let EthereumTypeError::DeserializationError(_) = error {
            // Expected variant
        } else {
            panic!("Expected DeserializationError variant");
        }
    }
}
