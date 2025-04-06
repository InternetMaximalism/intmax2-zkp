use thiserror::Error;

#[derive(Debug, Error)]
pub enum SerializeError {
    #[error("Failed to serialize circuit: {0}")]
    SerializationFailed(String),

    #[error("Failed to deserialize circuit: {0}")]
    DeserializationFailed(String),

    #[error("Plonky2 serialization error: {0}")]
    PlonkyError(String),
}
