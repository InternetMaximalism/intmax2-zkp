#[derive(Debug, thiserror::Error)]
pub enum AccountError {
    #[error("AccountInclusionValue error: {0}")]
    AccountInclusionValue(String),
    
    #[error("AccountExclusionValue error: {0}")]
    AccountExclusionValue(String),
}
