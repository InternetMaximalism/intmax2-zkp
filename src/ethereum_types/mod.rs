pub mod account_id;
pub mod address;
pub mod bytes16;
pub mod bytes32;
pub mod error;
pub mod u256;
pub mod u32limb_trait;
pub mod u64;

// Result 型エイリアスを再エクスポート
pub use error::EthereumTypeError;
pub type Result<T> = std::result::Result<T, EthereumTypeError>;
