pub const TX_TREE_HEIGHT: usize = 7;
pub const TRANSFER_TREE_HEIGHT: usize = 6;
pub const BLOCK_HASH_TREE_HEIGHT: usize = 32;
pub const DEPOSIT_TREE_HEIGHT: usize = 32;
pub const ASSET_TREE_HEIGHT: usize = 32;
pub const ACCOUNT_ID_BITS: usize = 40;
pub const NULLIFIER_TREE_HEIGHT: usize = 32;
pub const SENDER_TREE_HEIGHT: usize = TX_TREE_HEIGHT;
pub const NUM_SENDERS_IN_BLOCK: usize = 1 << TX_TREE_HEIGHT;
pub const NUM_TRANSFERS_IN_TX: usize = 1 << TRANSFER_TREE_HEIGHT;
pub const ACCOUNT_TREE_HEIGHT: usize = ACCOUNT_ID_BITS;

pub const VALIDITY_CIRCUIT_PADDING_DEGREE: usize = 13;
pub const BALANCE_CIRCUIT_PADDING_DEGREE: usize = 13;
pub const WITHDRAWAL_CIRCUIT_PADDING_DEGREE: usize = 13;
