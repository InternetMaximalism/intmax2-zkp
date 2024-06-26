use crate::{common::tx::Tx, ethereum_types::bytes32::Bytes32};

pub struct TxWitness {
    pub tx: Tx,
    pub block_hash: Bytes32<u32>, // hash of block that contains the tx
    pub block_number: u32,
}
