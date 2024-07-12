use crate::common::{
    signature::key_set::KeySet, trees::asset_tree::AssetTree, witness::tx_witness::TxWitness,
};

#[derive(Debug, Clone)]
pub struct BalanceManager {
    pub key_set: KeySet,
    pub asset_tree: AssetTree,
    pub nonce: u32,
    pub sent_tx: Vec<TxWitness>,
}
