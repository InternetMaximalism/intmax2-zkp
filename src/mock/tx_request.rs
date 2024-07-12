use crate::common::{signature::key_set::KeySet, tx::Tx};

#[derive(Clone, Debug)]
pub struct TxRequest {
    pub tx: Tx,
    pub sender: KeySet,
    pub will_return_signature: bool,
}

impl TxRequest {
    pub fn dummy() -> Self {
        Self {
            tx: Tx::default(),
            sender: KeySet::dummy(),
            will_return_signature: false,
        }
    }
}
