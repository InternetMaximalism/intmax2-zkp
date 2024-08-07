use crate::common::{signature::key_set::KeySet, tx::Tx};

#[derive(Clone, Debug)]
pub struct MockTxRequest {
    pub tx: Tx,
    pub sender: KeySet,
    pub will_return_signature: bool,
}

impl MockTxRequest {
    pub fn dummy() -> Self {
        Self {
            tx: Tx::default(),
            sender: KeySet::dummy(),
            will_return_signature: false,
        }
    }
}