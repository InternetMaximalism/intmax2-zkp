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

#[cfg(test)]
mod tests {
    use crate::common::trees::account_tree::AccountTree;

    use super::MockTxRequest;

    #[test]
    fn dummy_key_account_id() {
        let account_tree = AccountTree::initialize();
        let dummy_pubkey = MockTxRequest::dummy().sender.pubkey_x;
        let account_id = account_tree.index(dummy_pubkey);
        assert_eq!(account_id, Some(1)); // account_id of dummy key is 1
    }
}
