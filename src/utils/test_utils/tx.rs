use rand::Rng;

use crate::{
    common::{signature::key_set::KeySet, tx::Tx},
    constants::NUM_SENDERS_IN_BLOCK,
    mock::tx_request::MockTxRequest,
};

pub(crate) fn generate_random_tx_requests<R: Rng>(rng: &mut R) -> Vec<MockTxRequest> {
    (0..NUM_SENDERS_IN_BLOCK)
        .map(|_| {
            let sender = KeySet::rand(rng);
            let tx = Tx::rand(rng);
            MockTxRequest {
                tx,
                sender,
                will_return_signature: rng.gen(),
            }
        })
        .collect::<Vec<_>>()
}
