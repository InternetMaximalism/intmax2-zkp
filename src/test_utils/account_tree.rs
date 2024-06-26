use rand::Rng;

use crate::common::{signature::key_set::KeySet, trees::account_tree::AccountTree};

pub fn add_random_accounts<R: Rng>(rng: &mut R, tree: &mut AccountTree, n: usize) {
    for _ in 0..n {
        let keyset = KeySet::rand(rng);
        let last_block_number = rng.gen();
        tree.insert(keyset.pubkey_x, last_block_number).unwrap();
    }
}
