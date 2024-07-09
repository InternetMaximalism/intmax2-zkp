use rand::Rng;
use serde::Serialize;

use crate::utils::{leafable::Leafable, poseidon_hash_out::PoseidonHashOut};

pub const TX_LEN: usize = 4 + 1;

#[derive(Clone, Default, Debug, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Tx {
    pub transfer_tree_root: PoseidonHashOut,
    pub nonce: u32,
}

impl Tx {
    pub fn to_u64_vec(&self) -> Vec<u64> {
        let vec = self
            .transfer_tree_root
            .to_u64_vec()
            .into_iter()
            .chain(vec![self.nonce as u64].into_iter())
            .collect::<Vec<_>>();
        assert_eq!(vec.len(), TX_LEN);
        vec
    }

    pub fn rand<R: Rng>(rng: &mut R) -> Self {
        Self {
            transfer_tree_root: PoseidonHashOut::rand(rng),
            nonce: rng.gen(),
        }
    }
}

impl Leafable for Tx {
    type HashOut = PoseidonHashOut;

    fn empty_leaf() -> Self {
        Self::default()
    }

    fn hash(&self) -> Self::HashOut {
        PoseidonHashOut::hash_inputs_u64(&self.to_u64_vec())
    }

    fn two_to_one(left: Self::HashOut, right: Self::HashOut) -> Self::HashOut {
        let inputs = left
            .to_u64_vec()
            .into_iter()
            .chain(right.to_u64_vec().into_iter())
            .collect::<Vec<_>>();
        PoseidonHashOut::hash_inputs_u64(&inputs)
    }
}
