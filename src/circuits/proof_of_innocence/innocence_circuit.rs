use plonky2::iop::target::{BoolTarget, Target};

use crate::utils::poseidon_hash_out::{
    PoseidonHashOut, PoseidonHashOutTarget, POSEIDON_HASH_OUT_LEN,
};

pub const INNOCENCE_PUBLIC_INPUTS_LEN: usize = 1 + 3 * POSEIDON_HASH_OUT_LEN;

#[derive(Clone, Debug)]
pub struct InnocencePublicInputs {
    pub use_allow_list: bool,
    pub allow_list_tree_root: PoseidonHashOut,
    pub deny_list_tree_root: PoseidonHashOut,
    pub nullifier_tree_root: PoseidonHashOut,
}

impl InnocencePublicInputs {
    pub fn to_u64_vec(&self) -> Vec<u64> {
        let vec = vec![self.use_allow_list as u64]
            .into_iter()
            .chain(self.allow_list_tree_root.to_u64_vec().into_iter())
            .chain(self.deny_list_tree_root.to_u64_vec().into_iter())
            .chain(self.nullifier_tree_root.to_u64_vec().into_iter())
            .collect::<Vec<_>>();
        assert_eq!(vec.len(), INNOCENCE_PUBLIC_INPUTS_LEN);
        vec
    }

    pub fn from_u64_slice(slice: &[u64]) -> Self {
        assert_eq!(slice.len(), INNOCENCE_PUBLIC_INPUTS_LEN);
        let use_allow_list = slice[0] != 0;
        let allow_list_tree_root =
            PoseidonHashOut::from_u64_slice(&slice[1..1 + POSEIDON_HASH_OUT_LEN]);
        let deny_list_tree_root = PoseidonHashOut::from_u64_slice(
            &slice[1 + POSEIDON_HASH_OUT_LEN..1 + 2 * POSEIDON_HASH_OUT_LEN],
        );
        let nullifier_tree_root = PoseidonHashOut::from_u64_slice(
            &slice[1 + 2 * POSEIDON_HASH_OUT_LEN..1 + 3 * POSEIDON_HASH_OUT_LEN],
        );
        Self {
            use_allow_list,
            allow_list_tree_root,
            deny_list_tree_root,
            nullifier_tree_root,
        }
    }
}

#[derive(Clone, Debug)]
pub struct InnocencePublicInputsTarget {
    pub use_allow_list: BoolTarget,
    pub allow_list_tree_root: PoseidonHashOutTarget,
    pub deny_list_tree_root: PoseidonHashOutTarget,
    pub nullifier_tree_root: PoseidonHashOutTarget,
}

impl InnocencePublicInputsTarget {
    pub fn to_vec(&self) -> Vec<Target> {
        let vec = vec![self.use_allow_list.target]
            .into_iter()
            .chain(self.allow_list_tree_root.to_vec().into_iter())
            .chain(self.deny_list_tree_root.to_vec().into_iter())
            .chain(self.nullifier_tree_root.to_vec().into_iter())
            .collect::<Vec<_>>();
        assert_eq!(vec.len(), INNOCENCE_PUBLIC_INPUTS_LEN);
        vec
    }

    pub fn from_slice(slice: &[Target]) -> Self {
        assert_eq!(slice.len(), INNOCENCE_PUBLIC_INPUTS_LEN);
        let use_allow_list = BoolTarget::new_unsafe(slice[0]);
        let allow_list_tree_root =
            PoseidonHashOutTarget::from_slice(&slice[1..1 + POSEIDON_HASH_OUT_LEN]);
        let deny_list_tree_root = PoseidonHashOutTarget::from_slice(
            &slice[1 + POSEIDON_HASH_OUT_LEN..1 + 2 * POSEIDON_HASH_OUT_LEN],
        );
        let nullifier_tree_root = PoseidonHashOutTarget::from_slice(
            &slice[1 + 2 * POSEIDON_HASH_OUT_LEN..1 + 3 * POSEIDON_HASH_OUT_LEN],
        );
        Self {
            use_allow_list,
            allow_list_tree_root,
            deny_list_tree_root,
            nullifier_tree_root,
        }
    }
}
