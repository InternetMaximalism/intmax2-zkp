use crate::utils::poseidon_hash_out::PoseidonHashOut;

pub struct InnocencePublicInputs {
    pub use_allow_list: bool,
    pub allow_list_tree_root: PoseidonHashOut,
    pub deny_list_tree_root: PoseidonHashOut,
    pub nullifier_tree_root: PoseidonHashOut,
}
