use crate::{
    common::{deposit::Deposit, trees::nullifier_tree::NullifierInsertionProof},
    ethereum_types::bytes32::Bytes32,
    utils::poseidon_hash_out::PoseidonHashOut,
};

use super::address_list::AddressMembershipProof;

pub struct InnocenceInnerValue {
    pub use_allow_list: bool,
    pub allow_list_tree_root: PoseidonHashOut,
    pub deny_list_tree_root: PoseidonHashOut,
    pub prev_nullifier_tree_root: PoseidonHashOut,
    pub new_nullifier_tree_root: PoseidonHashOut,
    pub deposit: Deposit,
    pub nullifier_proof: NullifierInsertionProof,
    pub allow_list_membership_proof: AddressMembershipProof,
    pub deny_list_membership_proof: AddressMembershipProof,
}

impl InnocenceInnerValue {
    pub fn new(
        use_allow_list: bool,
        allow_list_tree_root: PoseidonHashOut,
        deny_list_tree_root: PoseidonHashOut,
        prev_nullifier_tree_root: PoseidonHashOut,
        deposit: Deposit,
        nullifier_proof: NullifierInsertionProof,
        allow_list_membership_proof: AddressMembershipProof,
        deny_list_membership_proof: AddressMembershipProof,
    ) -> anyhow::Result<Self> {
        // prove allow list inclusion
        allow_list_membership_proof
            .verify(deposit.depositor, allow_list_tree_root)
            .map_err(|e| {
                anyhow::anyhow!("allow list membership proof verification failed: {}", e)
            })?;
        if use_allow_list && !allow_list_membership_proof.is_included() {
            return Err(anyhow::anyhow!("depositor is not in the allow list"));
        }
        deny_list_membership_proof
            .verify(deposit.depositor, deny_list_tree_root)
            .map_err(|e| {
                anyhow::anyhow!("deny list membership proof verification failed: {}", e)
            })?;
        if !deny_list_membership_proof.is_included() {
            return Err(anyhow::anyhow!("depositor is in the deny list"));
        }
        // prove transition of nullifier root
        let nullifier: Bytes32 = deposit.poseidon_hash().into();
        let new_nullifier_tree_root = nullifier_proof
            .get_new_root(prev_nullifier_tree_root, nullifier)
            .map_err(|e| anyhow::anyhow!("Invalid nullifier merkle proof: {}", e))?;
        Ok(Self {
            use_allow_list,
            allow_list_tree_root,
            deny_list_tree_root,
            prev_nullifier_tree_root,
            new_nullifier_tree_root,
            deposit,
            nullifier_proof,
            allow_list_membership_proof,
            deny_list_membership_proof,
        })
    }
}
