use crate::{
    circuits::validity::validity_pis::ValidityPublicInputs,
    common::trees::{
        account_tree::{AccountRegistorationProof, AccountUpdateProof},
        block_hash_tree::BlockHashMerkleProof,
        sender_tree::SenderLeaf,
    },
    ethereum_types::{bytes32::Bytes32, u256::U256, u32limb_trait::U32LimbTrait},
    utils::poseidon_hash_out::PoseidonHashOut,
};

/// A structure that holds all the information needed to produce transition proof besides the
/// block_witness
#[derive(Debug, Clone)]
pub struct ValidityTransitionWitness {
    pub prev_pis: ValidityPublicInputs,
    pub prev_sender_leaves: Vec<SenderLeaf>,
    pub block_merkle_proof: BlockHashMerkleProof,
    pub account_registoration_proofs: Option<Vec<AccountRegistorationProof>>,
    pub account_update_proofs: Option<Vec<AccountUpdateProof>>,
}

pub struct Roots {
    pub account_tree_root: PoseidonHashOut,
    pub block_tree_root: PoseidonHashOut,
}

impl ValidityTransitionWitness {
    pub fn new_roots(&self) -> Roots {
        let prev_public_state = self.prev_pis.public_state.clone();
        self.block_merkle_proof
            .verify(
                &Bytes32::default(),
                prev_public_state.block_number as usize,
                prev_public_state.block_tree_root,
            )
            .expect("Block hash merkle proof is invalid");
        let block_tree_root = self.block_merkle_proof.get_root(
            &prev_public_state.block_hash,
            prev_public_state.block_number as usize,
        );
        let mut account_tree_root = prev_public_state.account_tree_root;
        if self.prev_pis.is_valid_block && self.prev_pis.is_registoration_block {
            let account_registoration_proofs = self
                .account_registoration_proofs
                .as_ref()
                .expect("account_registoration_proofs should be given");
            for (sender_leaf, account_registoration_proof) in self
                .prev_sender_leaves
                .iter()
                .zip(account_registoration_proofs)
            {
                let last_block_number = if sender_leaf.is_valid {
                    prev_public_state.block_number
                } else {
                    0
                };
                let is_not_dummy = sender_leaf.sender != U256::<u32>::one();
                account_tree_root = account_registoration_proof
                    .conditional_get_new_root(
                        is_not_dummy,
                        sender_leaf.sender,
                        last_block_number as u64,
                        account_tree_root,
                    )
                    .expect("Invalid account registoration proof");
            }
        }
        if self.prev_pis.is_valid_block && !self.prev_pis.is_registoration_block {
            let account_update_proofs = self
                .account_update_proofs
                .as_ref()
                .expect("account_update_proofs should be given");
            for (sender_leaf, account_update_proof) in
                self.prev_sender_leaves.iter().zip(account_update_proofs)
            {
                let prev_last_block_number = account_update_proof.prev_leaf.value as u32;
                let last_block_number = if sender_leaf.is_valid {
                    prev_public_state.block_number
                } else {
                    prev_last_block_number
                };
                account_tree_root = account_update_proof
                    .get_new_root(
                        sender_leaf.sender,
                        prev_last_block_number as u64,
                        last_block_number as u64,
                        account_tree_root,
                    )
                    .expect("Invalid account update proof");
            }
        }
        Roots {
            account_tree_root,
            block_tree_root,
        }
    }
}
