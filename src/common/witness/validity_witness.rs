use crate::{
    circuits::validity::validity_pis::ValidityPublicInputs,
    common::public_state::PublicState,
    ethereum_types::{bytes32::Bytes32, u256::U256, u32limb_trait::U32LimbTrait},
};

use super::{block_witness::BlockWitness, validity_transition_witness::ValidityTransitionWitness};

#[derive(Debug, Clone)]
pub struct ValidityWitness {
    pub block_witness: BlockWitness,
    pub validity_transition_witness: ValidityTransitionWitness,
}

impl ValidityWitness {
    pub fn genesis() -> Self {
        Self {
            block_witness: BlockWitness::genesis(),
            validity_transition_witness: ValidityTransitionWitness::genesis(),
        }
    }

    pub fn to_validity_pis(&self) -> ValidityPublicInputs {
        // calculate new roots
        let prev_block_tree_root = self.block_witness.prev_block_tree_root;

        // transition block tree root
        let block = self.block_witness.block.clone();
        self.validity_transition_witness
            .block_merkle_proof
            .verify(
                &Bytes32::default(),
                block.block_number as usize,
                prev_block_tree_root,
            )
            .expect("Block merkle proof is invalid");
        let block_tree_root = self
            .validity_transition_witness
            .block_merkle_proof
            .get_root(&block.hash(), block.block_number as usize);

        let main_validation_pis = self.block_witness.to_main_validation_pis();

        // transition account tree root
        let prev_account_tree_root = self.block_witness.prev_account_tree_root;
        let mut account_tree_root = prev_account_tree_root;
        if main_validation_pis.is_valid && main_validation_pis.is_registoration_block {
            let account_registoration_proofs = self
                .validity_transition_witness
                .account_registoration_proofs
                .as_ref()
                .expect("account_registoration_proofs should be given");
            for (sender_leaf, account_registoration_proof) in self
                .validity_transition_witness
                .sender_leaves
                .iter()
                .zip(account_registoration_proofs)
            {
                let last_block_number = if sender_leaf.is_valid {
                    block.block_number
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
        if main_validation_pis.is_valid && !main_validation_pis.is_registoration_block {
            let account_update_proofs = self
                .validity_transition_witness
                .account_update_proofs
                .as_ref()
                .expect("account_update_proofs should be given");
            for (sender_leaf, account_update_proof) in self
                .validity_transition_witness
                .sender_leaves
                .iter()
                .zip(account_update_proofs)
            {
                let prev_last_block_number = account_update_proof.prev_leaf.value as u32;
                let last_block_number = if sender_leaf.is_valid {
                    block.block_number
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

        ValidityPublicInputs {
            public_state: PublicState {
                prev_account_tree_root,
                account_tree_root,
                block_tree_root,
                deposit_tree_root: block.deposit_tree_root,
                block_number: block.block_number,
                block_hash: main_validation_pis.block_hash,
            },
            tx_tree_root: main_validation_pis.tx_tree_root,
            sender_tree_root: main_validation_pis.sender_tree_root,
            is_registoration_block: main_validation_pis.is_registoration_block,
            is_valid_block: main_validation_pis.is_valid,
        }
    }

    pub fn get_block_number(&self) -> u32 {
        self.block_witness.block.block_number
    }
}
