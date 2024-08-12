use serde::{Deserialize, Serialize};

use crate::{
    circuits::validity::validity_pis::ValidityPublicInputs, common::public_state::PublicState,
    ethereum_types::bytes32::Bytes32,
};

use super::{
    block_witness::{BlockWitness, CompressedBlockWitness},
    validity_transition_witness::{CompressedValidityTransitionWitness, ValidityTransitionWitness},
};

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ValidityWitness {
    pub block_witness: BlockWitness,
    pub validity_transition_witness: ValidityTransitionWitness,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CompressedValidityWitness {
    pub block_witness: CompressedBlockWitness,
    pub validity_transition_witness: CompressedValidityTransitionWitness,
}

impl ValidityWitness {
    pub fn genesis() -> Self {
        Self {
            block_witness: BlockWitness::genesis(),
            validity_transition_witness: ValidityTransitionWitness::genesis(),
        }
    }

    pub fn compress(&self, max_account_id: usize) -> CompressedValidityWitness {
        CompressedValidityWitness {
            block_witness: self.block_witness.compress(max_account_id),
            validity_transition_witness: self.validity_transition_witness.compress(max_account_id),
        }
    }

    pub fn decompress(compressed: &CompressedValidityWitness) -> Self {
        Self {
            block_witness: BlockWitness::decompress(&compressed.block_witness),
            validity_transition_witness: ValidityTransitionWitness::decompress(
                &compressed.validity_transition_witness,
            ),
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
        if main_validation_pis.is_valid && main_validation_pis.is_registration_block {
            let account_registration_proofs = self
                .validity_transition_witness
                .account_registration_proofs
                .as_ref()
                .expect("account_registration_proofs should be given");
            for (sender_leaf, account_registration_proof) in self
                .validity_transition_witness
                .sender_leaves
                .iter()
                .zip(account_registration_proofs)
            {
                let last_block_number = if sender_leaf.is_valid {
                    block.block_number
                } else {
                    0
                };
                let is_not_dummy = !sender_leaf.sender.is_dummy_pubkey();
                account_tree_root = account_registration_proof
                    .conditional_get_new_root(
                        is_not_dummy,
                        sender_leaf.sender,
                        last_block_number as u64,
                        account_tree_root,
                    )
                    .expect("Invalid account registration proof");
            }
        }
        if main_validation_pis.is_valid && !main_validation_pis.is_registration_block {
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
            is_valid_block: main_validation_pis.is_valid,
        }
    }

    pub fn get_block_number(&self) -> u32 {
        self.block_witness.block.block_number
    }
}
