use serde::{Deserialize, Serialize};

use crate::{
    circuits::validity::validity_pis::ValidityPublicInputs,
    common::{error::CommonError, public_state::PublicState},
    ethereum_types::bytes32::Bytes32,
};

use super::{block_witness::BlockWitness, validity_transition_witness::ValidityTransitionWitness};

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
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

    pub fn to_validity_pis(&self) -> Result<ValidityPublicInputs, CommonError> {
        // calculate new roots
        let prev_block_tree_root = self.block_witness.prev_block_tree_root;

        // transition block tree root
        let block = self.block_witness.block.clone();
        self.validity_transition_witness
            .block_merkle_proof
            .verify(
                &Bytes32::default(),
                block.block_number as u64,
                prev_block_tree_root,
            )
            .map_err(|e| CommonError::InvalidProof(format!("Block merkle proof is invalid: {}", e)))?;
        let block_tree_root = self
            .validity_transition_witness
            .block_merkle_proof
            .get_root(&block.hash(), block.block_number as u64);

        let main_validation_pis = self.block_witness.to_main_validation_pis().map_err(|e| {
            CommonError::BlockWitnessConversionFailed(format!(
                "Failed to convert block witness to main validation pis: {}",
                e
            ))
        })?;

        // transition account tree root
        let prev_account_tree_root = self.block_witness.prev_account_tree_root;
        let mut account_tree_root = prev_account_tree_root;
        let mut next_account_id = self.block_witness.prev_next_account_id;
        if main_validation_pis.is_valid && main_validation_pis.is_registration_block {
            let account_registration_proofs = self
                .validity_transition_witness
                .account_registration_proofs
                .as_ref()
                .ok_or(CommonError::MissingData(
                    "account_registration_proofs should be given".to_string(),
                ))?;
            for (sender_leaf, account_registration_proof) in self
                .validity_transition_witness
                .sender_leaves
                .iter()
                .zip(account_registration_proofs)
            {
                let is_not_dummy = !sender_leaf.sender.is_dummy_pubkey();
                let will_update = sender_leaf.signature_included && is_not_dummy;
                account_tree_root = account_registration_proof
                    .conditional_get_new_root(
                        will_update,
                        sender_leaf.sender,
                        block.block_number as u64,
                        account_tree_root,
                    )
                    .map_err(|e| CommonError::InvalidProof(format!("Invalid account registration proof: {}", e)))?;
                if will_update {
                    next_account_id += 1;
                }
            }
        }
        if main_validation_pis.is_valid && !main_validation_pis.is_registration_block {
            let account_update_proofs = self
                .validity_transition_witness
                .account_update_proofs
                .as_ref()
                .ok_or(CommonError::MissingData("account_update_proofs should be given".to_string()))?;
            for (sender_leaf, account_update_proof) in self
                .validity_transition_witness
                .sender_leaves
                .iter()
                .zip(account_update_proofs)
            {
                let prev_last_block_number = account_update_proof.prev_leaf.value as u32;
                let last_block_number = if sender_leaf.signature_included {
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
                    .map_err(|e| CommonError::InvalidProof(format!("Invalid account update proof: {}", e)))?;
            }
        }

        Ok(ValidityPublicInputs {
            public_state: PublicState {
                prev_account_tree_root,
                account_tree_root,
                next_account_id,
                block_tree_root,
                deposit_tree_root: block.deposit_tree_root,
                block_number: block.block_number,
                block_hash: main_validation_pis.block_hash,
                timestamp: block.timestamp,
            },
            tx_tree_root: main_validation_pis.tx_tree_root,
            sender_tree_root: main_validation_pis.sender_tree_root,
            is_valid_block: main_validation_pis.is_valid,
        })
    }

    pub fn get_block_number(&self) -> u32 {
        self.block_witness.block.block_number
    }
}
