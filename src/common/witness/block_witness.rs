use serde::{Deserialize, Serialize};

use crate::{
    circuits::validity::{
        block_validation::{
            account_exclusion::AccountExclusionValue, account_inclusion::AccountInclusionValue,
            aggregation::AggregationValue, format_validation::FormatValidationValue,
            main_validation::MainValidationPublicInputs,
        },
        validity_pis::ValidityPublicInputs,
    },
    common::{
        block::Block,
        error::CommonError,
        signature::{utils::get_pubkey_hash, SignatureContent},
        trees::{
            account_tree::{
                AccountMembershipProof, AccountMerkleProof, AccountRegistrationProof, AccountTree,
            },
            block_hash_tree::BlockHashTree,
            sender_tree::{get_sender_leaves, get_sender_tree_root, SenderTree},
        },
    },
    constants::{ACCOUNT_TREE_HEIGHT, BLOCK_HASH_TREE_HEIGHT, SENDER_TREE_HEIGHT},
    ethereum_types::{account_id::AccountIdPacked, u256::U256},
    utils::poseidon_hash_out::PoseidonHashOut,
};

use super::{
    validity_transition_witness::ValidityTransitionWitness, validity_witness::ValidityWitness,
};

/// A structure that holds all the information needed to verify a block
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct BlockWitness {
    pub block: Block,
    pub signature: SignatureContent,
    pub pubkeys: Vec<U256>,
    pub prev_account_tree_root: PoseidonHashOut,
    pub prev_next_account_id: u64,
    pub prev_block_tree_root: PoseidonHashOut,
    pub account_id_packed: Option<AccountIdPacked>, // in account id case
    pub account_merkle_proofs: Option<Vec<AccountMerkleProof>>, // in account id case
    pub account_membership_proofs: Option<Vec<AccountMembershipProof>>, // in pubkey case
}

impl BlockWitness {
    pub fn genesis() -> Self {
        let block_hash_tree = BlockHashTree::new(BLOCK_HASH_TREE_HEIGHT);
        let account_tree = AccountTree::initialize();
        Self {
            block: Block::genesis(),
            signature: SignatureContent::default(),
            pubkeys: vec![],
            prev_account_tree_root: account_tree.get_root(),
            prev_next_account_id: 2,
            prev_block_tree_root: block_hash_tree.get_root(),
            account_id_packed: None,
            account_merkle_proofs: None,
            account_membership_proofs: None,
        }
    }

    pub fn to_main_validation_pis(&self) -> Result<MainValidationPublicInputs, CommonError> {
        if self.block == Block::genesis() {
            let validity_pis = ValidityPublicInputs::genesis();
            return Ok(MainValidationPublicInputs {
                prev_block_hash: Block::genesis().prev_block_hash,
                block_hash: validity_pis.public_state.block_hash,
                deposit_tree_root: validity_pis.public_state.deposit_tree_root,
                account_tree_root: validity_pis.public_state.account_tree_root,
                tx_tree_root: validity_pis.tx_tree_root,
                sender_tree_root: validity_pis.sender_tree_root,
                timestamp: validity_pis.public_state.timestamp,
                block_number: validity_pis.public_state.block_number,
                is_registration_block: false, // genesis block is not a registration block
                is_valid: validity_pis.is_valid_block,
            });
        }

        let mut result = true;
        let block = self.block.clone();
        let signature = self.signature.clone();
        let pubkeys = self.pubkeys.clone();
        let account_tree_root = self.prev_account_tree_root;
        let sender_leaves = get_sender_leaves(&pubkeys, signature.sender_flag);

        let pubkey_hash = get_pubkey_hash(&pubkeys);
        let is_registration_block = signature.block_sign_payload.is_registration_block;
        let is_pubkey_eq = signature.pubkey_hash == pubkey_hash;
        if is_registration_block {
            if !is_pubkey_eq {
                return Err(CommonError::InvalidData("pubkey hash mismatch".to_string()));
            }
        } else {
            result = result && is_pubkey_eq;
        }
        if is_registration_block {
            // Account exclusion verification
            let account_exclusion_value = AccountExclusionValue::new(
                account_tree_root,
                self.account_membership_proofs
                    .clone()
                    .ok_or(CommonError::MissingData(
                        "account_membership_proofs is None in registration block".to_string(),
                    ))?,
                sender_leaves,
            )?;
            result = result && account_exclusion_value.is_valid;
        } else {
            // Account inclusion verification
            let account_inclusion_value = AccountInclusionValue::new(
                account_tree_root,
                self.account_id_packed.ok_or(CommonError::MissingData(
                    "account_id_packed is None in non-registration block".to_string(),
                ))?,
                self.account_merkle_proofs
                    .clone()
                    .ok_or(CommonError::MissingData(
                        "account_merkle_proofs is None in non-registration block".to_string(),
                    ))?,
                pubkeys.clone(),
            )?;
            result = result && account_inclusion_value.is_valid;
        }

        // Format validation
        let format_validation_value =
            FormatValidationValue::new(pubkeys.clone(), signature.clone());
        result = result && format_validation_value.is_valid;

        if result {
            let aggregation_value = AggregationValue::new(pubkeys.clone(), signature.clone());
            result = result && aggregation_value.is_valid;
        }

        let prev_block_hash = block.prev_block_hash;
        let block_hash = block.hash();
        let sender_tree_root = get_sender_tree_root(&pubkeys, signature.sender_flag);

        let tx_tree_root = signature.block_sign_payload.tx_tree_root;
        Ok(MainValidationPublicInputs {
            prev_block_hash,
            block_hash,
            deposit_tree_root: block.deposit_tree_root,
            account_tree_root,
            tx_tree_root,
            sender_tree_root,
            timestamp: block.timestamp,
            block_number: block.block_number,
            is_registration_block,
            is_valid: result,
        })
    }

    pub fn to_validity_witness(
        &self,
        account_tree: &AccountTree,
        block_tree: &BlockHashTree,
    ) -> Result<ValidityWitness, CommonError> {
        let mut account_tree = account_tree.clone();
        let mut block_tree = block_tree.clone();
        self.update_trees(&mut account_tree, &mut block_tree)
    }

    pub fn update_trees(
        &self,
        account_tree: &mut AccountTree,
        block_tree: &mut BlockHashTree,
    ) -> Result<ValidityWitness, CommonError> {
        let block_pis = self
            .to_main_validation_pis()
            .map_err(|e| CommonError::BlockWitnessConversionFailed(e.to_string()))?;
        if block_pis.block_number != block_tree.len() as u32 {
            return Err(CommonError::InvalidBlock(
                "block number mismatch".to_string(),
            ));
        }

        // Update block tree
        let block_merkle_proof = block_tree.prove(self.block.block_number as u64);
        block_tree.push(self.block.hash());

        // Update account tree
        let sender_leaves = get_sender_leaves(&self.pubkeys, self.signature.sender_flag);
        let account_registration_proofs = {
            if block_pis.is_valid && block_pis.is_registration_block {
                let mut account_registration_proofs = Vec::new();
                for sender_leaf in &sender_leaves {
                    let is_dummy_pubkey = sender_leaf.sender.is_dummy_pubkey();
                    let will_update = sender_leaf.signature_included && !is_dummy_pubkey;
                    let proof = if will_update {
                        account_tree
                            .prove_and_insert(sender_leaf.sender, block_pis.block_number as u64)
                            .map_err(|e| {
                                CommonError::AccountTreeProveAndInsertFailed(e.to_string())
                            })?
                    } else {
                        AccountRegistrationProof::dummy(ACCOUNT_TREE_HEIGHT)
                    };
                    account_registration_proofs.push(proof);
                }
                Some(account_registration_proofs)
            } else {
                None
            }
        };

        let account_update_proofs = {
            if block_pis.is_valid && (!block_pis.is_registration_block) {
                let mut account_update_proofs = Vec::new();
                let block_number = block_pis.block_number;
                for sender_leaf in sender_leaves.iter() {
                    let account_id = account_tree.index(sender_leaf.sender).unwrap();
                    let prev_leaf = account_tree.get_leaf(account_id);
                    let prev_last_block_number = prev_leaf.value as u32;
                    let last_block_number = if sender_leaf.signature_included {
                        block_number
                    } else {
                        prev_last_block_number
                    };
                    let proof = account_tree
                        .prove_and_update(sender_leaf.sender, last_block_number as u64)
                        .map_err(|e| CommonError::AccountTreeProveAndUpdateFailed(e.to_string()))?;
                    account_update_proofs.push(proof);
                }
                Some(account_update_proofs)
            } else {
                None
            }
        };

        let validity_transition_witness = ValidityTransitionWitness {
            sender_leaves,
            block_merkle_proof,
            account_registration_proofs,
            account_update_proofs,
        };
        Ok(ValidityWitness {
            validity_transition_witness,
            block_witness: self.clone(),
        })
    }

    pub fn get_sender_tree(&self) -> SenderTree {
        let sender_leaves = get_sender_leaves(&self.pubkeys, self.signature.sender_flag);
        let mut sender_tree = SenderTree::new(SENDER_TREE_HEIGHT);
        for sender_leaf in sender_leaves {
            sender_tree.push(sender_leaf);
        }
        assert_eq!(
            sender_tree.get_root(),
            get_sender_tree_root(&self.pubkeys, self.signature.sender_flag)
        );
        sender_tree
    }
}
