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
        public_state::PublicState,
        signature::{utils::get_pubkey_hash, SignatureContent},
        trees::{
            account_tree::{AccountMembershipProof, AccountMerkleProof, AccountTree},
            block_hash_tree::BlockHashTree,
            sender_tree::get_sender_tree_root,
            tx_tree::TxTree,
        },
    },
    constants::BLOCK_HASH_TREE_HEIGHT,
    ethereum_types::{account_id_packed::AccountIdPacked, u256::U256},
    utils::poseidon_hash_out::PoseidonHashOut,
};

use super::tx_witness::TxWitness;

/// A structure that holds all the information needed to verify a block
#[derive(Debug, Clone)]
pub struct BlockWitness {
    pub block: Block,
    pub signature: SignatureContent,
    pub pubkeys: Vec<U256<u32>>,
    pub account_tree_root: PoseidonHashOut,
    pub block_tree_root: PoseidonHashOut,
    pub account_id_packed: Option<AccountIdPacked<u32>>, // in account id case
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
            account_tree_root: account_tree.get_root(),
            block_tree_root: block_hash_tree.get_root(),
            account_id_packed: None,
            account_merkle_proofs: None,
            account_membership_proofs: None,
        }
    }

    pub fn to_validity_pis(&self) -> ValidityPublicInputs {
        let main_validation_pis = self.to_main_validation_pis();
        ValidityPublicInputs {
            public_state: PublicState {
                account_tree_root: self.account_tree_root,
                block_tree_root: self.block_tree_root,
                deposit_tree_root: self.block.deposit_tree_root,
                block_number: self.block.block_number,
                block_hash: main_validation_pis.block_hash,
            },
            tx_tree_root: main_validation_pis.tx_tree_root,
            sender_tree_root: main_validation_pis.sender_tree_root,
            is_registoration_block: main_validation_pis.is_registoration_block,
            is_valid_block: main_validation_pis.is_valid,
        }
    }

    pub fn to_main_validation_pis(&self) -> MainValidationPublicInputs {
        if self.block == Block::genesis() {
            let validity_pis = ValidityPublicInputs::genesis();
            return MainValidationPublicInputs {
                prev_block_hash: Block::genesis().prev_block_hash,
                block_hash: validity_pis.public_state.block_hash,
                deposit_tree_root: validity_pis.public_state.deposit_tree_root,
                account_tree_root: validity_pis.public_state.account_tree_root,
                tx_tree_root: validity_pis.tx_tree_root,
                sender_tree_root: validity_pis.sender_tree_root,
                block_number: validity_pis.public_state.block_number,
                is_registoration_block: validity_pis.is_registoration_block,
                is_valid: validity_pis.is_valid_block,
            };
        }

        let mut result = true;
        let block = self.block.clone();
        let signature = self.signature.clone();
        let pubkeys = self.pubkeys.clone();
        let account_tree_root = self.account_tree_root;

        let pubkey_hash = get_pubkey_hash(&pubkeys);
        let is_registoration_block = signature.is_registoration_block;
        let is_pubkey_eq = signature.pubkey_hash == pubkey_hash;
        if is_registoration_block {
            assert!(is_pubkey_eq, "pubkey hash mismatch");
        } else {
            result = result && is_pubkey_eq;
        }
        if is_registoration_block {
            // Account exclusion verification
            let account_exclusion_value = AccountExclusionValue::new(
                account_tree_root,
                self.account_membership_proofs.clone().unwrap(),
                pubkeys.clone(),
            );
            result = result && account_exclusion_value.is_valid;
        } else {
            // Account inclusion verification
            let account_inclusion_value = AccountInclusionValue::new(
                account_tree_root,
                self.account_id_packed.unwrap(),
                self.account_merkle_proofs.clone().unwrap(),
                pubkeys.clone(),
            );
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

        let tx_tree_root = signature.tx_tree_root;
        MainValidationPublicInputs {
            prev_block_hash,
            block_hash,
            deposit_tree_root: block.deposit_tree_root,
            account_tree_root,
            tx_tree_root,
            sender_tree_root,
            block_number: block.block_number,
            is_registoration_block,
            is_valid: result,
        }
    }
}

#[derive(Clone, Debug)]
pub struct BlockInfo {
    pub block_witness: BlockWitness,
    pub tx_tree: TxTree,
}

impl BlockInfo {
    pub fn generate_tx_witnesses(&self) -> Vec<TxWitness> {
        return self
            .tx_tree
            .leaves()
            .into_iter()
            .enumerate()
            .map(|(tx_index, tx)| {
                let tx_merkle_proof = self.tx_tree.prove(tx_index);
                TxWitness {
                    block_witness: self.block_witness.clone(),
                    tx: tx.clone(),
                    tx_index,
                    tx_merkle_proof,
                }
            })
            .collect();
    }
}
