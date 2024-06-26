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
        signature::{utils::get_pubkey_hash, SignatureContent},
        trees::{
            account_tree::{AccountMembershipProof, AccountMerkleProof},
            sender_tree::get_sender_tree_root,
        },
    },
    ethereum_types::{account_id_packed::AccountIdPacked, u256::U256},
    utils::poseidon_hash_out::PoseidonHashOut,
};

/// A structure that holds all the information needed to verify a block
#[derive(Debug, Clone, Default)]
pub struct BlockWitness {
    pub block: Block,
    pub signature: SignatureContent,
    pub pubkeys: Vec<U256<u32>>,
    pub account_tree_root: PoseidonHashOut,
    pub block_hash_tree_root: PoseidonHashOut,
    pub account_id_packed: Option<AccountIdPacked<u32>>, // account id case
    pub account_merkle_proofs: Option<Vec<AccountMerkleProof>>, // account id case
    pub account_membership_proofs: Option<Vec<AccountMembershipProof>>, // pubkey case
}

impl BlockWitness {
    pub fn to_validity_pis(&self) -> ValidityPublicInputs {
        let main_validation_pis = self.to_main_validation_pis();
        ValidityPublicInputs {
            account_tree_root: self.account_tree_root,
            block_hash_tree_root: self.block_hash_tree_root,
            block_number: self.block.block_number,
            block_hash: main_validation_pis.block_hash,
            tx_tree_root: main_validation_pis.tx_tree_root,
            sender_tree_root: main_validation_pis.sender_tree_root,
            is_registoration_block: main_validation_pis.is_registoration_block,
            is_valid_block: main_validation_pis.is_valid,
        }
    }

    pub fn to_main_validation_pis(&self) -> MainValidationPublicInputs {
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
            account_tree_root,
            tx_tree_root,
            sender_tree_root,
            is_registoration_block,
            is_valid: result,
        }
    }
}
