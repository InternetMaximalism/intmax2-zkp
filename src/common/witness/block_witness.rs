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
        signature::{utils::get_pubkey_hash, SignatureContent},
        trees::{
            account_tree::{AccountMembershipProof, AccountMerkleProof, AccountTree},
            block_hash_tree::BlockHashTree,
            sender_tree::{get_sender_leaves, get_sender_tree_root, SenderTree},
        },
    },
    constants::{ACCOUNT_TREE_HEIGHT, BLOCK_HASH_TREE_HEIGHT, SENDER_TREE_HEIGHT},
    ethereum_types::{
        account_id_packed::AccountIdPacked, bytes32::Bytes32, u256::U256,
        u32limb_trait::U32LimbTrait,
    },
    utils::{
        poseidon_hash_out::PoseidonHashOut,
        trees::{incremental_merkle_tree::IncrementalMerkleProof, merkle_tree::MerkleProof},
    },
};

use super::validity_transition_witness::effective_bits;

/// A structure that holds all the information needed to verify a block
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct BlockWitness {
    pub block: Block,
    pub signature: SignatureContent,
    pub pubkeys: Vec<U256>,
    pub prev_account_tree_root: PoseidonHashOut,
    pub prev_block_tree_root: PoseidonHashOut,
    pub account_id_packed: Option<AccountIdPacked>, // in account id case
    pub account_merkle_proofs: Option<Vec<AccountMerkleProof>>, // in account id case
    pub account_membership_proofs: Option<Vec<AccountMembershipProof>>, // in pubkey case
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CompressedBlockWitness {
    pub block: Block,
    pub signature: SignatureContent,
    pub pubkeys: Vec<U256>,
    pub prev_account_tree_root: PoseidonHashOut,
    pub prev_block_tree_root: PoseidonHashOut,
    pub account_id_packed: Option<AccountIdPacked>, // in account id case
    pub significant_account_merkle_proofs: Option<Vec<AccountMerkleProof>>, // in account id case
    pub significant_account_membership_proofs: Option<Vec<AccountMembershipProof>>, /* in pubkey
                                                     * case */
    pub common_account_merkle_proof: Vec<PoseidonHashOut>,
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
            prev_block_tree_root: block_hash_tree.get_root(),
            account_id_packed: None,
            account_merkle_proofs: None,
            account_membership_proofs: None,
        }
    }

    pub fn compress(&self, max_account_id: usize) -> CompressedBlockWitness {
        let significant_height = effective_bits(max_account_id) as usize;

        let mut common_account_merkle_proof = vec![];
        let significant_account_merkle_proofs = if let Some(account_merkle_proofs) =
            &self.account_merkle_proofs
        {
            common_account_merkle_proof =
                account_merkle_proofs[0].merkle_proof.0.siblings[significant_height..].to_vec();
            let significant_account_merkle_proofs = account_merkle_proofs
                .iter()
                .map(|proof| {
                    for i in 0..ACCOUNT_TREE_HEIGHT - significant_height {
                        assert_eq!(
                            proof.merkle_proof.0.siblings[significant_height + i],
                            common_account_merkle_proof[i]
                        );
                    }
                    AccountMerkleProof {
                        merkle_proof: IncrementalMerkleProof(MerkleProof {
                            siblings: proof.merkle_proof.0.siblings[..significant_height].to_vec(),
                        }),
                        leaf: proof.leaf.clone(),
                    }
                })
                .collect();
            Some(significant_account_merkle_proofs)
        } else {
            None
        };
        let significant_account_membership_proofs = if let Some(account_membership_proofs) =
            &self.account_membership_proofs
        {
            common_account_merkle_proof =
                account_membership_proofs[0].leaf_proof.0.siblings[significant_height..].to_vec();
            let significant_account_membership_proofs = account_membership_proofs
                .iter()
                .map(|proof| {
                    for i in 0..ACCOUNT_TREE_HEIGHT - significant_height {
                        assert_eq!(
                            proof.leaf_proof.0.siblings[significant_height + i],
                            common_account_merkle_proof[i]
                        );
                    }
                    AccountMembershipProof {
                        leaf_proof: IncrementalMerkleProof(MerkleProof {
                            siblings: proof.leaf_proof.0.siblings[..significant_height].to_vec(),
                        }),
                        ..(proof.clone())
                    }
                })
                .collect();
            Some(significant_account_membership_proofs)
        } else {
            None
        };

        CompressedBlockWitness {
            block: self.block.clone(),
            signature: self.signature.clone(),
            pubkeys: self.pubkeys.clone(),
            prev_account_tree_root: self.prev_account_tree_root.clone(),
            prev_block_tree_root: self.prev_block_tree_root.clone(),
            account_id_packed: self.account_id_packed.clone(),
            significant_account_merkle_proofs,
            significant_account_membership_proofs,
            common_account_merkle_proof,
        }
    }

    pub fn decompress(compressed: &CompressedBlockWitness) -> Self {
        let account_merkle_proofs = if let Some(significant_account_merkle_proofs) =
            &compressed.significant_account_merkle_proofs
        {
            let common_account_merkle_proof = &compressed.common_account_merkle_proof;
            let account_merkle_proofs = significant_account_merkle_proofs
                .iter()
                .map(|proof| AccountMerkleProof {
                    merkle_proof: IncrementalMerkleProof(MerkleProof {
                        siblings: [
                            &proof.merkle_proof.0.siblings[..],
                            &common_account_merkle_proof[..],
                        ]
                        .concat(),
                    }),
                    leaf: proof.leaf.clone(),
                })
                .collect();
            Some(account_merkle_proofs)
        } else {
            None
        };
        let account_membership_proofs = if let Some(significant_account_membership_proofs) =
            &compressed.significant_account_membership_proofs
        {
            let common_account_merkle_proof = &compressed.common_account_merkle_proof;
            let account_membership_proofs = significant_account_membership_proofs
                .iter()
                .map(|proof| AccountMembershipProof {
                    leaf_proof: IncrementalMerkleProof(MerkleProof {
                        siblings: [
                            &proof.leaf_proof.0.siblings[..],
                            &common_account_merkle_proof[..],
                        ]
                        .concat(),
                    }),
                    ..(proof.clone())
                })
                .collect();
            Some(account_membership_proofs)
        } else {
            None
        };

        Self {
            block: compressed.block.clone(),
            signature: compressed.signature.clone(),
            pubkeys: compressed.pubkeys.clone(),
            prev_account_tree_root: compressed.prev_account_tree_root.clone(),
            prev_block_tree_root: compressed.prev_block_tree_root.clone(),
            account_id_packed: compressed.account_id_packed.clone(),
            account_merkle_proofs,
            account_membership_proofs,
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
                is_registration_block: false, // genesis block is not a registration block
                is_valid: validity_pis.is_valid_block,
            };
        }

        let mut result = true;
        let block = self.block.clone();
        let signature = self.signature.clone();
        let pubkeys = self.pubkeys.clone();
        let account_tree_root = self.prev_account_tree_root;

        let pubkey_hash = get_pubkey_hash(&pubkeys);
        let is_registration_block = signature.is_registration_block;
        let is_pubkey_eq = signature.pubkey_hash == pubkey_hash;
        if is_registration_block {
            assert!(is_pubkey_eq, "pubkey hash mismatch");
        } else {
            result = result && is_pubkey_eq;
        }
        if is_registration_block {
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
            is_registration_block,
            is_valid: result,
        }
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

// A subset of `BlockWitness` that only contains the information to be submitted to the
// contract
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct FullBlock {
    pub block: Block,
    pub signature: SignatureContent,
    pub pubkeys: Option<Vec<U256>>,  // pubkeys trimmed dummy pubkey
    pub account_ids: Option<String>, // hex representation of account_ids trimmed dummy account ids
    pub block_hash: Bytes32,
}

impl BlockWitness {
    pub fn to_full_block(&self) -> FullBlock {
        let pubkeys = if self.signature.is_registration_block {
            let pubkey_trimmed_dummy = self
                .pubkeys
                .iter()
                .filter(|p| !p.is_dummy_pubkey())
                .cloned()
                .collect::<Vec<_>>();
            Some(pubkey_trimmed_dummy)
        } else {
            None
        };
        let account_ids = if self.account_id_packed.is_some() {
            let account_id_packed = self.account_id_packed.unwrap();
            let dummy_account_id_start_at = account_id_packed
                .unpack()
                .iter()
                .position(|account_id| *account_id == 1);
            if dummy_account_id_start_at.is_none() {
                Some(account_id_packed.to_hex()) // account ids are full
            } else {
                let hex = account_id_packed.to_hex();
                let start_index = dummy_account_id_start_at.unwrap();
                //  a little dirty implementation to slice until 5bytes * start_index = 10hex
                // *start_index
                Some(hex[..2 + 10 * start_index].to_string())
            }
        } else {
            None
        };

        FullBlock {
            block: self.block.clone(),
            signature: self.signature.clone(),
            pubkeys,
            account_ids,
            block_hash: self.block.hash(),
        }
    }
}
