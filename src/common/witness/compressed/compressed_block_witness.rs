use serde::{Deserialize, Serialize};

use crate::{
    common::{
        block::Block,
        signature::SignatureContent,
        trees::account_tree::{AccountMembershipProof, AccountMerkleProof},
        witness::block_witness::BlockWitness,
    },
    constants::ACCOUNT_TREE_HEIGHT,
    ethereum_types::{account_id_packed::AccountIdPacked, u256::U256},
    utils::{
        poseidon_hash_out::PoseidonHashOut,
        trees::{incremental_merkle_tree::IncrementalMerkleProof, merkle_tree::MerkleProof},
    },
};

use super::effective_bits;

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
}
