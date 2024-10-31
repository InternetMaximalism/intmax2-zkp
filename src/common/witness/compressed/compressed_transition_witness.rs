use serde::{Deserialize, Serialize};

use crate::{
    common::{
        trees::{
            account_tree::{AccountRegistrationProof, AccountUpdateProof},
            block_hash_tree::BlockHashMerkleProof,
            sender_tree::SenderLeaf,
        },
        witness::validity_transition_witness::{
            AccountRegistrationProofOrDummy, ValidityTransitionWitness,
        },
    },
    constants::ACCOUNT_TREE_HEIGHT,
    utils::{
        poseidon_hash_out::PoseidonHashOut,
        trees::{incremental_merkle_tree::IncrementalMerkleProof, merkle_tree::MerkleProof},
    },
};

use super::{effective_bits, is_dummy_incremental_merkle_proof};

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CompressedValidityTransitionWitness {
    pub sender_leaves: Vec<SenderLeaf>,
    pub block_merkle_proof: BlockHashMerkleProof,
    pub significant_account_registration_proofs: Option<Vec<AccountRegistrationProofOrDummy>>,
    pub significant_account_update_proofs: Option<Vec<AccountUpdateProof>>,
    pub common_account_merkle_proof: Vec<PoseidonHashOut>,
}

impl ValidityTransitionWitness {
    pub fn compress(&self, max_account_id: usize) -> CompressedValidityTransitionWitness {
        let significant_height = effective_bits(max_account_id) as usize;

        let mut common_account_merkle_proof = vec![];
        let significant_account_registration_proofs = if let Some(account_registration_proofs) =
            &self.account_registration_proofs
        {
            common_account_merkle_proof = account_registration_proofs[0].low_leaf_proof.0.siblings
                [significant_height..]
                .to_vec();
            let significant_account_registration_proofs = account_registration_proofs
                .iter()
                .map(|proof| {
                    let low_leaf_proof = if is_dummy_incremental_merkle_proof(
                        &proof.low_leaf_proof,
                        ACCOUNT_TREE_HEIGHT,
                    ) {
                        None
                    } else {
                        for i in 0..ACCOUNT_TREE_HEIGHT - significant_height {
                            assert_eq!(
                                proof.low_leaf_proof.0.siblings[significant_height + i],
                                common_account_merkle_proof[i]
                            );
                        }

                        Some(IncrementalMerkleProof(MerkleProof {
                            siblings: proof.low_leaf_proof.0.siblings[..significant_height]
                                .to_vec(),
                        }))
                    };

                    let leaf_proof = if is_dummy_incremental_merkle_proof(
                        &proof.leaf_proof,
                        ACCOUNT_TREE_HEIGHT,
                    ) {
                        None
                    } else {
                        for i in 0..ACCOUNT_TREE_HEIGHT - significant_height {
                            assert_eq!(
                                proof.leaf_proof.0.siblings[significant_height + i],
                                common_account_merkle_proof[i]
                            );
                        }

                        Some(IncrementalMerkleProof(MerkleProof {
                            siblings: proof.leaf_proof.0.siblings[..significant_height].to_vec(),
                        }))
                    };

                    AccountRegistrationProofOrDummy {
                        low_leaf_proof,
                        leaf_proof,
                        index: proof.index,
                        low_leaf_index: proof.low_leaf_index,
                        prev_low_leaf: proof.prev_low_leaf.clone(),
                    }
                })
                .collect::<Vec<_>>();

            Some(significant_account_registration_proofs)
        } else {
            None
        };
        let significant_account_update_proofs = if let Some(account_update_proofs) =
            &self.account_update_proofs
        {
            common_account_merkle_proof =
                account_update_proofs[0].leaf_proof.0.siblings[significant_height..].to_vec();
            let significant_account_update_proofs = account_update_proofs
                .iter()
                .map(|proof| {
                    for i in 0..ACCOUNT_TREE_HEIGHT - significant_height {
                        assert_eq!(
                            proof.leaf_proof.0.siblings[significant_height + i],
                            common_account_merkle_proof[i]
                        );
                    }
                    AccountUpdateProof {
                        leaf_proof: IncrementalMerkleProof(MerkleProof {
                            siblings: proof.leaf_proof.0.siblings[..significant_height].to_vec(),
                        }),
                        ..(proof.clone())
                    }
                })
                .collect::<Vec<_>>();

            Some(significant_account_update_proofs)
        } else {
            None
        };

        CompressedValidityTransitionWitness {
            sender_leaves: self.sender_leaves.clone(),
            block_merkle_proof: self.block_merkle_proof.clone(),
            significant_account_registration_proofs,
            significant_account_update_proofs,
            common_account_merkle_proof,
        }
    }

    pub fn decompress(compressed: &CompressedValidityTransitionWitness) -> Self {
        // let significant_height = ACCOUNT_TREE_HEIGHT -
        // compressed.common_account_merkle_proof.len();
        let account_registration_proofs = if let Some(significant_account_registration_proofs) =
            &compressed.significant_account_registration_proofs
        {
            let account_registration_proofs = significant_account_registration_proofs
                .iter()
                .map(|proof| {
                    let low_leaf_proof = if let Some(low_leaf_proof) = &proof.low_leaf_proof {
                        IncrementalMerkleProof(MerkleProof {
                            siblings: [
                                &low_leaf_proof.0.siblings[..],
                                &compressed.common_account_merkle_proof[..],
                            ]
                            .concat(),
                        })
                    } else {
                        IncrementalMerkleProof::dummy(ACCOUNT_TREE_HEIGHT)
                    };
                    let leaf_proof = if let Some(leaf_proof) = &proof.leaf_proof {
                        IncrementalMerkleProof(MerkleProof {
                            siblings: [
                                &leaf_proof.0.siblings[..],
                                &compressed.common_account_merkle_proof[..],
                            ]
                            .concat(),
                        })
                    } else {
                        IncrementalMerkleProof::dummy(ACCOUNT_TREE_HEIGHT)
                    };

                    AccountRegistrationProof {
                        low_leaf_proof,
                        leaf_proof,
                        index: proof.index,
                        low_leaf_index: proof.low_leaf_index,
                        prev_low_leaf: proof.prev_low_leaf.clone(),
                    }
                })
                .collect::<Vec<_>>();

            Some(account_registration_proofs)
        } else {
            None
        };
        let account_update_proofs = if let Some(significant_account_update_proofs) =
            &compressed.significant_account_update_proofs
        {
            let account_update_proofs = significant_account_update_proofs
                .iter()
                .map(|proof| AccountUpdateProof {
                    leaf_proof: IncrementalMerkleProof(MerkleProof {
                        siblings: [
                            &proof.leaf_proof.0.siblings[..],
                            &compressed.common_account_merkle_proof[..],
                        ]
                        .concat(),
                    }),
                    ..(proof.clone())
                })
                .collect::<Vec<_>>();

            Some(account_update_proofs)
        } else {
            None
        };

        Self {
            sender_leaves: compressed.sender_leaves.clone(),
            block_merkle_proof: compressed.block_merkle_proof.clone(),
            account_registration_proofs,
            account_update_proofs,
        }
    }
}
