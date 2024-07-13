use ark_bn254::{Bn254, Fr, G1Affine, G2Affine};
use ark_ec::{pairing::Pairing as _, AffineRepr as _};
use hashbrown::HashMap;
use num::BigUint;
use plonky2::field::{goldilocks_field::GoldilocksField, types::Field};
use plonky2_bn254::{curves::g2::G2Target, utils::hash_to_g2::HashToG2 as _};

use crate::{
    circuits::validity::validity_pis::ValidityPublicInputs,
    common::{
        block::Block,
        signature::{
            sign::{hash_to_weight, sign_to_tx_root},
            utils::get_pubkey_hash,
            SignatureContent,
        },
        trees::{
            account_tree::{AccountRegistorationProof, AccountTree},
            block_hash_tree::BlockHashTree,
            deposit_tree::DepositTree,
            sender_tree::get_sender_leaves,
            tx_tree::TxTree,
        },
        witness::{
            block_witness::BlockWitness, validity_transition_witness::ValidityTransitionWitness,
            validity_witness::ValidityWitness,
        },
    },
    constants::{
        ACCOUNT_TREE_HEIGHT, BLOCK_HASH_TREE_HEIGHT, DEPOSIT_TREE_HEIGHT, NUM_SENDERS_IN_BLOCK,
        TX_TREE_HEIGHT,
    },
    ethereum_types::{
        account_id_packed::AccountIdPacked, bytes32::Bytes32, u128::U128, u256::U256,
        u32limb_trait::U32LimbTrait,
    },
};

use super::tx_request::TxRequest;

pub struct MockBlockBuilder {
    pub account_tree: AccountTree, // current account tree
    pub block_tree: BlockHashTree, // current block hash tree
    pub deposit_tree: DepositTree, // current deposit tree
    pub block_witnesses: Vec<BlockWitness>,
    pub prev_account_tree: AccountTree, // previous account tree
    pub prev_block_tree: BlockHashTree, // previous block hash tree
    pub aux_info: HashMap<u32, AuxInfo>,
}

/// Information not required for validity proof but required for balance proof construction
pub struct AuxInfo {
    pub tx_tree: TxTree,
    pub prev_block_witness: BlockWitness,
    pub validity_witness: ValidityWitness,
    pub account_tree: AccountTree,
    pub block_tree: BlockHashTree,
}

impl MockBlockBuilder {
    // instantiate a new MockBlockBuilder
    // post the genesis block
    pub fn new() -> Self {
        let account_tree = AccountTree::initialize();
        let prev_account_tree = account_tree.clone();

        let prev_block_tree = BlockHashTree::new(BLOCK_HASH_TREE_HEIGHT);
        let deposit_tree = DepositTree::new(DEPOSIT_TREE_HEIGHT);
        let block_witness = BlockWitness::genesis();
        let mut block_tree = prev_block_tree.clone();
        block_tree.push(block_witness.block.hash()); // register genesis block
        MockBlockBuilder {
            account_tree,
            block_tree,
            deposit_tree,
            block_witnesses: vec![block_witness],
            prev_account_tree,
            prev_block_tree,
            aux_info: HashMap::new(),
        }
    }

    pub fn get_last_block_witness(&self) -> BlockWitness {
        self.block_witnesses.last().unwrap().clone()
    }
}

impl MockBlockBuilder {
    fn generate_block(
        &self,
        is_registoration_block: bool,
        txs: Vec<TxRequest>,
    ) -> (BlockWitness, TxTree) {
        assert!(txs.len() > 0, "at least one tx is required");
        assert!(txs.len() <= NUM_SENDERS_IN_BLOCK, "too many txs");
        // sort and pad txs
        let mut sorted_txs = txs.clone();
        sorted_txs.sort_by(|a, b| b.sender.pubkey_x.cmp(&a.sender.pubkey_x));
        sorted_txs.resize(NUM_SENDERS_IN_BLOCK, TxRequest::dummy());

        let pubkeys = sorted_txs
            .iter()
            .map(|tx| tx.sender.pubkey_x)
            .collect::<Vec<_>>();
        let pubkey_hash = get_pubkey_hash(&pubkeys);

        // account lookup
        let (account_id_packed, account_merkle_proofs, account_membership_proofs) =
            if is_registoration_block {
                let mut account_membership_proofs = Vec::new();
                for pubkey in pubkeys.iter() {
                    let is_dummy = *pubkey == U256::<u32>::one();
                    assert!(
                        self.account_tree.index(*pubkey).is_none() || is_dummy,
                        "account already exists"
                    );
                    let proof = self.account_tree.prove_membership(*pubkey);
                    account_membership_proofs.push(proof);
                }
                (None, None, Some(account_membership_proofs))
            } else {
                let mut account_ids = Vec::new();
                let mut account_merkle_proofs = Vec::new();
                for pubkey in pubkeys.iter() {
                    let account_id = self.account_tree.index(*pubkey).expect("account not found");
                    let proof = self.account_tree.prove_inclusion(account_id);
                    account_ids.push(account_id);
                    account_merkle_proofs.push(proof);
                }
                let account_id_packed = AccountIdPacked::pack(&account_ids);
                (Some(account_id_packed), Some(account_merkle_proofs), None)
            };
        let account_id_hash = account_id_packed.map(|x| x.hash()).unwrap_or_default();

        // construct tx tree root
        let mut tx_tree = TxTree::new(TX_TREE_HEIGHT);
        for tx in txs.iter() {
            tx_tree.push(tx.tx.clone());
        }
        let tx_tree_root: Bytes32<u32> = tx_tree.get_root().into();

        let signature = construct_signature(
            tx_tree_root,
            pubkey_hash,
            account_id_hash,
            is_registoration_block,
            &sorted_txs,
        );
        let signature_hash = signature.hash();

        let prev_block = self.get_last_block_witness().block;
        let block = Block {
            prev_block_hash: prev_block.hash(),
            deposit_tree_root: self.deposit_tree.get_root(),
            signature_hash,
            block_number: prev_block.block_number + 1,
        };
        let account_tree_root = self.account_tree.get_root();
        let block_hash_tree_root = self.block_tree.get_root();
        let block_witness = BlockWitness {
            block,
            signature: signature.clone(),
            pubkeys: pubkeys.clone(),
            account_tree_root,
            block_tree_root: block_hash_tree_root,
            account_id_packed,
            account_merkle_proofs,
            account_membership_proofs,
        };
        assert!(block_witness.to_main_validation_pis().is_valid); // should be valid block
        (block_witness, tx_tree)
    }

    // Generate transition witness from the prev block to the current block
    fn generate_transition_witness(&self) -> ValidityTransitionWitness {
        let prev_block_witness = self.get_last_block_witness();
        if prev_block_witness.block.block_number == 0 {
            // prev block is genesis block
            assert_eq!(
                self.prev_block_tree.get_root(),
                prev_block_witness.block_tree_root
            );
            return ValidityTransitionWitness {
                prev_pis: ValidityPublicInputs::genesis(),
                prev_sender_leaves: Vec::new(),
                block_merkle_proof: self.prev_block_tree.prove(0),
                account_registoration_proofs: None,
                account_update_proofs: None,
            };
        }
        let prev_pis = prev_block_witness.to_validity_pis();
        let block_merkle_proof = self
            .prev_block_tree
            .prove(prev_block_witness.block.block_number as usize);
        assert_eq!(
            prev_pis.public_state.account_tree_root,
            self.prev_account_tree.get_root()
        );
        assert_eq!(
            prev_pis.public_state.block_tree_root,
            self.prev_block_tree.get_root()
        );

        let prev_sender_leaves = get_sender_leaves(
            &prev_block_witness.pubkeys,
            prev_block_witness.signature.sender_flag,
        );
        let account_registoration_proofs = {
            if prev_pis.is_valid_block && prev_pis.is_registoration_block {
                let mut account_registoration_proofs = Vec::new();
                let mut prev_account_tree = self.prev_account_tree.clone();
                for sender_leaf in &prev_sender_leaves {
                    let last_block_number = if sender_leaf.is_valid {
                        prev_pis.public_state.block_number
                    } else {
                        0
                    };
                    let is_dummy_pubkey = sender_leaf.sender == U256::<u32>::one();
                    let proof = if is_dummy_pubkey {
                        AccountRegistorationProof::dummy(ACCOUNT_TREE_HEIGHT)
                    } else {
                        prev_account_tree
                            .prove_and_insert(sender_leaf.sender, last_block_number as u64)
                            .unwrap()
                    };
                    account_registoration_proofs.push(proof);
                }
                Some(account_registoration_proofs)
            } else {
                None
            }
        };

        let account_update_proofs = {
            if prev_pis.is_valid_block && (!prev_pis.is_registoration_block) {
                let mut account_update_proofs = Vec::new();
                let mut prev_account_tree = self.prev_account_tree.clone();
                let block_number = prev_pis.public_state.block_number;
                for sender_leaf in prev_sender_leaves.iter() {
                    let account_id = prev_account_tree.index(sender_leaf.sender).unwrap();
                    let prev_leaf = prev_account_tree.get_leaf(account_id);
                    let prev_last_block_number = prev_leaf.value as u32;
                    let last_block_number = if sender_leaf.is_valid {
                        block_number
                    } else {
                        prev_last_block_number
                    };
                    let proof = prev_account_tree
                        .prove_and_update(sender_leaf.sender, last_block_number as u64);
                    account_update_proofs.push(proof);
                }
                Some(account_update_proofs)
            } else {
                None
            }
        };
        ValidityTransitionWitness {
            prev_pis,
            prev_sender_leaves,
            block_merkle_proof,
            account_registoration_proofs,
            account_update_proofs,
        }
    }

    pub fn generate_block_and_witness(
        &self,
        is_registoration_block: bool,
        txs: Vec<TxRequest>,
    ) -> (ValidityWitness, TxTree) {
        let (block_witness, tx_tree) = self.generate_block(is_registoration_block, txs);
        let validity_transition_witness = self.generate_transition_witness();
        // assertion
        let new_roots = validity_transition_witness.new_roots();
        assert_eq!(block_witness.account_tree_root, new_roots.account_tree_root);
        assert_eq!(block_witness.block_tree_root, new_roots.block_tree_root);
        (
            ValidityWitness {
                validity_transition_witness,
                block_witness,
            },
            tx_tree,
        )
    }

    pub fn save_aux_info(
        &mut self,
        block_number: u32,
        tx_tree: TxTree,
        validity_witness: ValidityWitness,
    ) {
        assert_eq!(self.block_witnesses.len(), block_number as usize);
        self.aux_info.insert(
            block_number,
            AuxInfo {
                tx_tree,
                prev_block_witness: self.get_last_block_witness(),
                validity_witness: validity_witness.clone(),
                account_tree: self.account_tree.clone(),
                block_tree: self.block_tree.clone(),
            },
        );
    }

    pub fn update(&mut self, block_witness: &BlockWitness) {
        self.block_witnesses.push(block_witness.clone());
        self.prev_account_tree = self.account_tree.clone();
        self.prev_block_tree = self.block_tree.clone();
        let sender_flag_bits = block_witness.signature.sender_flag.to_bits_le();
        if block_witness.signature.is_registoration_block {
            for (&pubkey, &b) in block_witness.pubkeys.iter().zip(sender_flag_bits.iter()) {
                let last_block_number = if b {
                    block_witness.block.block_number
                } else {
                    0
                };
                let is_dummy_pubkey = pubkey == U256::<u32>::one();
                if !is_dummy_pubkey {
                    self.account_tree
                        .insert(pubkey, last_block_number as u64)
                        .expect("insert failed");
                }
            }
        } else {
            for (&pubkey, &b) in block_witness.pubkeys.iter().zip(sender_flag_bits.iter()) {
                let account_id = self.account_tree.index(pubkey).expect("account not found");
                let prev_last_block_number = self.account_tree.get_leaf(account_id).value as u32;
                let last_block_number = if b {
                    block_witness.block.block_number
                } else {
                    prev_last_block_number
                };
                self.account_tree
                    .update(pubkey, last_block_number as u64)
                    .expect("update failed");
            }
        }
        self.block_tree.push(block_witness.block.hash());
    }

    pub fn post_block(
        &mut self,
        is_registoration_block: bool,
        txs: Vec<TxRequest>,
    ) -> ValidityWitness {
        let (validity_witness, tx_tree) =
            self.generate_block_and_witness(is_registoration_block, txs);
        self.save_aux_info(
            validity_witness.block_witness.block.block_number,
            tx_tree,
            validity_witness.clone(),
        );
        self.update(&validity_witness.block_witness);
        validity_witness
    }
}

fn construct_signature(
    tx_tree_root: Bytes32<u32>,
    pubkey_hash: Bytes32<u32>,
    account_id_hash: Bytes32<u32>,
    is_registoration_block: bool,
    sorted_txs: &[TxRequest],
) -> SignatureContent {
    assert_eq!(sorted_txs.len(), NUM_SENDERS_IN_BLOCK);
    let sender_flag_bits = sorted_txs
        .iter()
        .map(|tx| tx.will_return_signature)
        .collect::<Vec<_>>();
    let sender_flag = U128::from_bits_le(&sender_flag_bits);
    let agg_pubkey_g1 = sorted_txs
        .iter()
        .map(|tx| {
            let weight = hash_to_weight(tx.sender.pubkey_x, pubkey_hash);
            if tx.will_return_signature {
                (tx.sender.pubkey * Fr::from(BigUint::from(weight))).into()
            } else {
                G1Affine::zero()
            }
        })
        .fold(G1Affine::zero(), |acc: G1Affine, x: G1Affine| {
            (acc + x).into()
        });
    let agg_signature_g2 = sorted_txs
        .iter()
        .map(|tx| {
            if tx.will_return_signature {
                sign_to_tx_root(tx.sender.privkey, tx_tree_root, pubkey_hash)
            } else {
                G2Affine::zero()
            }
        })
        .fold(G2Affine::zero(), |acc: G2Affine, x: G2Affine| {
            (acc + x).into()
        });
    // message point
    let tx_tree_root_f = tx_tree_root
        .limbs()
        .iter()
        .map(|x| GoldilocksField::from_canonical_u32(*x))
        .collect::<Vec<_>>();
    let message_point_g2 = G2Target::<GoldilocksField, 2>::hash_to_g2(&tx_tree_root_f);
    assert!(
        Bn254::pairing(agg_pubkey_g1, message_point_g2)
            == Bn254::pairing(G1Affine::generator(), agg_signature_g2)
    );
    let agg_pubkey = [agg_pubkey_g1.x.into(), agg_pubkey_g1.y.into()];
    let agg_signature = [
        agg_signature_g2.x.c0.into(),
        agg_signature_g2.x.c1.into(),
        agg_signature_g2.y.c0.into(),
        agg_signature_g2.y.c1.into(),
    ];
    let message_point = [
        message_point_g2.x.c0.into(),
        message_point_g2.x.c1.into(),
        message_point_g2.y.c0.into(),
        message_point_g2.y.c1.into(),
    ];
    SignatureContent {
        tx_tree_root,
        is_registoration_block,
        sender_flag,
        pubkey_hash,
        account_id_hash,
        agg_pubkey,
        agg_signature,
        message_point,
    }
}

#[cfg(test)]
mod tests {
    use crate::test_utils::tx::generate_random_tx_requests;

    use super::MockBlockBuilder;

    #[test]
    fn block_builder() {
        let mut rng = rand::thread_rng();
        let mut block_builder = MockBlockBuilder::new();
        for _ in 0..10 {
            block_builder.post_block(true, generate_random_tx_requests(&mut rng));
        }
    }
}
