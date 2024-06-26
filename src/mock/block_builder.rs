use ark_bn254::{Bn254, Fr, G1Affine, G2Affine};
use ark_ec::{pairing::Pairing as _, AffineRepr as _};
use num::BigUint;
use plonky2::field::{goldilocks_field::GoldilocksField, types::Field};
use plonky2_bn254::{curves::g2::G2Target, utils::hash_to_g2::HashToG2 as _};
use rand::Rng;

use crate::{
    common::{
        block::Block,
        signature::{
            key_set::KeySet,
            sign::{hash_to_weight, sign_to_tx_root},
            utils::get_pubkey_hash,
            SignatureContent,
        },
        trees::tx_tree::TxTree,
        tx::Tx,
        witness::block_witness::BlockWitness,
    },
    constants::{NUM_SENDERS_IN_BLOCK, TX_TREE_HEIGHT},
    ethereum_types::{
        account_id_packed::AccountIdPacked, bytes32::Bytes32, u128::U128,
        u32limb_trait::U32LimbTrait,
    },
};

use super::db::{BlockInfo, MockDB};

pub struct MockBlockBuilder {}

#[derive(Clone, Debug)]
pub struct TxResuest {
    pub tx: Tx,
    pub sender: KeySet,
    pub will_return_signature: bool,
}

impl TxResuest {
    pub fn dummy() -> Self {
        Self {
            tx: Tx::default(),
            sender: KeySet::dummy(),
            will_return_signature: false,
        }
    }
}

impl MockBlockBuilder {
    pub fn generate_block(
        &self,
        db: &MockDB,
        is_registoration_block: bool,
        txs: Vec<TxResuest>,
    ) -> BlockInfo {
        assert!(txs.len() > 0, "at least one tx is required");
        assert!(txs.len() <= NUM_SENDERS_IN_BLOCK, "too many txs");

        // sort and pad txs
        let mut sorted_txs = txs.clone();
        sorted_txs.sort_by(|a, b| b.sender.pubkey_x.cmp(&a.sender.pubkey_x));
        sorted_txs.resize(NUM_SENDERS_IN_BLOCK, TxResuest::dummy());

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
                    assert!(
                        db.account_tree.index(*pubkey).is_none(),
                        "account already exists"
                    );
                    let proof = db.account_tree.prove_membership(*pubkey);
                    account_membership_proofs.push(proof);
                }
                (None, None, Some(account_membership_proofs))
            } else {
                let mut account_ids = Vec::new();
                let mut account_merkle_proofs = Vec::new();
                for pubkey in pubkeys.iter() {
                    let account_id = db.account_tree.index(*pubkey).expect("account not found");
                    let proof = db.account_tree.prove_inclusion(account_id);
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

        let prev_block = db.get_last_block();
        let block = Block {
            prev_block_hash: prev_block.hash(),
            deposit_tree_root: db.current_deposit_root,
            signature_hash,
            block_number: prev_block.block_number + 1,
        };
        let account_tree_root = db.account_tree.0.get_root();
        let block_hash_tree_root = db.block_hash_tree.get_root();
        let block_witness = BlockWitness {
            block,
            signature: signature.clone(),
            pubkeys: pubkeys.clone(),
            account_tree_root,
            block_hash_tree_root,
            account_id_packed,
            account_merkle_proofs,
            account_membership_proofs,
        };
        let validity_pis = block_witness.to_validity_pis();
        assert!(validity_pis.is_valid_block);
        BlockInfo {
            block_witness,
            tx_tree,
        }
    }

    pub fn update(&self, db: &mut MockDB, block_info: &BlockInfo) {
        db.save_prev_state();
        db.push_block_info(block_info.clone());
        let block_witness = &block_info.block_witness;
        let sender_flag_bits = block_witness.signature.sender_flag.to_bits_le();
        if block_witness.signature.is_registoration_block {
            for (&pubkey, &b) in block_witness.pubkeys.iter().zip(sender_flag_bits.iter()) {
                let last_block_number = if b {
                    block_witness.block.block_number
                } else {
                    0
                };
                db.account_tree
                    .insert(pubkey, last_block_number as u64)
                    .expect("insert failed");
            }
        } else {
            for (&pubkey, &b) in block_witness.pubkeys.iter().zip(sender_flag_bits.iter()) {
                let account_id = db.account_tree.index(pubkey).expect("account not found");
                let prev_last_block_number = db.account_tree.0.get_leaf(account_id).value as u32;
                let last_block_number = if b {
                    block_witness.block.block_number
                } else {
                    prev_last_block_number
                };
                db.account_tree
                    .update(pubkey, last_block_number as u64)
                    .expect("update failed");
            }
        }
        db.block_hash_tree.push(block_witness.block.hash());
    }

    pub fn post_dummy_block<R: Rng>(&self, rng: &mut R, db: &mut MockDB) {
        let txs = (0..NUM_SENDERS_IN_BLOCK)
            .map(|_| {
                let sender = KeySet::rand(rng);
                let tx = Tx::rand(rng);
                TxResuest {
                    tx,
                    sender,
                    will_return_signature: rng.gen(),
                }
            })
            .collect::<Vec<_>>();
        let block_info = self.generate_block(db, true, txs);
        self.update(db, &block_info);
    }
}

fn construct_signature(
    tx_tree_root: Bytes32<u32>,
    pubkey_hash: Bytes32<u32>,
    account_id_hash: Bytes32<u32>,
    is_registoration_block: bool,
    sorted_txs: &[TxResuest],
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
    use super::MockBlockBuilder;

    #[test]
    fn block_builder() {
        let mut rng = rand::thread_rng();
        let mut db = super::MockDB::new();
        let block_builder = MockBlockBuilder {};
        for _ in 0..10 {
            block_builder.post_dummy_block(&mut rng, &mut db);
        }
    }
}
