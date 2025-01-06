use crate::{
    common::signature::{
        key_set::KeySet,
        sign::{hash_to_weight, sign_to_tx_root},
        utils::get_pubkey_hash,
        SignatureContent,
    },
    constants::NUM_SENDERS_IN_BLOCK,
    ethereum_types::{bytes16::Bytes16, bytes32::Bytes32, u32limb_trait::U32LimbTrait as _},
};
use ark_bn254::{Bn254, Fr, G1Affine, G2Affine};
use ark_ec::{pairing::Pairing, AffineRepr as _};
use num::BigUint;
use plonky2::field::{goldilocks_field::GoldilocksField, types::Field as _};
use plonky2_bn254::{curves::g2::G2Target, utils::hash_to_g2::HashToG2 as _};
use rand::Rng;

impl SignatureContent {
    pub fn rand<R: Rng>(rng: &mut R) -> (Vec<KeySet>, Self) {
        let mut key_sets = (0..NUM_SENDERS_IN_BLOCK)
            .map(|_| KeySet::rand(rng))
            .collect::<Vec<_>>();
        // sort by pubkey_x in descending order
        key_sets.sort_by(|a, b| b.pubkey.cmp(&a.pubkey));
        let pubkeys = key_sets
            .iter()
            .map(|keyset| keyset.pubkey)
            .collect::<Vec<_>>();
        let pubkey_hash = get_pubkey_hash(&pubkeys);
        let account_id_hash = Bytes32::rand(rng);
        let tx_tree_root = Bytes32::rand(rng);
        let is_registration_block = rng.gen();
        let sender_flag = Bytes16::rand(rng);
        let sender_flag_bits = sender_flag.to_bits_be();
        let agg_pubkey = key_sets
            .iter()
            .zip(sender_flag_bits.iter())
            .map(|(keyset, b)| {
                let weight = hash_to_weight(keyset.pubkey, pubkey_hash);
                if *b {
                    (keyset.pubkey_g1 * Fr::from(BigUint::from(weight))).into()
                } else {
                    G1Affine::zero()
                }
            })
            .fold(G1Affine::zero(), |acc: G1Affine, x: G1Affine| {
                (acc + x).into()
            });
        let agg_signature = key_sets
            .iter()
            .map(|keyset| sign_to_tx_root(keyset.privkey, tx_tree_root, pubkey_hash))
            .zip(sender_flag_bits.into_iter())
            .fold(
                G2Affine::zero(),
                |acc: G2Affine, (x, b)| {
                    if b {
                        (acc + x).into()
                    } else {
                        acc
                    }
                },
            );
        // message point
        let tx_tree_root_f = tx_tree_root
            .to_u32_vec()
            .iter()
            .map(|x| GoldilocksField::from_canonical_u32(*x))
            .collect::<Vec<_>>();
        let message_point = G2Target::<GoldilocksField, 2>::hash_to_g2(&tx_tree_root_f);
        assert!(
            Bn254::pairing(agg_pubkey, message_point)
                == Bn254::pairing(G1Affine::generator(), agg_signature)
        );
        let signature = Self {
            tx_tree_root,
            expiry: 0.into(),
            is_registration_block,
            sender_flag,
            pubkey_hash,
            account_id_hash,
            agg_pubkey: agg_pubkey.into(),
            agg_signature: agg_signature.into(),
            message_point: message_point.into(),
        };
        (key_sets, signature)
    }
}
