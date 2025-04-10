use crate::{
    common::signature::{
        block_sign_payload::{hash_to_weight, BlockSignPayload},
        key_set::KeySet,
        utils::get_pubkey_hash,
        SignatureContent,
    },
    constants::NUM_SENDERS_IN_BLOCK,
    ethereum_types::{bytes16::Bytes16, bytes32::Bytes32, u32limb_trait::U32LimbTrait as _},
};
use ark_bn254::{Bn254, Fr, G1Affine, G2Affine};
use ark_ec::{pairing::Pairing, AffineRepr as _};
use num::BigUint;
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
        let sender_flag = Bytes16::rand(rng);
        let sender_flag_bits = sender_flag.to_bits_be();

        let block_sign_payload = BlockSignPayload::rand(rng);
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
            .map(|keyset| G2Affine::from(block_sign_payload.sign(keyset.privkey, pubkey_hash)))
            .zip(sender_flag_bits)
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
        let message_point = block_sign_payload.message_point();
        assert!(
            Bn254::pairing(agg_pubkey, G2Affine::from(message_point.clone()))
                == Bn254::pairing(G1Affine::generator(), agg_signature)
        );
        let signature = Self {
            block_sign_payload,
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
