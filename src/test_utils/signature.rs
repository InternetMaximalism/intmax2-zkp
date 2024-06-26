use crate::{
    common::signature::{
        key_set::KeySet,
        sign::{hash_to_weight, sign_to_tx_root},
        utils::get_pubkey_hash,
        SignatureContent,
    },
    constants::NUM_SENDERS_IN_BLOCK,
    ethereum_types::{bytes32::Bytes32, u128::U128, u32limb_trait::U32LimbTrait as _},
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
        key_sets.sort_by(|a, b| b.pubkey_x.cmp(&a.pubkey_x));
        let pubkeys = key_sets
            .iter()
            .map(|keyset| keyset.pubkey_x)
            .collect::<Vec<_>>();
        let pubkey_hash = get_pubkey_hash(&pubkeys);
        let account_id_hash = Bytes32::<u32>::rand(rng);
        let tx_tree_root = Bytes32::<u32>::rand(rng);
        let is_registoration_block = rng.gen();
        let sender_flag = U128::rand(rng);
        let sender_flag_bits = sender_flag.to_bits_le();
        let agg_pubkey_g1 = key_sets
            .iter()
            .zip(sender_flag_bits.iter())
            .map(|(keyset, b)| {
                let weight = hash_to_weight(keyset.pubkey_x, pubkey_hash);
                if *b {
                    (keyset.pubkey * Fr::from(BigUint::from(weight))).into()
                } else {
                    G1Affine::zero()
                }
            })
            .fold(G1Affine::zero(), |acc: G1Affine, x: G1Affine| {
                (acc + x).into()
            });
        let agg_signature_g2 = key_sets
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
        let signature = Self {
            tx_tree_root,
            is_registoration_block,
            sender_flag,
            pubkey_hash,
            account_id_hash,
            agg_pubkey,
            agg_signature,
            message_point,
        };
        (key_sets, signature)
    }
}

#[cfg(test)]
mod tests {
    use crate::common::signature::SignatureContent;

    #[test]
    fn random_signature() {
        let rng = &mut rand::thread_rng();
        let _signature = SignatureContent::rand(rng);
    }
}
