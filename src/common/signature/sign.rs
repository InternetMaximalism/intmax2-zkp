use crate::ethereum_types::{
    bytes32::{Bytes32, Bytes32Target},
    u256::{U256Target, U256},
    u32limb_trait::{U32LimbTargetTrait as _, U32LimbTrait as _},
    u64::{U64Target, U64},
};
use ark_bn254::{Bn254, Fr, G1Affine, G1Projective, G2Affine};
use ark_ec::{pairing::Pairing, AffineRepr};
use num::{BigUint, One, Zero as _};
use plonky2::{
    field::{extension::Extendable, goldilocks_field::GoldilocksField, types::Field as _},
    hash::{hash_types::RichField, poseidon::PoseidonHash},
    iop::{
        challenger::{Challenger, RecursiveChallenger},
        target::Target,
    },
    plonk::{
        circuit_builder::CircuitBuilder,
        config::{AlgebraicHasher, GenericConfig},
    },
};
use plonky2_bn254::{
    curves::g2::G2Target,
    fields::{
        biguint::{BigUintTarget, CircuitBuilderBiguint},
        recover::RecoverFromX,
    },
    utils::hash_to_g2::HashToG2 as _,
};
use plonky2_keccak::utils::solidity_keccak256;
use plonky2_u32::gadgets::arithmetic_u32::U32Target;

use super::flatten::FlatG2Target;

fn check_pairing(g1s: &[G1Affine], g2s: &[G2Affine]) -> bool {
    Bn254::multi_pairing(g1s, g2s).is_zero()
}

// 10*1 padding
fn pad_10star1(input: &[u8]) -> Vec<u8> {
    const WINDOW_SIZE: usize = 4;

    let mut padded = input.to_vec();
    padded.push(0b10000000);
    while padded.len() % WINDOW_SIZE != WINDOW_SIZE - 1 {
        padded.push(0);
    }
    padded.push(1);

    padded
}

fn sign_u32_limbs(privkey: Fr, message: &[u32]) -> G2Affine {
    let elements = message
        .iter()
        .map(|x| GoldilocksField::from_canonical_u32(*x))
        .collect::<Vec<_>>();
    let message_g2 = G2Target::<GoldilocksField, 2>::hash_to_g2(&elements);
    let signature: G2Affine = (message_g2 * privkey).into();

    signature
}

fn verify_u32_limbs(signature_g2: G2Affine, pubkey: U256, message: &[u32]) -> anyhow::Result<()> {
    let elements = message
        .iter()
        .map(|x| GoldilocksField::from_canonical_u32(*x))
        .collect::<Vec<_>>();
    let message_g2 = G2Target::<GoldilocksField, 2>::hash_to_g2(&elements);

    let pubkey_g1 = G1Affine::recover_from_x(pubkey.into());
    let g1_generator_inv = -G1Affine::generator();
    if !check_pairing(&[g1_generator_inv, pubkey_g1], &[signature_g2, message_g2]) {
        anyhow::bail!("Invalid signature");
    }

    Ok(())
}

pub fn sign_message(privkey: Fr, message: &[u8]) -> G2Affine {
    let padded_message = pad_10star1(message);
    debug_assert!(padded_message.len() % 4 == 0);
    let limbs = padded_message
        .chunks(4)
        .map(|c| u32::from_be_bytes(c.try_into().unwrap()))
        .collect::<Vec<_>>();

    sign_u32_limbs(privkey, &limbs)
}

pub fn verify_signature(signature: G2Affine, pubkey: U256, message: &[u8]) -> anyhow::Result<()> {
    let padded_message = pad_10star1(message);
    debug_assert!(padded_message.len() % 4 == 0);
    let limbs = padded_message
        .chunks(4)
        .map(|c| u32::from_be_bytes(c.try_into().unwrap()))
        .collect::<Vec<_>>();

    verify_u32_limbs(signature, pubkey, &limbs)
}

pub fn get_pubkey_hash(pubkeys: &[U256]) -> Bytes32 {
    let pubkey_flattened = pubkeys
        .iter()
        .flat_map(|x| x.to_u32_vec())
        .collect::<Vec<_>>();
    Bytes32::from_u32_slice(&solidity_keccak256(&pubkey_flattened))
}

pub fn weight_to_signature(signature: G2Affine, pubkey: U256, signers: Vec<U256>) -> G2Affine {
    let pubkey = G1Affine::recover_from_x(pubkey.into());
    let pubkey_x: U256 = pubkey.x.into();
    let pubkey_hash = get_pubkey_hash(&signers);
    let weight = hash_to_weight(pubkey_x, pubkey_hash);

    (signature * Fr::from(BigUint::from(weight))).into()
}

pub fn sign_message_with_signers(privkey: Fr, message: &[u8], signers: Vec<U256>) -> G2Affine {
    let signature: G2Affine = sign_message(privkey, message);
    let pubkey: G1Affine = (G1Affine::generator() * privkey).into();
    let pubkey_x: U256 = pubkey.x.into();

    weight_to_signature(signature, pubkey_x, signers)
}

pub fn calc_aggregated_pubkey(signers: &[U256]) -> U256 {
    let pubkey_hash = get_pubkey_hash(signers);
    let mut aggregated_pubkey = G1Projective::zero();
    for signer in signers {
        let signer_g1 = G1Affine::recover_from_x((*signer).into());
        let signer_x: U256 = signer_g1.x.into();
        let weight = hash_to_weight(signer_x, pubkey_hash);
        let weight_pubkey = signer_g1 * Fr::from(BigUint::from(weight));
        aggregated_pubkey += weight_pubkey;
    }

    let pubkey: G1Affine = aggregated_pubkey.into();

    U256::from(pubkey.x)
}

pub fn verify_signature_with_signers(
    signature: G2Affine,
    message: &[u8],
    signers: Vec<U256>,
) -> anyhow::Result<()> {
    let aggregated_pubkey = calc_aggregated_pubkey(&signers);

    verify_signature(signature, aggregated_pubkey, message)
}

pub fn sign_to_tx_root_and_expiry(
    privkey: Fr,
    tx_tree_root: Bytes32,
    expiry: u64,
    pubkey_hash: Bytes32,
) -> G2Affine {
    let pubkey: G1Affine = (G1Affine::generator() * privkey).into();
    let pubkey_x: U256 = pubkey.x.into();
    let weight = hash_to_weight(pubkey_x, pubkey_hash);
    let message_point = tx_tree_root_and_expiry_to_message_point(tx_tree_root, expiry.into());

    (message_point * privkey * Fr::from(BigUint::from(weight))).into()
}

pub fn hash_to_weight(my_pubkey: U256, pubkey_hash: Bytes32) -> U256 {
    type F = GoldilocksField;
    let flattened = my_pubkey
        .to_u32_vec()
        .into_iter()
        .chain(pubkey_hash.to_u32_vec())
        .map(|x| F::from_canonical_u32(x))
        .collect::<Vec<_>>();
    let mut challenger = Challenger::<F, PoseidonHash>::new();
    challenger.observe_elements(&flattened);
    let output = challenger.get_n_challenges(16);
    f_slice_to_biguint(&output).try_into().unwrap()
}

pub(crate) fn hash_to_weight_circuit<F: RichField + Extendable<D>, const D: usize>(
    builder: &mut CircuitBuilder<F, D>,
    my_pubkey: U256Target,
    pubkey_hash: Bytes32Target,
) -> U256Target {
    let flattened = my_pubkey
        .to_vec()
        .into_iter()
        .chain(pubkey_hash.to_vec())
        .map(|x| x)
        .collect::<Vec<_>>();
    let mut challenger = RecursiveChallenger::<F, PoseidonHash, D>::new(builder);
    challenger.observe_elements(&flattened);
    let output = challenger.get_n_challenges(builder, 16);
    let output = target_slice_to_biguint_target(builder, &output);

    U256Target::from_slice(
        &output
            .limbs
            .into_iter()
            .map(|x| x.0)
            .rev()
            .collect::<Vec<_>>(),
    )
}

pub fn tx_tree_root_and_expiry_to_message_point(tx_tree_root: Bytes32, expiry: U64) -> G2Affine {
    let elements = tx_tree_root
        .to_u32_vec()
        .iter()
        .chain(expiry.to_u32_vec().iter())
        .map(|x| GoldilocksField::from_canonical_u32(*x))
        .collect::<Vec<_>>();
    let message_point = G2Target::<GoldilocksField, 2>::hash_to_g2(&elements);
    message_point
}

pub fn tx_tree_root_and_expiry_to_message_point_target<
    F: RichField + Extendable<D>,
    C: GenericConfig<D, F = F> + 'static,
    const D: usize,
>(
    builder: &mut CircuitBuilder<F, D>,
    tx_tree_root: Bytes32Target,
    expiry: U64Target,
) -> FlatG2Target
where
    <C as GenericConfig<D>>::Hasher: AlgebraicHasher<F>,
{
    let elements = tx_tree_root
        .to_vec()
        .iter()
        .chain(expiry.to_vec().iter())
        .cloned()
        .collect::<Vec<_>>();
    let message_point: FlatG2Target =
        G2Target::<F, D>::hash_to_g2_circuit::<C>(builder, &elements).into();
    message_point
}

fn f_slice_to_biguint<F: RichField>(input: &[F]) -> BigUint {
    let limbs = input
        .iter()
        .map(|c| {
            let x = c.to_canonical_u64();
            // discard the high bits because it's not uniformally distributed
            x as u32
        })
        .collect::<Vec<_>>();
    let mut value = BigUint::zero();
    for (i, limb) in limbs.iter().enumerate() {
        value += BigUint::from(*limb) << (i * 32);
    }
    let r = BigUint::from(Fr::from(-1)) + BigUint::one();
    value % r
}

fn target_slice_to_biguint_target<F: RichField + Extendable<D>, const D: usize>(
    builder: &mut CircuitBuilder<F, D>,
    input: &[Target],
) -> BigUintTarget {
    let limbs = input
        .iter()
        .map(|c| {
            let (lo, _hi) = builder.split_low_high(*c, 32, 64);
            // discard the high bits because it's not uniformly distributed
            U32Target(lo)
        })
        .collect::<Vec<_>>();
    let r = BigUint::from(Fr::from(-1)) + BigUint::one();
    let value = BigUintTarget { limbs };
    builder.div_rem_biguint(&value, &r).1
}

#[cfg(test)]
mod tests {
    use ark_bn254::{G1Affine, G2Affine, G2Projective};
    use ark_ff::UniformRand;
    use num::Zero as _;
    use plonky2::{
        field::goldilocks_field::GoldilocksField,
        iop::witness::PartialWitness,
        plonk::{
            circuit_builder::CircuitBuilder, circuit_data::CircuitConfig,
            config::PoseidonGoldilocksConfig,
        },
    };

    use crate::{
        common::signature::{
            flatten::FlatG2,
            key_set::KeySet,
            sign::{
                sign_message, sign_message_with_signers, sign_u32_limbs, verify_signature,
                verify_signature_with_signers, verify_u32_limbs, weight_to_signature,
            },
            utils::get_pubkey_hash,
        },
        constants::NUM_SENDERS_IN_BLOCK,
        ethereum_types::{
            bytes32::Bytes32Target,
            u256::{U256Target, U256},
            u32limb_trait::U32LimbTargetTrait,
        },
    };

    use super::{hash_to_weight, hash_to_weight_circuit};

    type F = GoldilocksField;
    const D: usize = 2;
    type C = PoseidonGoldilocksConfig;

    #[test]
    fn test_hash_to_weight() {
        let rng = &mut rand::thread_rng();
        let pubkeys_g1 = (0..NUM_SENDERS_IN_BLOCK)
            .map(|_| G1Affine::rand(rng))
            .collect::<Vec<_>>();
        let pubkeys = pubkeys_g1.iter().map(|x| x.x.into()).collect::<Vec<_>>();
        let pubkey_hash = get_pubkey_hash(&pubkeys);
        let my_pubkey = pubkeys[0];
        let weight = hash_to_weight(my_pubkey, pubkey_hash);
        let mut builder = CircuitBuilder::<F, D>::new(CircuitConfig::default());
        let my_pubkey_t = U256Target::constant(&mut builder, my_pubkey);
        let pubkey_hash_t = Bytes32Target::constant(&mut builder, pubkey_hash);
        let weight_t = hash_to_weight_circuit(&mut builder, my_pubkey_t, pubkey_hash_t);
        let mut pw = PartialWitness::new();
        weight_t.set_witness(&mut pw, weight);
        let circuit = builder.build::<C>();
        let proof = circuit.prove(pw).unwrap();
        assert!(circuit.verify(proof).is_ok());
    }

    #[test]
    fn test_verify_signature_to_u32_limbs() {
        let rng = &mut rand::thread_rng();
        let key = KeySet::rand(rng);
        let message = [1, 2, 3, 4];
        let signature = sign_u32_limbs(key.privkey, &message);
        assert!(verify_u32_limbs(signature.into(), key.pubkey, &message).is_ok());
    }

    #[test]
    fn test_verify_signature() {
        let rng = &mut rand::thread_rng();
        let key = KeySet::rand(rng);
        let message = b"hello world";
        let signature = sign_message(key.privkey, message);
        assert!(verify_signature(signature.into(), key.pubkey, message).is_ok());
    }

    // TODO: fail sometimes
    #[test]
    fn test_verify_signature_with_signers() {
        let rng = &mut rand::thread_rng();
        let keys = (0..1).map(|_| KeySet::rand(rng)).collect::<Vec<_>>();
        let signers = keys.iter().map(|key| key.pubkey).collect::<Vec<_>>();
        let message = b"hello world";
        let mut signatures = vec![];
        for key in keys.iter() {
            let signature = sign_message_with_signers(key.privkey, message, signers.clone());
            signatures.push(signature);
        }
        let aggregated_signature = signatures.iter().zip(keys.iter()).fold(
            G2Projective::zero(),
            |acc, (signature, key)| {
                let pubkey_x: U256 = key.pubkey_g1.x.into();

                let x = weight_to_signature(*signature, pubkey_x, signers.clone());

                acc + x
            },
        );
        for signature in signatures.iter() {
            println!("{:?}", FlatG2::from(G2Affine::from(*signature)));
        }
        println!("{:?}", FlatG2::from(G2Affine::from(aggregated_signature)));
        for signer in signers.iter() {
            println!("{:?}", signer);
        }
        let aggregated_pubkey = super::calc_aggregated_pubkey(&signers);
        println!("{:?}", aggregated_pubkey);

        let success = verify_signature_with_signers(aggregated_signature.into(), message, signers);
        println!("{:?}", success);
        assert!(success.is_ok());
    }

    #[test]
    #[should_panic]
    fn test_fail_to_verify_signature_with_signers() {
        let rng = &mut rand::thread_rng();
        let keys = (0..3).map(|_| KeySet::rand(rng)).collect::<Vec<_>>();
        let signers = keys.iter().map(|key| key.pubkey).collect::<Vec<_>>();
        let message = b"hello world";
        let mut signatures = vec![];
        for key in keys.iter() {
            let signature = sign_message_with_signers(key.privkey, message, signers.clone());
            signatures.push(signature);
        }
        let aggregated_signature = signatures
            .iter()
            .fold(G2Projective::zero(), |acc, x| acc + x);

        let wrong_signers = [signers, vec![keys[0].pubkey]].concat();
        verify_signature_with_signers(aggregated_signature.into(), message, wrong_signers).unwrap();
    }
}
