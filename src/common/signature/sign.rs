use crate::ethereum_types::{
    bytes32::Bytes32,
    u256::U256,
    u32limb_trait::{U32LimbTargetTrait as _, U32LimbTrait as _},
};
use ark_bn254::{Fr, G1Affine, G2Affine};
use ark_ec::AffineRepr;
use num::{BigUint, Zero as _};
use plonky2::{
    field::{extension::Extendable, goldilocks_field::GoldilocksField, types::Field as _},
    hash::{hash_types::RichField, poseidon::PoseidonHash},
    iop::{
        challenger::{Challenger, RecursiveChallenger},
        target::Target,
    },
    plonk::circuit_builder::CircuitBuilder,
};
use plonky2_bn254::{
    curves::g2::G2Target, fields::biguint::BigUintTarget, utils::hash_to_g2::HashToG2 as _,
};
use plonky2_u32::gadgets::arithmetic_u32::U32Target;

pub fn sign_to_tx_root(
    privkey: Fr,
    tx_tree_root: Bytes32<u32>,
    pubkey_hash: Bytes32<u32>,
) -> G2Affine {
    let pubkey: G1Affine = (G1Affine::generator() * privkey).into();
    let pubkey_x: U256<u32> = pubkey.x.into();
    let weight = hash_to_weight(pubkey_x, pubkey_hash);

    // message point
    let tx_tree_root = tx_tree_root
        .limbs()
        .iter()
        .map(|x| GoldilocksField::from_canonical_u32(*x))
        .collect::<Vec<_>>();
    let message_point = G2Target::<GoldilocksField, 2>::hash_to_g2(&tx_tree_root);
    (message_point * privkey * Fr::from(BigUint::from(weight))).into()
}

pub(crate) fn hash_to_weight(my_pubkey: U256<u32>, pubkey_hash: Bytes32<u32>) -> U256<u32> {
    type F = GoldilocksField;
    let flattened = my_pubkey
        .limbs()
        .into_iter()
        .chain(pubkey_hash.limbs())
        .map(|x| F::from_canonical_u32(x))
        .collect::<Vec<_>>();
    let mut challenger = Challenger::<F, PoseidonHash>::new();
    challenger.observe_elements(&flattened);
    let output = challenger.get_n_challenges(8);
    f_slice_to_biguint(&output).try_into().unwrap()
}

pub(crate) fn hash_to_weight_circuit<F: RichField + Extendable<D>, const D: usize>(
    builder: &mut CircuitBuilder<F, D>,
    my_pubkey: U256<Target>,
    pubkey_hash: Bytes32<Target>,
) -> U256<Target> {
    let flattened = my_pubkey
        .limbs()
        .into_iter()
        .chain(pubkey_hash.limbs())
        .map(|x| x)
        .collect::<Vec<_>>();
    let mut challenger = RecursiveChallenger::<F, PoseidonHash, D>::new(builder);
    challenger.observe_elements(&flattened);
    let output = challenger.get_n_challenges(builder, 8);
    let output = target_slice_to_biguint_target(builder, &output);

    U256::<Target>::from_limbs(
        &output
            .limbs
            .into_iter()
            .map(|x| x.0)
            .rev()
            .collect::<Vec<_>>(),
    )
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
    value
}

fn target_slice_to_biguint_target<F: RichField + Extendable<D>, const D: usize>(
    builder: &mut CircuitBuilder<F, D>,
    input: &[Target],
) -> BigUintTarget {
    let limbs = input
        .iter()
        .map(|c| {
            let (lo, _hi) = builder.split_low_high(*c, 32, 64);
            // discard the high bits because it's not uniformally distributed
            U32Target(lo)
        })
        .collect::<Vec<_>>();
    BigUintTarget { limbs }
}

#[cfg(test)]
mod tests {
    use ark_bn254::G1Affine;
    use ark_ff::UniformRand;
    use plonky2::{
        field::goldilocks_field::GoldilocksField,
        iop::{target::Target, witness::PartialWitness},
        plonk::{
            circuit_builder::CircuitBuilder, circuit_data::CircuitConfig,
            config::PoseidonGoldilocksConfig,
        },
    };

    use crate::{
        common::signature::utils::get_pubkey_hash,
        constants::NUM_SENDERS_IN_BLOCK,
        ethereum_types::{bytes32::Bytes32, u256::U256, u32limb_trait::U32LimbTargetTrait},
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
        let my_pubkey_t = U256::<Target>::constant(&mut builder, my_pubkey);
        let pubkey_hash_t = Bytes32::<Target>::constant(&mut builder, pubkey_hash);
        let weight_t = hash_to_weight_circuit(&mut builder, my_pubkey_t, pubkey_hash_t);
        let mut pw = PartialWitness::new();
        weight_t.set_witness(&mut pw, weight);
        let circuit = builder.build::<C>();
        let proof = circuit.prove(pw).unwrap();
        assert!(circuit.verify(proof).is_ok());
    }
}
