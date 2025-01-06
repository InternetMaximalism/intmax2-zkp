use crate::ethereum_types::{
    bytes32::{Bytes32, Bytes32Target},
    u256::{U256Target, U256},
    u32limb_trait::{U32LimbTargetTrait as _, U32LimbTrait as _},
    u64::{U64Target, U64},
};
use ark_bn254::{Fr, G1Affine, G2Affine};
use ark_ec::AffineRepr;
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
    fields::biguint::{BigUintTarget, CircuitBuilderBiguint},
    utils::hash_to_g2::HashToG2 as _,
};
use plonky2_u32::gadgets::arithmetic_u32::U32Target;

use super::flatten::FlatG2Target;

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
    use ark_bn254::G1Affine;
    use ark_ff::UniformRand;
    use plonky2::{
        field::goldilocks_field::GoldilocksField,
        iop::witness::PartialWitness,
        plonk::{
            circuit_builder::CircuitBuilder, circuit_data::CircuitConfig,
            config::PoseidonGoldilocksConfig,
        },
    };

    use crate::{
        common::signature::utils::get_pubkey_hash,
        constants::NUM_SENDERS_IN_BLOCK,
        ethereum_types::{
            bytes32::Bytes32Target, u256::U256Target, u32limb_trait::U32LimbTargetTrait,
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
}
