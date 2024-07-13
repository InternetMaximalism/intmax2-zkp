use plonky2::{
    field::{extension::Extendable, types::Field},
    hash::hash_types::RichField,
    iop::{
        target::{BoolTarget, Target},
        witness::WitnessWrite,
    },
    plonk::{
        circuit_builder::CircuitBuilder,
        config::{AlgebraicHasher, GenericConfig},
    },
};
use plonky2_keccak::{builder::BuilderKeccak256 as _, utils::solidity_keccak256};

use super::poseidon_hash_out::{PoseidonHashOut, PoseidonHashOutTarget};
use crate::ethereum_types::{
    bytes32::Bytes32,
    u32limb_trait::{U32LimbTargetTrait as _, U32LimbTrait as _},
};
use core::fmt::Debug;

pub trait LeafableHasher: Debug + Clone {
    type HashOut: Clone + Copy + Debug + Default + PartialEq;
    type HashOutTarget: Clone + Debug;

    fn two_to_one(left: Self::HashOut, right: Self::HashOut) -> Self::HashOut;

    fn hash_out_target<F: RichField + Extendable<D>, const D: usize>(
        builder: &mut CircuitBuilder<F, D>,
    ) -> Self::HashOutTarget;

    fn constant_hash_out_target<F: RichField + Extendable<D>, const D: usize>(
        builder: &mut CircuitBuilder<F, D>,
        value: Self::HashOut,
    ) -> Self::HashOutTarget;

    fn set_hash_out_target<W: WitnessWrite<F>, F: Field>(
        target: &Self::HashOutTarget,
        witness: &mut W,
        value: Self::HashOut,
    );

    fn connect_hash<F: RichField + Extendable<D>, const D: usize>(
        builder: &mut CircuitBuilder<F, D>,
        x: &Self::HashOutTarget,
        y: &Self::HashOutTarget,
    );

    fn conditional_assert_eq_hash<F: RichField + Extendable<D>, const D: usize>(
        builder: &mut CircuitBuilder<F, D>,
        condition: BoolTarget,
        x: &Self::HashOutTarget,
        y: &Self::HashOutTarget,
    );

    // Generic `C` is used for keccak256
    fn two_to_one_target<
        F: RichField + Extendable<D>,
        C: GenericConfig<D, F = F> + 'static,
        const D: usize,
    >(
        builder: &mut CircuitBuilder<F, D>,
        left: &Self::HashOutTarget,
        right: &Self::HashOutTarget,
    ) -> Self::HashOutTarget
    where
        <C as GenericConfig<D>>::Hasher: AlgebraicHasher<F>;

    // Generic `C` is used for keccak256
    fn two_to_one_swapped<
        F: RichField + Extendable<D>,
        C: GenericConfig<D, F = F> + 'static,
        const D: usize,
    >(
        builder: &mut CircuitBuilder<F, D>,
        left: &Self::HashOutTarget,
        right: &Self::HashOutTarget,
        swap: BoolTarget,
    ) -> Self::HashOutTarget
    where
        <C as GenericConfig<D>>::Hasher: AlgebraicHasher<F>;
}

#[derive(Debug, Clone)]
pub struct PoseidonLeafableHasher;

impl LeafableHasher for PoseidonLeafableHasher {
    type HashOut = PoseidonHashOut;
    type HashOutTarget = PoseidonHashOutTarget;

    fn two_to_one(left: Self::HashOut, right: Self::HashOut) -> Self::HashOut {
        let inputs = left
            .to_u64_vec()
            .into_iter()
            .chain(right.to_u64_vec().into_iter())
            .collect::<Vec<_>>();
        PoseidonHashOut::hash_inputs_u64(&inputs)
    }

    fn hash_out_target<F: RichField + Extendable<D>, const D: usize>(
        builder: &mut CircuitBuilder<F, D>,
    ) -> Self::HashOutTarget {
        PoseidonHashOutTarget::new(builder)
    }

    fn constant_hash_out_target<F: RichField + Extendable<D>, const D: usize>(
        builder: &mut CircuitBuilder<F, D>,
        value: PoseidonHashOut,
    ) -> Self::HashOutTarget {
        PoseidonHashOutTarget::constant(builder, value)
    }

    fn set_hash_out_target<W: WitnessWrite<F>, F: Field>(
        target: &Self::HashOutTarget,
        witness: &mut W,
        value: PoseidonHashOut,
    ) {
        target.set_witness(witness, value)
    }

    fn connect_hash<F: RichField + Extendable<D>, const D: usize>(
        builder: &mut CircuitBuilder<F, D>,
        x: &Self::HashOutTarget,
        y: &Self::HashOutTarget,
    ) {
        x.connect(builder, *y)
    }

    fn conditional_assert_eq_hash<F: RichField + Extendable<D>, const D: usize>(
        builder: &mut CircuitBuilder<F, D>,
        condition: BoolTarget,
        x: &Self::HashOutTarget,
        y: &Self::HashOutTarget,
    ) {
        x.conditional_assert_eq(builder, *y, condition)
    }

    fn two_to_one_target<
        F: RichField + Extendable<D>,
        C: GenericConfig<D, F = F> + 'static,
        const D: usize,
    >(
        builder: &mut CircuitBuilder<F, D>,
        left: &Self::HashOutTarget,
        right: &Self::HashOutTarget,
    ) -> PoseidonHashOutTarget
    where
        <C as GenericConfig<D>>::Hasher: AlgebraicHasher<F>,
    {
        PoseidonHashOutTarget::two_to_one(builder, *left, *right)
    }

    fn two_to_one_swapped<
        F: RichField + Extendable<D>,
        C: GenericConfig<D, F = F> + 'static,
        const D: usize,
    >(
        builder: &mut CircuitBuilder<F, D>,
        left: &Self::HashOutTarget,
        right: &Self::HashOutTarget,
        swap: BoolTarget,
    ) -> Self::HashOutTarget
    where
        <C as GenericConfig<D>>::Hasher: AlgebraicHasher<F>,
    {
        PoseidonHashOutTarget::two_to_one_swapped(builder, *left, *right, swap)
    }
}

#[derive(Debug, Clone)]
pub struct KeccakLeafableHasher;

impl LeafableHasher for KeccakLeafableHasher {
    type HashOut = Bytes32<u32>;
    type HashOutTarget = Bytes32<Target>;

    fn two_to_one(left: Self::HashOut, right: Self::HashOut) -> Self::HashOut {
        let inputs = vec![left.limbs(), right.limbs()].concat();
        Bytes32::<u32>::from_limbs(&solidity_keccak256(&inputs))
    }

    fn connect_hash<F: RichField + Extendable<D>, const D: usize>(
        builder: &mut plonky2::plonk::circuit_builder::CircuitBuilder<F, D>,
        x: &Self::HashOutTarget,
        y: &Self::HashOutTarget,
    ) {
        x.connect(builder, *y)
    }

    fn conditional_assert_eq_hash<F: RichField + Extendable<D>, const D: usize>(
        builder: &mut plonky2::plonk::circuit_builder::CircuitBuilder<F, D>,
        condition: BoolTarget,
        x: &Self::HashOutTarget,
        y: &Self::HashOutTarget,
    ) {
        x.conditional_assert_eq(builder, *y, condition)
    }

    fn two_to_one_target<
        F: RichField + Extendable<D>,
        C: GenericConfig<D, F = F> + 'static,
        const D: usize,
    >(
        builder: &mut CircuitBuilder<F, D>,
        left: &Self::HashOutTarget,
        right: &Self::HashOutTarget,
    ) -> Self::HashOutTarget
    where
        <C as GenericConfig<D>>::Hasher: AlgebraicHasher<F>,
    {
        let input = vec![left.limbs(), right.limbs()].concat();
        Bytes32::<Target>::from_limbs(&builder.keccak256::<C>(&input))
    }

    fn two_to_one_swapped<
        F: RichField + Extendable<D>,
        C: GenericConfig<D, F = F> + 'static,
        const D: usize,
    >(
        builder: &mut CircuitBuilder<F, D>,
        left: &Self::HashOutTarget,
        right: &Self::HashOutTarget,
        swap: BoolTarget,
    ) -> Self::HashOutTarget
    where
        <C as GenericConfig<D>>::Hasher: AlgebraicHasher<F>,
    {
        let left_swapped = Bytes32::<Target>::select(builder, swap, *right, *left);
        let right_swapped = Bytes32::<Target>::select(builder, swap, *left, *right);
        Self::two_to_one_target::<F, C, D>(builder, &left_swapped, &right_swapped)
    }

    fn hash_out_target<F: RichField + Extendable<D>, const D: usize>(
        builder: &mut CircuitBuilder<F, D>,
    ) -> Self::HashOutTarget {
        Bytes32::<Target>::new(builder, false)
    }

    fn constant_hash_out_target<F: RichField + Extendable<D>, const D: usize>(
        builder: &mut CircuitBuilder<F, D>,
        value: Self::HashOut,
    ) -> Self::HashOutTarget {
        Bytes32::<Target>::constant(builder, value)
    }

    fn set_hash_out_target<
        W: plonky2::iop::witness::WitnessWrite<F>,
        F: plonky2::field::types::Field,
    >(
        target: &Self::HashOutTarget,
        witness: &mut W,
        value: Self::HashOut,
    ) {
        target.set_witness(witness, value)
    }
}
