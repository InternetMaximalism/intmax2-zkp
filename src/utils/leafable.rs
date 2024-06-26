use std::fmt::Debug;

use crate::ethereum_types::{
    bytes32::Bytes32,
    u256::U256,
    u32limb_trait::{U32LimbTargetTrait as _, U32LimbTrait},
};
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

use super::poseidon_hash_out::{PoseidonHashOut, PoseidonHashOutTarget};

/// Can be a leaf of Merkle trees.
pub trait Leafable: Clone {
    type HashOut: Clone + Copy + Debug + PartialEq;

    /// Default hash which indicates empty value.
    fn empty_leaf() -> Self;

    /// Hash of its value.
    fn hash(&self) -> Self::HashOut;

    fn two_to_one(left: Self::HashOut, right: Self::HashOut) -> Self::HashOut;
}

/// Can be a leaf target of Merkle trees.
pub trait LeafableTarget: Clone {
    type Leaf: Leafable;
    type HashOutTarget: Clone + Debug;

    fn hash_out_target<F: RichField + Extendable<D>, const D: usize>(
        builder: &mut CircuitBuilder<F, D>,
    ) -> Self::HashOutTarget;

    fn constant_hash_out_target<F: RichField + Extendable<D>, const D: usize>(
        builder: &mut CircuitBuilder<F, D>,
        value: <Self::Leaf as Leafable>::HashOut,
    ) -> Self::HashOutTarget;

    fn set_hash_out_target<W: WitnessWrite<F>, F: Field>(
        target: &Self::HashOutTarget,
        witness: &mut W,
        value: <Self::Leaf as Leafable>::HashOut,
    );

    /// Default constant hash target which indicates empty value.
    fn empty_leaf<F: RichField + Extendable<D>, const D: usize>(
        builder: &mut CircuitBuilder<F, D>,
    ) -> Self;

    /// Hash target of its value.
    // Generic `C` is used for keccak256
    fn hash<F: RichField + Extendable<D>, C: GenericConfig<D, F = F> + 'static, const D: usize>(
        &self,
        builder: &mut CircuitBuilder<F, D>,
    ) -> Self::HashOutTarget
    where
        <C as GenericConfig<D>>::Hasher: AlgebraicHasher<F>;

    fn connect_hash<F: RichField + Extendable<D>, const D: usize>(
        builder: &mut CircuitBuilder<F, D>,
        x: &Self::HashOutTarget,
        y: &Self::HashOutTarget,
    );

    // Generic `C` is used for keccak256
    fn two_to_one<
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

/*
 * Leafable for PoseidonHashOut
 */
impl Leafable for PoseidonHashOut {
    type HashOut = PoseidonHashOut;

    fn empty_leaf() -> Self {
        Self::default()
    }

    // Output as is in the case of a hash.
    fn hash(&self) -> Self {
        *self
    }

    fn two_to_one(left: PoseidonHashOut, right: PoseidonHashOut) -> Self {
        let inputs = left
            .elements
            .into_iter()
            .chain(right.elements.into_iter())
            .collect::<Vec<_>>();
        PoseidonHashOut::hash_inputs_u64(&inputs)
    }
}

impl LeafableTarget for PoseidonHashOutTarget {
    type Leaf = PoseidonHashOut;
    type HashOutTarget = PoseidonHashOutTarget;

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

    fn empty_leaf<F: RichField + Extendable<D>, const D: usize>(
        builder: &mut CircuitBuilder<F, D>,
    ) -> Self {
        let empty_leaf = <PoseidonHashOut as Leafable>::empty_leaf();
        PoseidonHashOutTarget::constant(builder, empty_leaf)
    }

    fn hash<F: RichField + Extendable<D>, C: GenericConfig<D, F = F> + 'static, const D: usize>(
        &self,
        _builder: &mut CircuitBuilder<F, D>,
    ) -> PoseidonHashOutTarget
    where
        <C as GenericConfig<D>>::Hasher: AlgebraicHasher<F>,
    {
        *self
    }

    fn connect_hash<F: RichField + Extendable<D>, const D: usize>(
        builder: &mut CircuitBuilder<F, D>,
        x: &Self::HashOutTarget,
        y: &Self::HashOutTarget,
    ) {
        x.connect(builder, *y)
    }

    fn two_to_one<
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

/*
 * Leafable for Bytes32<u32>
 */
impl Leafable for Bytes32<u32> {
    type HashOut = PoseidonHashOut;

    fn empty_leaf() -> Self {
        Bytes32::default()
    }

    fn hash(&self) -> PoseidonHashOut {
        PoseidonHashOut::hash_inputs_u32(&self.limbs())
    }

    fn two_to_one(left: Self::HashOut, right: Self::HashOut) -> Self::HashOut {
        let inputs = left
            .elements
            .into_iter()
            .chain(right.elements.into_iter())
            .collect::<Vec<_>>();
        PoseidonHashOut::hash_inputs_u64(&inputs)
    }
}

impl LeafableTarget for Bytes32<Target> {
    type Leaf = Bytes32<u32>;
    type HashOutTarget = PoseidonHashOutTarget;

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

    fn empty_leaf<F: RichField + Extendable<D>, const D: usize>(
        builder: &mut CircuitBuilder<F, D>,
    ) -> Self {
        let empty_leaf = <Bytes32<u32> as Leafable>::empty_leaf();
        Bytes32::<Target>::constant(builder, empty_leaf)
    }

    fn hash<F: RichField + Extendable<D>, C: GenericConfig<D, F = F> + 'static, const D: usize>(
        &self,
        builder: &mut CircuitBuilder<F, D>,
    ) -> PoseidonHashOutTarget
    where
        <C as GenericConfig<D>>::Hasher: AlgebraicHasher<F>,
    {
        PoseidonHashOutTarget::hash_inputs(builder, &self.limbs())
    }

    fn connect_hash<F: RichField + Extendable<D>, const D: usize>(
        builder: &mut CircuitBuilder<F, D>,
        x: &Self::HashOutTarget,
        y: &Self::HashOutTarget,
    ) {
        x.connect(builder, *y)
    }

    fn two_to_one<
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

/*
 * Leafable for U256<u32>
 */
impl Leafable for U256<u32> {
    type HashOut = PoseidonHashOut;

    fn empty_leaf() -> Self {
        U256::default()
    }

    fn hash(&self) -> PoseidonHashOut {
        PoseidonHashOut::hash_inputs_u32(&self.limbs())
    }

    fn two_to_one(left: Self::HashOut, right: Self::HashOut) -> Self::HashOut {
        let inputs = left
            .elements
            .into_iter()
            .chain(right.elements.into_iter())
            .collect::<Vec<_>>();
        PoseidonHashOut::hash_inputs_u64(&inputs)
    }
}

impl LeafableTarget for U256<Target> {
    type Leaf = U256<u32>;
    type HashOutTarget = PoseidonHashOutTarget;

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

    fn empty_leaf<F: RichField + Extendable<D>, const D: usize>(
        builder: &mut CircuitBuilder<F, D>,
    ) -> Self {
        let empty_leaf = <U256<u32> as Leafable>::empty_leaf();
        U256::<Target>::constant(builder, empty_leaf)
    }

    fn hash<F: RichField + Extendable<D>, C: GenericConfig<D, F = F> + 'static, const D: usize>(
        &self,
        builder: &mut CircuitBuilder<F, D>,
    ) -> PoseidonHashOutTarget
    where
        <C as GenericConfig<D>>::Hasher: AlgebraicHasher<F>,
    {
        PoseidonHashOutTarget::hash_inputs(builder, &self.limbs())
    }

    fn connect_hash<F: RichField + Extendable<D>, const D: usize>(
        builder: &mut CircuitBuilder<F, D>,
        x: &Self::HashOutTarget,
        y: &Self::HashOutTarget,
    ) {
        x.connect(builder, *y)
    }

    fn two_to_one<
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
