use plonky2::{
    field::{extension::Extendable, types::Field},
    hash::hash_types::RichField,
    iop::{target::BoolTarget, witness::WitnessWrite},
    plonk::{
        circuit_builder::CircuitBuilder,
        config::{AlgebraicHasher, GenericConfig},
    },
};

pub trait LeafableHasher {
    type HashOut;
    type HashOutTarget;

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
