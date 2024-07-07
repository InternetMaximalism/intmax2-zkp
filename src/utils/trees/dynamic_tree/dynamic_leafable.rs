use std::fmt::Display;

use plonky2::{
    field::extension::Extendable,
    hash::hash_types::RichField,
    plonk::config::{AlgebraicHasher, GenericConfig},
};

use crate::{
    ethereum_types::bytes32::Bytes32,
    utils::{dummy::DummyProof, recursivable::Recursivable},
};

pub trait DynamicLeafableCircuit<F, C, const D: usize>: Recursivable<F, C, D>
where
    F: RichField + Extendable<D>,
    C: GenericConfig<D, F = F> + 'static,
    <C as GenericConfig<D>>::Hasher: AlgebraicHasher<F>,
{
    fn dummy_leaf(&self) -> DummyProof<F, C, D>;
}

pub trait DynamicLeafable: Clone + Display {
    fn hash(&self) -> Bytes32<u32>;
}
