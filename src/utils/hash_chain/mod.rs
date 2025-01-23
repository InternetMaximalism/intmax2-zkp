use plonky2::{
    field::extension::Extendable,
    hash::hash_types::RichField,
    iop::target::Target,
    plonk::{
        circuit_builder::CircuitBuilder,
        config::{AlgebraicHasher, GenericConfig},
    },
};
use plonky2_keccak::{builder::BuilderKeccak256 as _, utils::solidity_keccak256};

use crate::ethereum_types::{
    bytes32::{Bytes32, Bytes32Target},
    u32limb_trait::{U32LimbTargetTrait as _, U32LimbTrait as _},
};

pub mod chain_end_circuit;
pub mod cyclic_chain_circuit;
pub mod hash_chain_processor;
pub mod hash_inner_circuit;

pub fn hash_with_prev_hash(content: &[u32], prev_hash: Bytes32) -> Bytes32 {
    let input = [prev_hash.to_u32_vec(), content.to_vec()].concat();
    Bytes32::from_u32_slice(&solidity_keccak256(&input))
}

pub fn hash_with_prev_hash_circuit<
    F: RichField + Extendable<D>,
    C: GenericConfig<D, F = F> + 'static,
    const D: usize,
>(
    builder: &mut CircuitBuilder<F, D>,
    content: &[Target],
    prev_hash: Bytes32Target,
) -> Bytes32Target
where
    <C as GenericConfig<D>>::Hasher: AlgebraicHasher<F>,
{
    let input = [prev_hash.to_vec(), content.to_vec()].concat();
    Bytes32Target::from_slice(&builder.keccak256::<C>(&input))
}
