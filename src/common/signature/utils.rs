use plonky2::{
    field::extension::Extendable,
    hash::hash_types::RichField,
    plonk::{
        circuit_builder::CircuitBuilder,
        config::{AlgebraicHasher, GenericConfig},
    },
};
use plonky2_keccak::{builder::BuilderKeccak256 as _, utils::solidity_keccak256};

use crate::{
    constants::NUM_SENDERS_IN_BLOCK,
    ethereum_types::{
        bytes32::{Bytes32, Bytes32Target},
        u256::{U256Target, U256},
        u32limb_trait::{U32LimbTargetTrait as _, U32LimbTrait as _},
    },
};

pub fn get_pubkey_hash(pubkeys: &[U256]) -> Bytes32 {
    assert_eq!(pubkeys.len(), NUM_SENDERS_IN_BLOCK);
    let pubkey_flattened = pubkeys
        .iter()
        .flat_map(|x| x.to_u32_vec())
        .collect::<Vec<_>>();
    Bytes32::from_u32_slice(&solidity_keccak256(&pubkey_flattened))
}

pub fn get_pubkey_hash_circuit<
    F: RichField + Extendable<D>,
    C: GenericConfig<D, F = F> + 'static,
    const D: usize,
>(
    builder: &mut CircuitBuilder<F, D>,
    pubkeys: &[U256Target],
) -> Bytes32Target
where
    <C as GenericConfig<D>>::Hasher: AlgebraicHasher<F>,
{
    let pubkey_flattened = pubkeys
        .iter()
        .flat_map(|pubkey| pubkey.to_vec())
        .collect::<Vec<_>>();
    Bytes32Target::from_slice(&builder.keccak256::<C>(&pubkey_flattened))
}
