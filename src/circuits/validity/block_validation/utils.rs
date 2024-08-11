use plonky2::{
    field::extension::Extendable, hash::hash_types::RichField,
    plonk::circuit_builder::CircuitBuilder,
};

use crate::{
    ethereum_types::{
        u256::{U256Target, U256},
        u32limb_trait::{U32LimbTargetTrait as _, U32LimbTrait as _},
    },
    utils::poseidon_hash_out::{PoseidonHashOut, PoseidonHashOutTarget},
};

pub(crate) fn get_pubkey_commitment(pubkeys: &[U256]) -> PoseidonHashOut {
    let pubkey_flattened = pubkeys
        .iter()
        .flat_map(|pubkey| pubkey.to_u32_vec())
        .collect::<Vec<_>>();
    PoseidonHashOut::hash_inputs_u32(&pubkey_flattened)
}

pub(crate) fn get_pubkey_commitment_circuit<F: RichField + Extendable<D>, const D: usize>(
    builder: &mut CircuitBuilder<F, D>,
    pubkeys: &[U256Target],
) -> PoseidonHashOutTarget {
    let pubkey_flattened = pubkeys
        .iter()
        .flat_map(|pubkey| pubkey.to_vec())
        .collect::<Vec<_>>();
    PoseidonHashOutTarget::hash_inputs(builder, &pubkey_flattened)
}
