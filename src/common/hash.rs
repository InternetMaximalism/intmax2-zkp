use plonky2::{
    field::extension::Extendable, hash::hash_types::RichField, iop::target::Target,
    plonk::circuit_builder::CircuitBuilder,
};

use crate::{
    ethereum_types::{
        bytes32::Bytes32,
        u256::U256,
        u32limb_trait::{U32LimbTargetTrait as _, U32LimbTrait as _},
    },
    utils::poseidon_hash_out::{PoseidonHashOut, PoseidonHashOutTarget},
};

use super::salt::{Salt, SaltTarget};

pub fn get_pubkey_salt_hash(pubkey: U256<u32>, salt: Salt) -> Bytes32<u32> {
    let input = vec![pubkey.to_u64_vec(), salt.to_u64_vec()].concat();
    let hash = PoseidonHashOut::hash_inputs_u64(&input);
    hash.into()
}

pub fn get_pubkey_salt_hash_circuit<F: RichField + Extendable<D>, const D: usize>(
    builder: &mut CircuitBuilder<F, D>,
    pubkey: U256<Target>,
    salt: SaltTarget,
) -> Bytes32<Target> {
    let inputs = vec![pubkey.to_vec(), salt.to_vec()].concat();
    let hash = PoseidonHashOutTarget::hash_inputs(builder, &inputs);
    Bytes32::<Target>::from_hash_out(builder, hash)
}
