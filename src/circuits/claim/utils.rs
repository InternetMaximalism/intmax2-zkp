use plonky2::{
    field::extension::Extendable, hash::hash_types::RichField, iop::target::Target,
    plonk::circuit_builder::CircuitBuilder,
};

use crate::{
    common::{
        deposit::{Deposit, DepositTarget},
        salt::{Salt, SaltTarget},
    },
    ethereum_types::bytes32::{Bytes32, Bytes32Target},
    utils::poseidon_hash_out::{PoseidonHashOut, PoseidonHashOutTarget},
};

pub fn get_mining_deposit_nullifier(deposit: &Deposit, deposit_salt: Salt) -> Bytes32 {
    let hash_inputs: Vec<u64> = deposit
        .to_u32_vec()
        .into_iter()
        .map(|x| x as u64)
        .chain(deposit_salt.to_u64_vec().into_iter())
        .collect();
    let nullifier = PoseidonHashOut::hash_inputs_u64(&hash_inputs);
    nullifier.into()
}

pub fn get_mining_deposit_nullifier_circuit<F: RichField + Extendable<D>, const D: usize>(
    builder: &mut CircuitBuilder<F, D>,
    deposit: &DepositTarget,
    deposit_salt: SaltTarget,
) -> Bytes32Target {
    let hash_inputs: Vec<Target> = deposit
        .to_vec()
        .into_iter()
        .chain(deposit_salt.to_vec().into_iter())
        .collect();
    let nullifier = PoseidonHashOutTarget::hash_inputs(builder, &hash_inputs);
    Bytes32Target::from_hash_out(builder, nullifier)
}
