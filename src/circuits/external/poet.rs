use plonky2::{
    field::extension::Extendable,
    hash::hash_types::RichField,
    plonk::{config::GenericConfig, proof::ProofWithPublicInputs},
};

use crate::ethereum_types::{bytes32::Bytes32, u256::U256};

// Proof of elapsed time (poet) verifying the following constraints:
// 1. At the time of old_balance_proof, a deposit specified by token_index and deposit_amount has
//    already been made.
// 2. At a block number where at least min_elapsed_time has passed, a withdrawal with the same
//    token_index and min_withdrawal_amount = deposit_amount - max_delta or more has been made.
// 3. The last block number related to the user in the block immediately before that block number is
//    older than the block number of the old balance proof.
// 4. The nullifier is a value uniquely generated from the deposit to prevent reuse of the deposit.
#[derive(Clone, Debug)]
pub struct PoetPublicInputs {
    pub token_index: u32,
    pub deposit_amount: U256,
    pub max_delta: U256,
    pub nullifier: Bytes32,
    pub block_number: u32,
    pub block_hash: Bytes32,
}

#[derive(Clone, Debug)]
pub struct PoetValue<
    F: RichField + Extendable<D>,
    C: GenericConfig<D, F = F> + 'static,
    const D: usize,
> {
    pub old_balance_proof: ProofWithPublicInputs<F, C, D>,
}
