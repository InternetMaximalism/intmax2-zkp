use std::sync::OnceLock;

use anyhow::ensure;
use hashbrown::HashMap;
use plonky2::{
    field::extension::Extendable,
    hash::hash_types::RichField,
    plonk::{
        config::{AlgebraicHasher, GenericConfig},
        proof::ProofWithPublicInputs,
    },
};

use crate::{
    circuits::{
        validity::{
            validity_circuit::ValidityCircuit, validity_pis::ValidityPublicInputs,
            validity_processor::ValidityProcessor,
        },
        withdrawal::withdrawal_processor::WithdrawalProcessor,
    },
    common::{
        block::Block,
        trees::{
            account_tree::{AccountMembershipProof, AccountTree},
            block_hash_tree::{BlockHashMerkleProof, BlockHashTree},
            deposit_tree::{DepositMerkleProof, DepositTree},
        },
        withdrawal::Withdrawal,
        witness::update_witness::UpdateWitness,
    },
    constants::BLOCK_HASH_TREE_HEIGHT,
    ethereum_types::{bytes32::Bytes32, u256::U256},
};

pub struct WithdrawalAggregator<F, C, const D: usize>
where
    F: RichField + Extendable<D>,
    C: GenericConfig<D, F = F>,
    <C as GenericConfig<D>>::Hasher: AlgebraicHasher<F>,
{
    withdrawal_processor: WithdrawalProcessor<F, C, D>,
    prev_withdrawal_proof: Option<ProofWithPublicInputs<F, C, D>>,
    withdrawals: Vec<Withdrawal>,
}

impl<F, C, const D: usize> WithdrawalAggregator<F, C, D>
where
    F: RichField + Extendable<D>,
    C: GenericConfig<D, F = F>,
    <C as GenericConfig<D>>::Hasher: AlgebraicHasher<F>,
{
}
