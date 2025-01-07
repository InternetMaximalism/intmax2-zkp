use std::{collections::HashMap, sync::Arc};

use anyhow::Result;
use plonky2::{
    field::goldilocks_field::GoldilocksField,
    plonk::{config::PoseidonGoldilocksConfig, proof::ProofWithPublicInputs},
};

use crate::{
    circuits::{
        test_utils::witness_generator::construct_validity_witness,
        validity::{validity_pis::ValidityPublicInputs, validity_processor::ValidityProcessor},
    },
    common::{
        trees::{
            account_tree::AccountTree, block_hash_tree::BlockHashTree, deposit_tree::DepositTree,
        },
        witness::{tx_witness::TxWitness, update_witness::UpdateWitness},
    },
    ethereum_types::u256::U256,
};

use super::witness_generator::{construct_update_witness, MockTxRequest};

type F = GoldilocksField;
type C = PoseidonGoldilocksConfig;
const D: usize = 2;

pub struct ValidityStateManager {
    pub validity_processor: Arc<ValidityProcessor<F, C, D>>,

    // current state
    pub validity_pis: ValidityPublicInputs,
    pub validity_proof: Option<ProofWithPublicInputs<F, C, D>>,
    pub account_tree: AccountTree,
    pub block_tree: BlockHashTree,
    pub deposit_tree: DepositTree,

    // historical states
    pub historical_account_trees: HashMap<u32, AccountTree>,
    pub historical_block_trees: HashMap<u32, BlockHashTree>,
    pub historical_deposit_trees: HashMap<u32, DepositTree>,
    pub historical_validity_proofs: HashMap<u32, ProofWithPublicInputs<F, C, D>>,
}

impl ValidityStateManager {
    pub fn new(validity_processor: Arc<ValidityProcessor<F, C, D>>) -> Self {
        let account_tree = AccountTree::initialize();
        let block_tree = BlockHashTree::initialize();
        let deposit_tree = DepositTree::initialize();
        let historical_account_trees = HashMap::from([(0, account_tree.clone())]);
        let historical_block_trees = HashMap::from([(0, block_tree.clone())]);
        let historical_deposit_trees = HashMap::from([(0, deposit_tree.clone())]);
        let historical_validity_proofs = HashMap::new();
        let validity_pis = ValidityPublicInputs::genesis();
        let validity_proof = None;
        Self {
            validity_processor,
            validity_pis,
            validity_proof,
            account_tree,
            block_tree,
            deposit_tree,
            historical_account_trees,
            historical_block_trees,
            historical_deposit_trees,
            historical_validity_proofs,
        }
    }

    pub fn get_block_number(&self) -> u32 {
        self.validity_pis.public_state.block_number
    }

    // generate a new block and update the state manager
    pub fn tick(
        &mut self,
        is_registration_block: bool,
        tx_requests: &[MockTxRequest],
    ) -> Result<Vec<TxWitness>> {
        let (validity_witness, tx_witnesses) = construct_validity_witness(
            self.validity_pis.clone(),
            &mut self.account_tree,
            &mut self.block_tree,
            &self.deposit_tree,
            is_registration_block,
            tx_requests,
        )?;
        self.validity_pis = validity_witness.to_validity_pis()?;
        self.validity_proof = self
            .validity_processor
            .prove(&self.validity_proof, &validity_witness)?
            .into();
        let block_number = validity_witness.get_block_number();
        self.historical_validity_proofs
            .insert(block_number, self.validity_proof.clone().unwrap());
        self.historical_account_trees
            .insert(block_number, self.account_tree.clone());
        self.historical_block_trees
            .insert(block_number, self.block_tree.clone());
        self.historical_deposit_trees
            .insert(block_number, self.deposit_tree.clone());
        Ok(tx_witnesses)
    }

    pub fn get_update_witness(
        &self,
        pubkey: U256,
        root_block_number: u32,
        leaf_block_number: u32,
        is_prev_account_tree: bool,
    ) -> Result<UpdateWitness<F, C, D>> {
        construct_update_witness(
            &self.historical_account_trees,
            &self.historical_block_trees,
            &self.historical_validity_proofs,
            pubkey,
            root_block_number,
            leaf_block_number,
            is_prev_account_tree,
        )
    }
}
