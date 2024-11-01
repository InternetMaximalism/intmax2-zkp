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
    circuits::validity::{
        validity_circuit::ValidityCircuit, validity_processor::ValidityProcessor,
    },
    common::{
        block::Block,
        trees::{
            account_tree::{AccountMembershipProof, AccountTree},
            block_hash_tree::{BlockHashMerkleProof, BlockHashTree},
        },
        witness::update_witness::UpdateWitness,
    },
    constants::BLOCK_HASH_TREE_HEIGHT,
    ethereum_types::u256::U256,
};

use super::contract::MockContract;

// SyncValidityProver is a helper struct that helps to generate validity proofs from the
// contract state. It consumes a bit of memory to store account trees and block trees at all block
// numbers.
pub struct SyncValidityProver<F, C, const D: usize>
where
    F: RichField + Extendable<D>,
    C: GenericConfig<D, F = F>,
    <C as GenericConfig<D>>::Hasher: AlgebraicHasher<F>,
{
    pub validity_processor: OnceLock<ValidityProcessor<F, C, D>>, // delayed initialization
    pub last_block_number: u32,                                   /* last block number that has
                                                                   * been synced */
    pub account_trees: HashMap<u32, AccountTree>,
    pub block_trees: HashMap<u32, BlockHashTree>,
    pub validity_proofs: HashMap<u32, ProofWithPublicInputs<F, C, D>>,
    pub deposit_correspondence: HashMap<u32, (u32, u32)>, /* deposit_id -> (deposit_index,
                                                           * block_number) */
}

impl<F, C, const D: usize> SyncValidityProver<F, C, D>
where
    F: RichField + Extendable<D>,
    C: GenericConfig<D, F = F> + 'static,
    <C as GenericConfig<D>>::Hasher: AlgebraicHasher<F>,
{
    pub fn new() -> Self {
        let last_block_number = 0;
        let account_tree = AccountTree::initialize();
        let mut block_tree = BlockHashTree::new(BLOCK_HASH_TREE_HEIGHT);
        block_tree.push(Block::genesis().hash());

        let mut account_trees = HashMap::new();
        account_trees.insert(last_block_number, account_tree);
        let mut block_trees = HashMap::new();
        block_trees.insert(last_block_number, block_tree);

        Self {
            validity_processor: OnceLock::new(),
            last_block_number,
            account_trees,
            block_trees,
            validity_proofs: HashMap::new(), // no validity proof for genesis block
            deposit_correspondence: HashMap::new(),
        }
    }

    pub fn sync(&mut self, contract: &MockContract) -> anyhow::Result<()> {
        let mut account_tree = self
            .account_trees
            .get(&self.last_block_number)
            .unwrap()
            .clone();
        let mut block_tree = self
            .block_trees
            .get(&self.last_block_number)
            .unwrap()
            .clone();

        let next_block_number = contract.get_block_number();
        for block_number in (self.last_block_number + 1)..next_block_number {
            let prev_validity_proof = self.validity_proofs.get(&(block_number - 1)).cloned();
            assert!(
                prev_validity_proof.is_some() || block_number == 1,
                "prev validity proof not found"
            );
            let full_block = contract.get_full_block(block_number)?;
            let block_witness = full_block
                .to_block_witness(&account_tree, &block_tree)
                .map_err(|e| {
                    anyhow::anyhow!("failed to convert full block to block witness: {}", e)
                })?;
            let validity_witness = block_witness
                .update_trees(&mut account_tree, &mut block_tree)
                .map_err(|e| anyhow::anyhow!("failed to update trees: {}", e))?;
            let validity_proof = self
                .validity_processor()
                .prove(&prev_validity_proof, &validity_witness)
                .unwrap();

            // update self
            self.last_block_number = block_number;
            self.account_trees
                .insert(block_number, account_tree.clone());
            self.block_trees.insert(block_number, block_tree.clone());
            self.validity_proofs.insert(block_number, validity_proof);
        }
        self.deposit_correspondence = contract.deposit_correspondence.clone();
        Ok(())
    }

    pub fn get_update_witness(
        &self,
        pubkey: U256,
        root_block_number: u32,
        leaf_block_number: u32,
        is_prev_account_tree: bool,
    ) -> anyhow::Result<UpdateWitness<F, C, D>> {
        let validity_proof = self
            .validity_proofs
            .get(&root_block_number)
            .unwrap()
            .clone();
        let block_merkle_proof = self
            .get_block_merkle_proof(root_block_number, leaf_block_number)
            .map_err(|e| anyhow::anyhow!("failed to get block merkle proof: {}", e))?;
        let account_tree_block_number = if is_prev_account_tree {
            root_block_number - 1
        } else {
            root_block_number
        };
        let account_membership_proof = self
            .get_account_membership_proof(account_tree_block_number, pubkey)
            .map_err(|e| anyhow::anyhow!("failed to get account membership proof: {}", e))?;
        Ok(UpdateWitness {
            is_prev_account_tree,
            validity_proof,
            block_merkle_proof,
            account_membership_proof,
        })
    }

    // utilities
    pub fn get_account_id(&self, pubkey: U256) -> Option<usize> {
        self.account_trees
            .get(&self.last_block_number)
            .unwrap()
            .index(pubkey)
    }

    // returns deposit index and block number
    pub fn get_deposit_index_and_block(&self, deposit_id: u32) -> Option<(u32, u32)> {
        self.deposit_correspondence.get(&deposit_id).cloned()
    }

    pub fn get_block_merkle_proof(
        &self,
        root_block_number: u32,
        leaf_block_number: u32,
    ) -> anyhow::Result<BlockHashMerkleProof> {
        ensure!(
            leaf_block_number <= root_block_number,
            "leaf_block_number should be smaller than root_block_number"
        );
        let block_tree = &self
            .block_trees
            .get(&root_block_number)
            .ok_or(anyhow::anyhow!(
                "block tree not found for block number {}",
                root_block_number
            ))?;
        Ok(block_tree.prove(leaf_block_number as usize))
    }

    pub fn get_account_membership_proof(
        &self,
        block_number: u32,
        pubkey: U256,
    ) -> anyhow::Result<AccountMembershipProof> {
        let account_tree = &self
            .account_trees
            .get(&block_number)
            .ok_or(anyhow::anyhow!(
                "account tree not found for block number {}",
                block_number
            ))?;
        Ok(account_tree.prove_membership(pubkey))
    }

    pub fn validity_processor(&self) -> &ValidityProcessor<F, C, D> {
        self.validity_processor
            .get_or_init(|| ValidityProcessor::new())
    }

    pub fn validity_circuit(&self) -> &ValidityCircuit<F, C, D> {
        &self.validity_processor().validity_circuit
    }
}
