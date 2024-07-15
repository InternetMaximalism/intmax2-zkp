use itertools::Itertools;
use plonky2::{
    field::extension::Extendable,
    hash::hash_types::RichField,
    plonk::{
        config::{AlgebraicHasher, GenericConfig},
        proof::ProofWithPublicInputs,
    },
};

use crate::circuits::balance::balance_processor::BalanceProcessor;

use super::{
    block_builder::MockBlockBuilder, local_manager::LocalManager,
    sync_validity_prover::SyncValidityProver,
};

pub struct SyncBalanceProver<F, C, const D: usize>
where
    F: RichField + Extendable<D>,
    C: GenericConfig<D, F = F>,
{
    pub last_block_number: u32,
    pub last_balance_proof: Option<ProofWithPublicInputs<F, C, D>>,
}

impl<F, C, const D: usize> SyncBalanceProver<F, C, D>
where
    F: RichField + Extendable<D>,
    C: GenericConfig<D, F = F> + 'static,
    <C as GenericConfig<D>>::Hasher: AlgebraicHasher<F>,
{
    pub fn new() -> Self {
        Self {
            last_block_number: 0,
            last_balance_proof: None,
        }
    }

    pub fn get_balance_proof(&self) -> ProofWithPublicInputs<F, C, D> {
        self.last_balance_proof
            .clone()
            .expect("balance proof not found")
    }

    pub fn sync_send(
        &mut self,
        sync_validity_prover: &mut SyncValidityProver<F, C, D>,
        balance_processor: &BalanceProcessor<F, C, D>,
        block_builder: &MockBlockBuilder,
        local_manager: &LocalManager,
    ) {
        sync_validity_prover.sync(&block_builder); // sync validity proofs
        let all_block_numbers = local_manager.get_all_block_numbers();
        let not_synced_block_numbers: Vec<u32> = all_block_numbers
            .into_iter()
            .filter(|block_number| self.last_block_number < *block_number)
            .sorted()
            .collect();
        for block_number in not_synced_block_numbers {
            let send_witness = local_manager
                .get_send_witness(block_number)
                .expect("send witness not found");
            let block_number = send_witness.get_included_block_number();
            let prev_block_number = send_witness.get_prev_block_number();
            let update_witness = sync_validity_prover.get_update_witness(
                block_builder,
                local_manager.get_pubkey(),
                prev_block_number,
                true,
            );
            let balance_proof = balance_processor.prove_send(
                sync_validity_prover.validity_circuit(),
                local_manager.get_pubkey(),
                &send_witness,
                &update_witness,
                &self.last_balance_proof,
            );
            self.last_block_number = block_number;
            self.last_balance_proof = Some(balance_proof);
        }
    }

    // Sync balance proof public state to the latest block
    // assuming that there is no un-synced send tx.
    pub fn sync_no_send(
        &mut self,
        sync_validity_prover: &mut SyncValidityProver<F, C, D>,
        balance_processor: &BalanceProcessor<F, C, D>,
        block_builder: &MockBlockBuilder,
        local_manager: &LocalManager,
    ) {
        sync_validity_prover.sync(&block_builder); // sync validity proofs
        let all_block_numbers = local_manager.get_all_block_numbers();
        let not_synced_block_numbers: Vec<u32> = all_block_numbers
            .into_iter()
            .filter(|block_number| self.last_block_number < *block_number)
            .sorted()
            .collect();
        assert!(not_synced_block_numbers.is_empty(), "sync send tx first");
        let current_block_number = block_builder.last_block_number();
        let update_witness = sync_validity_prover.get_update_witness(
            block_builder,
            local_manager.get_pubkey(),
            self.last_block_number,
            false,
        );
        let balance_proof = balance_processor.prove_update(
            sync_validity_prover.validity_circuit(),
            local_manager.get_pubkey(),
            &update_witness,
            &self.last_balance_proof,
        );
        self.last_block_number = current_block_number;
        self.last_balance_proof = Some(balance_proof);
    }

    pub fn sync_all(
        &mut self,
        sync_validity_prover: &mut SyncValidityProver<F, C, D>,
        balance_processor: &BalanceProcessor<F, C, D>,
        block_builder: &MockBlockBuilder,
        local_manager: &LocalManager,
    ) {
        self.sync_send(
            sync_validity_prover,
            balance_processor,
            block_builder,
            local_manager,
        );
        self.sync_no_send(
            sync_validity_prover,
            balance_processor,
            block_builder,
            local_manager,
        );
    }
}
