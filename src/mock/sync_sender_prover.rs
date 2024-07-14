use hashbrown::HashMap;
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

pub struct SyncSenderProver<F, C, const D: usize>
where
    F: RichField + Extendable<D>,
    C: GenericConfig<D, F = F>,
{
    pub last_block_number: u32,
    pub last_block_proof: Option<ProofWithPublicInputs<F, C, D>>,
    pub balance_proofs: HashMap<u32, ProofWithPublicInputs<F, C, D>>,
}

impl<F, C, const D: usize> SyncSenderProver<F, C, D>
where
    F: RichField + Extendable<D>,
    C: GenericConfig<D, F = F> + 'static,
    <C as GenericConfig<D>>::Hasher: AlgebraicHasher<F>,
{
    pub fn new() -> Self {
        Self {
            last_block_number: 0,
            last_block_proof: None,
            balance_proofs: HashMap::new(),
        }
    }

    pub fn sync(
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
            let update_public_state_witness = sync_validity_prover.get_update_public_state_witness(
                block_builder,
                block_number,
                prev_block_number,
            );
            let balance_proof = balance_processor.prove_send(
                sync_validity_prover.validity_circuit(),
                local_manager.get_pubkey(),
                &send_witness,
                &update_public_state_witness,
                &self.last_block_proof,
            );
            self.balance_proofs
                .insert(block_number, balance_proof.clone());
            self.last_block_number = block_number;
            self.last_block_proof = Some(balance_proof);
        }
    }
}
