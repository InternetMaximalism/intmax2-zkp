use itertools::Itertools;
use plonky2::{
    field::extension::Extendable,
    hash::hash_types::RichField,
    plonk::{
        config::{AlgebraicHasher, GenericConfig},
        proof::ProofWithPublicInputs,
    },
};
use rand::Rng;

use crate::{
    circuits::balance::{balance_pis::BalancePublicInputs, balance_processor::BalanceProcessor},
    common::witness::transfer_witness::TransferWitness,
};

use super::{
    block_builder::MockBlockBuilder, sync_validity_prover::SyncValidityProver, wallet::MockWallet,
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

    pub fn get_balance_pis(&self) -> BalancePublicInputs {
        BalancePublicInputs::from_pis(
            &self
                .last_balance_proof
                .as_ref()
                .expect("balance proof not found")
                .public_inputs,
        )
    }

    pub fn sync_send(
        &mut self,
        sync_validity_prover: &mut SyncValidityProver<F, C, D>,
        wallet: &mut MockWallet,
        balance_processor: &BalanceProcessor<F, C, D>,
        block_builder: &MockBlockBuilder,
    ) {
        sync_validity_prover.sync(&block_builder); // sync validity proofs
        let all_block_numbers = wallet.get_all_block_numbers();
        let not_synced_block_numbers: Vec<u32> = all_block_numbers
            .into_iter()
            .filter(|block_number| self.last_block_number < *block_number)
            .sorted()
            .collect();
        for block_number in not_synced_block_numbers {
            let send_witness = wallet
                .get_send_witness(block_number)
                .expect("send witness not found");
            let block_number = send_witness.get_included_block_number();
            let prev_block_number = send_witness.get_prev_block_number();
            let update_witness = sync_validity_prover.get_update_witness(
                block_builder,
                wallet.get_pubkey(),
                block_number,
                prev_block_number,
                true,
            );
            let balance_proof = balance_processor.prove_send(
                sync_validity_prover.validity_circuit(),
                wallet.get_pubkey(),
                &send_witness,
                &update_witness,
                &self.last_balance_proof,
            );
            let balance_pis = BalancePublicInputs::from_pis(&balance_proof.public_inputs);
            self.last_block_number = block_number;
            self.last_balance_proof = Some(balance_proof);
            // update wallet public state
            wallet.update_public_state(balance_pis.public_state);
        }
    }

    // Sync balance proof public state to the latest block
    // assuming that there is no un-synced send tx.
    pub fn sync_no_send(
        &mut self,
        sync_validity_prover: &mut SyncValidityProver<F, C, D>,
        wallet: &mut MockWallet,
        balance_processor: &BalanceProcessor<F, C, D>,
        block_builder: &MockBlockBuilder,
    ) {
        sync_validity_prover.sync(&block_builder); // sync validity proofs
        let all_block_numbers = wallet.get_all_block_numbers();
        let not_synced_block_numbers: Vec<u32> = all_block_numbers
            .into_iter()
            .filter(|block_number| self.last_block_number < *block_number)
            .sorted()
            .collect();
        assert!(not_synced_block_numbers.is_empty(), "sync send tx first");
        let current_block_number = block_builder.last_block_number();
        let update_witness = sync_validity_prover.get_update_witness(
            block_builder,
            wallet.get_pubkey(),
            block_builder.last_block_number(),
            self.last_block_number,
            false,
        );
        let balance_proof = balance_processor.prove_update(
            sync_validity_prover.validity_circuit(),
            wallet.get_pubkey(),
            &update_witness,
            &self.last_balance_proof,
        );
        let balance_pis = BalancePublicInputs::from_pis(&balance_proof.public_inputs);
        self.last_block_number = current_block_number;
        self.last_balance_proof = Some(balance_proof);
        // update wallet public state
        wallet.update_public_state(balance_pis.public_state);
    }

    pub fn sync_all(
        &mut self,
        sync_validity_prover: &mut SyncValidityProver<F, C, D>,
        wallet: &mut MockWallet,
        balance_processor: &BalanceProcessor<F, C, D>,
        block_builder: &MockBlockBuilder,
    ) {
        self.sync_send(
            sync_validity_prover,
            wallet,
            balance_processor,
            block_builder,
        );
        self.sync_no_send(
            sync_validity_prover,
            wallet,
            balance_processor,
            block_builder,
        );
    }

    pub fn receive_deposit<R: Rng>(
        &mut self,
        rng: &mut R,
        wallet: &mut MockWallet,
        balance_processor: &BalanceProcessor<F, C, D>,
        block_builder: &MockBlockBuilder,
        deposit_index: usize,
    ) {
        let receive_deposit_witness =
            wallet.receive_deposit_and_update(rng, block_builder, deposit_index);
        let balance_proof = balance_processor.prove_receive_deposit(
            wallet.get_pubkey(),
            &receive_deposit_witness,
            &self.last_balance_proof,
        );
        // public state is unchanged
        self.last_balance_proof = Some(balance_proof);
    }

    pub fn receive_transfer<R: Rng>(
        &mut self,
        rng: &mut R,
        wallet: &mut MockWallet,
        balance_processor: &BalanceProcessor<F, C, D>,
        block_builder: &MockBlockBuilder,
        transfer_witness: &TransferWitness,
        sender_balance_proof: &ProofWithPublicInputs<F, C, D>,
    ) {
        let receive_transfer_witness = wallet.receive_transfer_and_update(
            rng,
            block_builder,
            self.last_block_number,
            transfer_witness,
            sender_balance_proof,
        );
        let balance_proof = balance_processor.prove_receive_transfer(
            wallet.get_pubkey(),
            &receive_transfer_witness,
            &self.last_balance_proof,
        );
        // public state is unchanged
        self.last_balance_proof = Some(balance_proof);
    }
}
