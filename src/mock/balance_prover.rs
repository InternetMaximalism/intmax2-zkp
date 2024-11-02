use anyhow::ensure;
use plonky2::{
    field::extension::Extendable,
    hash::hash_types::RichField,
    plonk::{
        config::{AlgebraicHasher, GenericConfig},
        proof::ProofWithPublicInputs,
    },
};

use crate::{
    circuits::balance::balance_processor::{get_prev_balance_pis, BalanceProcessor},
    common::{
        salt::Salt,
        witness::{
            deposit_witness::DepositWitness,
            private_transition_witness::PrivateTransitionWitness,
            receive_deposit_witness::ReceiveDepositWitness,
            tx_witness::{self, TxWitness},
        },
    },
    ethereum_types::{bytes32::Bytes32, u256::U256},
};

use super::{
    data::{deposit_data::DepositData, tx_data::TxData, user_data::UserData},
    sync_validity_prover::SyncValidityProver,
};

pub struct BalanceProver;

impl BalanceProver {
    pub fn process_deposit<F, C, const D: usize>(
        &self,
        validity_prover: &SyncValidityProver<F, C, D>,
        balance_processor: &BalanceProcessor<F, C, D>,
        user_data: &mut UserData,
        new_salt: Salt,
        prev_balance_proof: &Option<ProofWithPublicInputs<F, C, D>>,
        deposit_block_number: u32,
        deposit_data: &DepositData,
    ) -> anyhow::Result<ProofWithPublicInputs<F, C, D>>
    where
        F: RichField + Extendable<D>,
        C: GenericConfig<D, F = F> + 'static,
        <C as GenericConfig<D>>::Hasher: AlgebraicHasher<F>,
    {
        // update balance proof up to the deposit block
        let before_balance_proof = self.update_balance_proof(
            validity_prover,
            balance_processor,
            user_data.pubkey,
            prev_balance_proof,
            deposit_block_number,
        )?;

        // Generate witness
        let (deposit_index, deposit_block_number) = validity_prover
            .get_deposit_index_and_block(deposit_data.deposit_id)
            .ok_or(anyhow::anyhow!("deposit not found"))?;
        ensure!(
            deposit_block_number == deposit_block_number,
            "deposit is not in the current block"
        );
        let deposit_merkle_proof = validity_prover
            .get_deposit_merkle_proof(deposit_index, deposit_block_number)
            .map_err(|_| anyhow::anyhow!("deposit merkle proof not found"))?;
        let deposit_witness = DepositWitness {
            deposit_salt: deposit_data.deposit_salt,
            deposit_index: deposit_index as usize,
            deposit: deposit_data.deposit.clone(),
            deposit_merkle_proof,
        };
        let deposit = deposit_data.deposit.clone();
        let nullifier: Bytes32 = deposit.poseidon_hash().into();
        let private_transition_witness = PrivateTransitionWitness::new(
            &mut user_data.full_private_state,
            deposit.token_index,
            deposit.amount,
            nullifier,
            new_salt,
        )
        .map_err(|e| anyhow::anyhow!("PrivateTransitionWitness::new failed: {:?}", e))?;
        let receive_deposit_witness = ReceiveDepositWitness {
            deposit_witness,
            private_transition_witness,
        };

        // prove deposit
        let balance_proof = balance_processor
            .prove_receive_deposit(
                user_data.pubkey,
                &receive_deposit_witness,
                &Some(before_balance_proof),
            )
            .map_err(|e| anyhow::anyhow!("prove_deposit failed: {:?}", e))?;

        Ok(balance_proof)
    }

    fn process_tx<F, C, const D: usize>(
        &self,
        validity_prover: &SyncValidityProver<F, C, D>,
        balance_processor: &BalanceProcessor<F, C, D>,
        // user_data: &mut UserData,
        sender: U256,
        prev_balance_proof: &Option<ProofWithPublicInputs<F, C, D>>,
        tx_block_number: u32,
        tx_data: &TxData<F, C, D>,
    ) -> anyhow::Result<ProofWithPublicInputs<F, C, D>>
    where
        F: RichField + Extendable<D>,
        C: GenericConfig<D, F = F> + 'static,
        <C as GenericConfig<D>>::Hasher: AlgebraicHasher<F>,
    {
        // sync check
        ensure!(
            tx_block_number <= validity_prover.last_block_number,
            "validity prover is not up to date"
        );
        let prev_balance_pis = get_prev_balance_pis(sender, prev_balance_proof);
        ensure!(
            prev_balance_pis.public_state.block_number < tx_block_number,
            "tx block number is not greater than prev balance proof"
        );

        // get witness
        let validity_pis =
            validity_prover
                .get_validity_pis(tx_block_number)
                .ok_or(anyhow::anyhow!(
                    "validity public inputs not found for block number {}",
                    tx_block_number
                ))?;
        let tx_witness = TxWitness {
            validity_pis,
            sender_leaves: tx_data.sender_leaves.clone(),
            tx: tx_data.tx.clone(),
            tx_index: tx_data.tx_index,
            tx_merkle_proof: tx_data.tx_merkle_proof.clone(),
        };
        let update_witness = validity_prover
            .get_update_witness(
                sender,
                tx_block_number,
                prev_balance_pis.public_state.block_number,
                true,
            )
            .map_err(|e| anyhow::anyhow!("get_update_witness failed: {:?}", e))?;

        // prove tx send
        let balance_proof = balance_processor
            .prove_send(
                validity_prover.validity_circuit(),
                sender,
                &tx_witness,
                &update_witness,
                &tx_data.spent_proof,
                prev_balance_proof,
            )
            .map_err(|e| anyhow::anyhow!("prove_send failed: {:?}", e))?;

        Ok(balance_proof)
    }

    // Inner function to update balance proof
    fn update_balance_proof<F, C, const D: usize>(
        &self,
        validity_prover: &SyncValidityProver<F, C, D>,
        balance_processor: &BalanceProcessor<F, C, D>,
        pubkey: U256,
        prev_balance_proof: &Option<ProofWithPublicInputs<F, C, D>>,
        block_number: u32,
    ) -> anyhow::Result<ProofWithPublicInputs<F, C, D>>
    where
        F: RichField + Extendable<D>,
        C: GenericConfig<D, F = F> + 'static,
        <C as GenericConfig<D>>::Hasher: AlgebraicHasher<F>,
    {
        // sync check
        ensure!(
            block_number <= validity_prover.last_block_number,
            "validity prover is not up to date"
        );

        // check block number
        ensure!(block_number > 0, "block number should be greater than 0");
        let prev_balance_pis = get_prev_balance_pis(pubkey, prev_balance_proof);
        if block_number == prev_balance_pis.public_state.block_number {
            // no need to update balance proof
            return Ok(prev_balance_proof.clone().unwrap());
        }

        // get update witness
        let update_witness = validity_prover
            .get_update_witness(
                pubkey,
                block_number,
                prev_balance_pis.public_state.block_number,
                false,
            )
            .map_err(|e| anyhow::anyhow!("get_update_witness failed: {:?}", e))?;
        let last_block_number = update_witness.get_last_block_number();
        ensure!(
            last_block_number <= block_number,
            "there is a sent tx after prev balance proof"
        );
        let balance_proof = balance_processor
            .prove_update(
                validity_prover.validity_circuit(),
                pubkey,
                &update_witness,
                &prev_balance_proof,
            )
            .map_err(|e| anyhow::anyhow!("prove_update failed: {:?}", e))?;
        Ok(balance_proof)
    }
}
