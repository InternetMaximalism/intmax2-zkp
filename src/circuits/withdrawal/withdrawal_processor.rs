use anyhow::Result;
use plonky2::{
    field::extension::Extendable,
    hash::hash_types::RichField,
    plonk::{
        circuit_data::VerifierCircuitData,
        config::{AlgebraicHasher, GenericConfig},
        proof::ProofWithPublicInputs,
    },
};

use crate::{
    circuits::balance::{
        balance_circuit::BalanceCircuit,
        receive::receive_targets::transfer_inclusion::TransferInclusionValue,
    },
    common::witness::withdrawal_witness::WithdrawalWitness,
    ethereum_types::{
        bytes32::{Bytes32, BYTES32_LEN},
        u32limb_trait::U32LimbTrait as _,
    },
    utils::conversion::ToU64,
};

use super::{
    withdrawal_circuit::WithdrawalCircuit, withdrawal_inner_circuit::WithdrawalInnerCircuit,
};

pub struct WithdrawalProcessor<F, C, const D: usize>
where
    F: RichField + Extendable<D>,
    C: GenericConfig<D, F = F>,
{
    pub balance_verifier_data: VerifierCircuitData<F, C, D>,
    pub withdrawal_inner_circuit: WithdrawalInnerCircuit<F, C, D>,
    pub withdrawal_circuit: WithdrawalCircuit<F, C, D>,
}

impl<F, C, const D: usize> WithdrawalProcessor<F, C, D>
where
    F: RichField + Extendable<D>,
    C: GenericConfig<D, F = F> + 'static,
    <C as GenericConfig<D>>::Hasher: AlgebraicHasher<F>,
{
    pub fn new(balance_circuit: &BalanceCircuit<F, C, D>) -> Self {
        let withdrawal_inner_circuit = WithdrawalInnerCircuit::new(balance_circuit);
        let withdrawal_circuit = WithdrawalCircuit::new(&withdrawal_inner_circuit);
        Self {
            balance_verifier_data: balance_circuit.get_verifier_data(),
            withdrawal_inner_circuit,
            withdrawal_circuit,
        }
    }

    pub fn prove(
        &self,
        withdrawal_witness: &WithdrawalWitness<F, C, D>,
        prev_withdrawal_proof: &Option<ProofWithPublicInputs<F, C, D>>,
    ) -> Result<ProofWithPublicInputs<F, C, D>> {
        let prev_withdrawal_hash = if prev_withdrawal_proof.is_some() {
            Bytes32::from_u64_slice(
                &prev_withdrawal_proof.as_ref().unwrap().public_inputs[0..BYTES32_LEN].to_u64_vec(),
            )
        } else {
            Bytes32::default()
        };
        let transfer_witness = &withdrawal_witness.transfer_witness;
        let transition_inclusion_value = TransferInclusionValue::new(
            &self.balance_verifier_data,
            &transfer_witness.transfer,
            transfer_witness.transfer_index,
            &transfer_witness.transfer_merkle_proof,
            &transfer_witness.tx,
            &withdrawal_witness.balance_proof,
        )
        .map_err(|e| anyhow::anyhow!("Failed to create transfer inclusion value: {}", e))?;
        let withdrawal_inner_proof = self
            .withdrawal_inner_circuit
            .prove(prev_withdrawal_hash, &transition_inclusion_value)
            .map_err(|e| anyhow::anyhow!("Failed to prove withdrawal inner: {}", e))?;
        let withdrawal_proof = self
            .withdrawal_circuit
            .prove(&withdrawal_inner_proof, prev_withdrawal_proof)
            .map_err(|e| anyhow::anyhow!("Failed to prove withdrawal: {}", e))?;
        Ok(withdrawal_proof)
    }
}

#[cfg(test)]
mod tests {
    use plonky2::{
        field::goldilocks_field::GoldilocksField, plonk::config::PoseidonGoldilocksConfig,
    };

    use crate::{
        circuits::balance::balance_processor::BalanceProcessor,
        common::{transfer::Transfer, witness::withdrawal_witness::WithdrawalWitness},
        ethereum_types::{
            bytes32::{Bytes32, BYTES32_LEN},
            u32limb_trait::U32LimbTrait,
        },
        mock::{
            block_builder::MockBlockBuilder, sync_balance_prover::SyncBalanceProver,
            sync_validity_prover::SyncValidityProver, wallet::MockWallet,
        },
        utils::conversion::ToU64,
    };

    use super::WithdrawalProcessor;

    type F = GoldilocksField;
    type C = PoseidonGoldilocksConfig;
    const D: usize = 2;

    #[test]
    fn withdawal_processor() {
        let mut rng = &mut rand::thread_rng();
        let mut block_builder = MockBlockBuilder::new();
        let mut wallet = MockWallet::new_rand(rng);
        let mut sync_validity_prover = SyncValidityProver::<F, C, D>::new();
        let mut sync_sender_prover = SyncBalanceProver::<F, C, D>::new();
        let balance_processor = BalanceProcessor::new(sync_validity_prover.validity_circuit());

        // withdraw transfer 1
        let transfer = Transfer::rand_withdrawal(rng);
        let send_witness = wallet.send_tx_and_update(&mut rng, &mut block_builder, &[transfer]);
        sync_sender_prover.sync_send(
            &mut sync_validity_prover,
            &mut wallet,
            &balance_processor,
            &block_builder,
        );
        let transfer_witness = wallet
            .get_transfer_witnesses(send_witness.get_included_block_number())
            .unwrap()[0]
            .clone();
        let balance_proof = sync_sender_prover.get_balance_proof();

        let withdrawal_witness = WithdrawalWitness {
            transfer_witness,
            balance_proof,
        };

        let withdraw_processor = WithdrawalProcessor::new(&balance_processor.balance_circuit);
        let withdrawal_proof = withdraw_processor
            .prove(&withdrawal_witness, &None)
            .expect("Failed to prove withdrawal");

        let withdrawal = withdrawal_witness.to_withdrawal();
        assert_eq!(
            withdrawal_proof.public_inputs[0..BYTES32_LEN].to_u64_vec(),
            withdrawal
                .hash_with_prev_hash(Bytes32::default())
                .to_u64_vec()
        );
    }
}
