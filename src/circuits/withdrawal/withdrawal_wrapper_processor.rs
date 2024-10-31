use anyhow::Result;
use plonky2::{
    field::goldilocks_field::GoldilocksField,
    plonk::{config::PoseidonGoldilocksConfig, proof::ProofWithPublicInputs},
};

use crate::{
    ethereum_types::address::Address, utils::wrapper::WrapperCircuit,
    wrapper_config::plonky2_config::PoseidonBN128GoldilocksConfig,
};

use super::{
    withdrawal_circuit::WithdrawalCircuit, withdrawal_wrapper_circuit::WithdrawalWrapperCircuit,
};

type F = GoldilocksField;
const D: usize = 2;
type C = PoseidonGoldilocksConfig;
type OuterC = PoseidonBN128GoldilocksConfig;

pub struct WithdrawalWrapperProcessor {
    pub withdrawal_wrapper_circuit: WithdrawalWrapperCircuit<F, C, D>,
    pub wrapper_circuit0: WrapperCircuit<F, C, C, D>,
    pub wrapper_circuit1: WrapperCircuit<F, C, OuterC, D>,
}

impl WithdrawalWrapperProcessor {
    pub fn new(withdrawal_circuit: &WithdrawalCircuit<F, C, D>) -> Self {
        let withdrawal_wrapper_circuit = WithdrawalWrapperCircuit::new(withdrawal_circuit);
        let wrapper_circuit0 = WrapperCircuit::new(&withdrawal_wrapper_circuit);
        let wrapper_circuit1 = WrapperCircuit::new(&wrapper_circuit0);
        Self {
            withdrawal_wrapper_circuit,
            wrapper_circuit0,
            wrapper_circuit1,
        }
    }

    pub fn prove(
        &self,
        withdrawal_proof: &ProofWithPublicInputs<F, C, D>,
        withdrawal_aggregator: Address,
    ) -> Result<ProofWithPublicInputs<F, OuterC, D>> {
        let withdrawal_wrapper_proof = self
            .withdrawal_wrapper_circuit
            .prove(withdrawal_proof, withdrawal_aggregator)?;
        let wrapper_proof0 = self.wrapper_circuit0.prove(&withdrawal_wrapper_proof)?;
        let wrapper_proof1 = self.wrapper_circuit1.prove(&wrapper_proof0)?;
        Ok(wrapper_proof1)
    }
}

#[cfg(test)]
#[cfg(feature = "skip_insufficient_check")]
mod tests {
    use crate::{
        circuits::{
            balance::balance_processor::BalanceProcessor,
            withdrawal::{self, withdrawal_processor::WithdrawalProcessor},
        },
        common::{transfer::Transfer, witness::withdrawal_witness::WithdrawalWitness},
        ethereum_types::{address::Address, u32limb_trait::U32LimbTrait},
        mock::{
            block_builder::MockBlockBuilder, sync_balance_prover::SyncBalanceProver,
            sync_validity_prover::SyncValidityProver, wallet::MockWallet,
        },
    };
    use plonky2::{
        field::goldilocks_field::GoldilocksField, plonk::config::PoseidonGoldilocksConfig,
    };

    type F = GoldilocksField;
    type C = PoseidonGoldilocksConfig;
    const D: usize = 2;

    #[test]
    fn test_withdrawal_wrapper_processor() {
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

        let withdrawal_wrapper_processor =
            withdrawal::withdrawal_wrapper_processor::WithdrawalWrapperProcessor::new(
                &withdraw_processor.withdrawal_circuit,
            );
        let withdrawal_aggregator = Address::rand(rng);
        let _withdrawal_wrapper_proof = withdrawal_wrapper_processor
            .prove(&withdrawal_proof, withdrawal_aggregator)
            .expect("Failed to prove withdrawal wrapper");
    }

    /// print withdrawal_circuit_digest to check consistency
    #[test]
    fn check_withdrawal_circuit_digest_consistency() {
        let sync_validity_prover = SyncValidityProver::<F, C, D>::new();
        let balance_processor = BalanceProcessor::new(sync_validity_prover.validity_circuit());
        let withdraw_processor = WithdrawalProcessor::new(&balance_processor.balance_circuit);
        let withdrawal_circuit_digest = withdraw_processor
            .withdrawal_circuit
            .data
            .verifier_only
            .circuit_digest;
        println!("withdrawal_circuit_digest: {:?}", withdrawal_circuit_digest);
    }
}
