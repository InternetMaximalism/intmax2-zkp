use plonky2::{
    field::extension::Extendable,
    hash::hash_types::RichField,
    plonk::{
        circuit_data::{VerifierCircuitData, VerifierOnlyCircuitData},
        config::{AlgebraicHasher, GenericConfig},
        proof::ProofWithPublicInputs,
    },
};

use crate::{
    circuits::balance::balance_pis::BalancePublicInputs,
    common::witness::{
        receive_deposit_witness::ReceiveDepositWitness,
        receive_transfer_witness::ReceiveTransferWitness, tx_witness::TxWitness,
        update_witness::UpdateWitness,
    },
    ethereum_types::u256::U256,
};

use super::{
    balance_circuit::BalanceCircuit, transition::transition_processor::BalanceTransitionProcessor,
};

pub struct BalanceProcessor<F, C, const D: usize>
where
    F: RichField + Extendable<D>,
    C: GenericConfig<D, F = F>,
{
    pub balance_transition_processor: BalanceTransitionProcessor<F, C, D>,
    pub balance_circuit: BalanceCircuit<F, C, D>,
}

impl<F, C, const D: usize> BalanceProcessor<F, C, D>
where
    F: RichField + Extendable<D>,
    C: GenericConfig<D, F = F> + 'static,
    <C as GenericConfig<D>>::Hasher: AlgebraicHasher<F>,
{
    pub fn new(validity_vd: &VerifierCircuitData<F, C, D>) -> Self {
        let balance_transition_processor = BalanceTransitionProcessor::new(validity_vd);
        let balance_circuit = BalanceCircuit::new(
            &balance_transition_processor
                .balance_transition_circuit
                .data
                .verifier_data(),
        );
        Self {
            balance_transition_processor,
            balance_circuit,
        }
    }

    pub fn get_verifier_only_data(&self) -> VerifierOnlyCircuitData<C, D> {
        self.balance_circuit.get_verifier_only_data()
    }

    pub fn get_verifier_data(&self) -> VerifierCircuitData<F, C, D> {
        self.balance_circuit.get_verifier_data()
    }

    pub fn prove_send(
        &self,
        validity_vd: &VerifierCircuitData<F, C, D>,
        pubkey: U256,
        tx_witness: &TxWitness,
        update_witness: &UpdateWitness<F, C, D>,
        spent_proof: &ProofWithPublicInputs<F, C, D>,
        prev_proof: &Option<ProofWithPublicInputs<F, C, D>>,
    ) -> anyhow::Result<ProofWithPublicInputs<F, C, D>> {
        let prev_balance_pis = get_prev_balance_pis(pubkey, prev_proof);
        let transition_proof = self
            .balance_transition_processor
            .prove_send(
                validity_vd,
                &self.get_verifier_only_data(),
                &prev_balance_pis,
                tx_witness,
                update_witness,
                spent_proof,
            )
            .map_err(|e| anyhow::anyhow!("failed to prove send: {:?}", e))?;
        let proof = self
            .balance_circuit
            .prove(pubkey, &transition_proof, prev_proof)
            .map_err(|e| anyhow::anyhow!("failed to prove send: {:?}", e))?;
        Ok(proof)
    }

    pub fn prove_update(
        &self,
        validity_vd: &VerifierCircuitData<F, C, D>,
        pubkey: U256,
        update_witness: &UpdateWitness<F, C, D>,
        prev_proof: &Option<ProofWithPublicInputs<F, C, D>>,
    ) -> anyhow::Result<ProofWithPublicInputs<F, C, D>> {
        let prev_balance_pis = get_prev_balance_pis(pubkey, prev_proof);
        let transition_proof = self
            .balance_transition_processor
            .prove_update(
                validity_vd,
                &self.get_verifier_only_data(),
                &prev_balance_pis,
                update_witness,
            )
            .map_err(|e| anyhow::anyhow!("failed to prove update: {:?}", e))?;
        let proof = self
            .balance_circuit
            .prove(pubkey, &transition_proof, prev_proof)
            .map_err(|e| anyhow::anyhow!("failed to prove update: {:?}", e))?;
        Ok(proof)
    }

    pub fn prove_receive_transfer(
        &self,
        pubkey: U256,
        receive_transfer_witness: &ReceiveTransferWitness<F, C, D>,
        prev_proof: &Option<ProofWithPublicInputs<F, C, D>>,
    ) -> anyhow::Result<ProofWithPublicInputs<F, C, D>> {
        let prev_balance_pis = get_prev_balance_pis(pubkey, prev_proof);
        let transition_proof = self
            .balance_transition_processor
            .prove_receive_transfer(
                &self.get_verifier_data(),
                &prev_balance_pis,
                receive_transfer_witness,
            )
            .map_err(|e| anyhow::anyhow!("failed to prove receive transfer: {:?}", e))?;
        let proof = self
            .balance_circuit
            .prove(pubkey, &transition_proof, prev_proof)
            .map_err(|e| anyhow::anyhow!("failed to prove receive transfer: {:?}", e))?;
        Ok(proof)
    }

    pub fn prove_receive_deposit(
        &self,
        pubkey: U256,
        receive_deposit_witness: &ReceiveDepositWitness,
        prev_proof: &Option<ProofWithPublicInputs<F, C, D>>,
    ) -> anyhow::Result<ProofWithPublicInputs<F, C, D>> {
        let prev_balance_pis = get_prev_balance_pis(pubkey, prev_proof);
        let transition_proof = self
            .balance_transition_processor
            .prove_receive_deposit(
                &self.get_verifier_data(),
                &prev_balance_pis,
                receive_deposit_witness,
            )
            .map_err(|e| anyhow::anyhow!("failed to prove receive deposit: {:?}", e))?;
        let proof = self
            .balance_circuit
            .prove(pubkey, &transition_proof, prev_proof)
            .map_err(|e| anyhow::anyhow!("failed to prove receive deposit: {:?}", e))?;
        Ok(proof)
    }
}

/// Get previous balance public inputs from previous balance proof
/// or create new balance public inputs from pubkey if no previous proof
pub fn get_prev_balance_pis<F, C, const D: usize>(
    pubkey: U256,
    prev_proof: &Option<ProofWithPublicInputs<F, C, D>>,
) -> BalancePublicInputs
where
    F: RichField + Extendable<D>,
    C: GenericConfig<D, F = F>,
{
    if let Some(prev_proof) = prev_proof {
        BalancePublicInputs::from_pis(&prev_proof.public_inputs)
    } else {
        BalancePublicInputs::new(pubkey)
    }
}

#[cfg(test)]
mod tests {
    use crate::{
        circuits::{
            balance::send::spent_circuit::SpentCircuit,
            test_utils::witness_generator::{construct_spent_witness, MockTxRequest},
        },
        common::{private_state::FullPrivateState, signature::key_set::KeySet, transfer::Transfer},
    };
    use plonky2::{
        field::goldilocks_field::GoldilocksField, plonk::config::PoseidonGoldilocksConfig,
    };

    use crate::circuits::validity::validity_processor::ValidityProcessor;

    use super::BalanceProcessor;

    type F = GoldilocksField;
    type C = PoseidonGoldilocksConfig;
    const D: usize = 2;

    #[test]
    fn balance_processor_setup() {
        let validity_processor = ValidityProcessor::<F, C, D>::new();
        let _balance_processor =
            BalanceProcessor::new(&validity_processor.validity_circuit.data.verifier_data());
    }

    #[test]
    #[cfg(feature = "skip_insufficient_check")]
    fn balance_processor_send() -> anyhow::Result<()> {
        use std::sync::Arc;

        use crate::circuits::test_utils::state_manager::ValidityStateManager;

        let mut rng = rand::thread_rng();
        let validity_processor = Arc::new(ValidityProcessor::<F, C, D>::new());
        let balance_processor = BalanceProcessor::new(&validity_processor.get_verifier_data());
        let spent_circuit = SpentCircuit::new();

        // public state
        let mut validity_state_manager = ValidityStateManager::new(validity_processor.clone());

        // local state
        let alice_key = KeySet::rand(&mut rng);
        let mut alice_state = FullPrivateState::new();

        // alice send transfer
        let transfer = Transfer::rand(&mut rng);

        let spent_witness = construct_spent_witness(&mut alice_state, &[transfer])?;
        let spent_proof = spent_circuit.prove(&spent_witness.to_value()?)?;
        let tx_request = MockTxRequest {
            tx: spent_witness.tx,
            sender_key: alice_key,
            will_return_sig: true,
        };
        let tx_witnesses = validity_state_manager.tick(true, &[tx_request])?;
        let update_witness =
            validity_state_manager.get_update_witness(alice_key.pubkey, 1, 0, true)?;

        let _alice_balance_proof = balance_processor.prove_send(
            &validity_processor.get_verifier_data(),
            alice_key.pubkey,
            &tx_witnesses[0],
            &update_witness,
            &spent_proof,
            &None,
        )?;
        Ok(())
    }

    // #[test]
    // fn balance_processor_update() {
    //     let mut rng = rand::thread_rng();
    //     // shared state
    //     let mut block_builder = MockBlockBuilder::new();
    //     let mut sync_validity_prover = SyncValidityProver::<F, C, D>::new();
    //     let balance_processor = BalanceProcessor::new(sync_validity_prover.validity_circuit());

    //     // alice send tx0
    //     let mut alice = MockWallet::new_rand(&mut rng);
    //     let transfer0 = Transfer::rand(&mut rng);
    //     alice.send_tx_and_update(&mut rng, &mut block_builder, &[transfer0]);

    //     // bob update balance proof
    //     let mut bob = MockWallet::new_rand(&mut rng);
    //     let mut bob_balance_prover = SyncBalanceProver::<F, C, D>::new();
    //     bob_balance_prover.sync_no_send(
    //         &mut sync_validity_prover,
    //         &mut bob,
    //         &balance_processor,
    //         &block_builder,
    //     );
    // }

    // #[test]
    // #[cfg(feature = "skip_insufficient_check")]
    // fn balance_processor_receive_transfer() {
    //     let mut rng = rand::thread_rng();
    //     // shared state
    //     let mut block_builder = MockBlockBuilder::new();
    //     let mut sync_validity_prover = SyncValidityProver::<F, C, D>::new();
    //     let balance_processor = BalanceProcessor::new(sync_validity_prover.validity_circuit());

    //     // accounts
    //     let mut alice = MockWallet::new_rand(&mut rng);
    //     let mut alice_balance_prover = SyncBalanceProver::<F, C, D>::new();
    //     let mut bob = MockWallet::new_rand(&mut rng);
    //     let mut bob_balance_prover = SyncBalanceProver::<F, C, D>::new();

    //     let transfer = Transfer::rand_to(&mut rng, bob.get_pubkey());
    //     let send_witness = alice.send_tx_and_update(&mut rng, &mut block_builder, &[transfer]);
    //     let transfer_witness = &alice
    //         .get_transfer_witnesses(send_witness.get_included_block_number())
    //         .unwrap()[0];
    //     alice_balance_prover.sync_send(
    //         &mut sync_validity_prover,
    //         &mut alice,
    //         &balance_processor,
    //         &block_builder,
    //     );
    //     let alice_balance_proof = alice_balance_prover.last_balance_proof.clone().unwrap();

    //     // bob update balance proof
    //     bob_balance_prover.sync_no_send(
    //         &mut sync_validity_prover,
    //         &mut bob,
    //         &balance_processor,
    //         &block_builder,
    //     );
    //     let bob_balance_proof = bob_balance_prover.get_balance_proof();

    //     let receive_transfer_witness = bob.receive_transfer_and_update(
    //         &mut rng,
    //         &block_builder,
    //         bob_balance_prover.last_block_number,
    //         transfer_witness,
    //         &alice_balance_proof,
    //     );
    //     let _new_bob_balance_proof = balance_processor.prove_receive_transfer(
    //         bob.get_pubkey(),
    //         &receive_transfer_witness,
    //         &Some(bob_balance_proof),
    //     );
    // }

    // #[test]
    // fn balance_processor_deposit() {
    //     let rng = &mut rand::thread_rng();
    //     // shared state
    //     let mut block_builder = MockBlockBuilder::new();
    //     let mut sync_validity_prover = SyncValidityProver::<F, C, D>::new();
    //     let balance_processor = BalanceProcessor::new(sync_validity_prover.validity_circuit());

    //     // alice deposit
    //     let mut alice = MockWallet::new_rand(rng);
    //     let mut alice_balance_prover = SyncBalanceProver::<F, C, D>::new();
    //     let deposit_amount = U256::rand_small(rng);
    //     let first_deposit_index = alice.deposit(rng, &mut block_builder, 0, deposit_amount);
    //     alice.deposit(rng, &mut block_builder, 1, deposit_amount); // dummy deposit

    //     // post dummy block
    //     let transfer = Transfer::rand(rng);
    //     alice.send_tx_and_update(rng, &mut block_builder, &[transfer]);
    //     alice_balance_prover.sync_send(
    //         &mut sync_validity_prover,
    //         &mut alice,
    //         &balance_processor,
    //         &block_builder,
    //     );
    //     let alice_balance_proof = alice_balance_prover.last_balance_proof.clone().unwrap();

    //     let receive_deposit_witness =
    //         alice.receive_deposit_and_update(rng, &block_builder, first_deposit_index);
    //     let _new_alice_balance_proof = balance_processor.prove_receive_deposit(
    //         alice.get_pubkey(),
    //         &receive_deposit_witness,
    //         &Some(alice_balance_proof),
    //     );
    // }
}
