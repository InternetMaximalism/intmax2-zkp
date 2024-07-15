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
    circuits::{
        balance::balance_pis::BalancePublicInputs, validity::validity_circuit::ValidityCircuit,
    },
    common::witness::{
        balance_incoming_witness::BalanceIncomingWitness,
        private_state_transition_witness::PrivateStateTransitionWitness,
        receive_deposit_witness::ReceiveDepositWitness, send_witness::SendWitness,
        transfer_witness::TransferWitness, update_witness::UpdateWitness,
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
    pub fn new(validity_circuit: &ValidityCircuit<F, C, D>) -> Self {
        let balance_transition_processor = BalanceTransitionProcessor::new(validity_circuit);
        let balance_circuit =
            BalanceCircuit::new(&balance_transition_processor.balance_transition_circuit);
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
        validity_circuit: &ValidityCircuit<F, C, D>,
        pubkey: U256<u32>,
        send_witness: &SendWitness,
        update_witness: &UpdateWitness<F, C, D>,
        prev_proof: &Option<ProofWithPublicInputs<F, C, D>>,
    ) -> ProofWithPublicInputs<F, C, D> {
        let transition_proof = self.balance_transition_processor.prove_send(
            validity_circuit,
            &self.get_verifier_only_data(),
            send_witness,
            update_witness,
        );
        let proof = self
            .balance_circuit
            .prove(pubkey, &transition_proof, prev_proof)
            .unwrap();
        proof
    }

    pub fn prove_update(
        &self,
        validity_circuit: &ValidityCircuit<F, C, D>,
        pubkey: U256<u32>,
        update_witness: &UpdateWitness<F, C, D>,
        prev_proof: &Option<ProofWithPublicInputs<F, C, D>>,
    ) -> ProofWithPublicInputs<F, C, D> {
        let prev_balance_pis = if prev_proof.is_some() {
            BalancePublicInputs::from_pis(&prev_proof.as_ref().unwrap().public_inputs)
        } else {
            BalancePublicInputs::new(pubkey)
        };
        let transition_proof = self.balance_transition_processor.prove_update(
            validity_circuit,
            &self.get_verifier_only_data(),
            &prev_balance_pis,
            update_witness,
        );
        let proof = self
            .balance_circuit
            .prove(pubkey, &transition_proof, prev_proof)
            .unwrap();
        proof
    }

    pub fn prove_receive_transfer(
        &self,
        pubkey: U256<u32>,
        transfer_witness: &TransferWitness,
        private_transition_witness: &PrivateStateTransitionWitness,
        balance_incoming_witness: &BalanceIncomingWitness<F, C, D>,
        prev_proof: &Option<ProofWithPublicInputs<F, C, D>>,
    ) -> ProofWithPublicInputs<F, C, D> {
        let prev_balance_pis = if prev_proof.is_some() {
            BalancePublicInputs::from_pis(&prev_proof.as_ref().unwrap().public_inputs)
        } else {
            BalancePublicInputs::new(pubkey)
        };
        let transition_proof = self.balance_transition_processor.prove_receive_transfer(
            &self.get_verifier_data(),
            &prev_balance_pis,
            transfer_witness,
            private_transition_witness,
            balance_incoming_witness,
        );
        let proof = self
            .balance_circuit
            .prove(pubkey, &transition_proof, prev_proof)
            .unwrap();
        proof
    }

    pub fn prove_receive_deposit(
        &self,
        pubkey: U256<u32>,
        receive_deposit_witness: &ReceiveDepositWitness,
        prev_proof: &Option<ProofWithPublicInputs<F, C, D>>,
    ) -> ProofWithPublicInputs<F, C, D> {
        let prev_balance_pis = if prev_proof.is_some() {
            BalancePublicInputs::from_pis(&prev_proof.as_ref().unwrap().public_inputs)
        } else {
            BalancePublicInputs::new(pubkey)
        };
        let transition_proof = self.balance_transition_processor.prove_receive_deposit(
            &self.get_verifier_data(),
            &prev_balance_pis,
            receive_deposit_witness,
        );
        let proof = self
            .balance_circuit
            .prove(pubkey, &transition_proof, prev_proof)
            .unwrap();
        proof
    }
}

#[cfg(test)]
mod tests {
    use plonky2::{
        field::goldilocks_field::GoldilocksField, plonk::config::PoseidonGoldilocksConfig,
    };

    use crate::{
        circuits::validity::validity_processor::ValidityProcessor,
        common::{transfer::Transfer, witness::balance_incoming_witness::BalanceIncomingWitness},
        ethereum_types::u256::U256,
        mock::{
            block_builder::MockBlockBuilder, local_manager::LocalManager,
            sync_balance_prover::SyncBalanceProver, sync_validity_prover::SyncValidityProver,
        },
    };

    use super::BalanceProcessor;

    type F = GoldilocksField;
    type C = PoseidonGoldilocksConfig;
    const D: usize = 2;

    #[test]
    fn balance_processor_setup() {
        let validity_processor = ValidityProcessor::<F, C, D>::new();
        let _balance_processor = BalanceProcessor::new(&validity_processor.validity_circuit);
    }

    #[test]
    fn balance_processor_send() {
        let mut rng = rand::thread_rng();
        let mut block_builder = MockBlockBuilder::new();
        let mut local_manager = LocalManager::new_rand(&mut rng);
        let mut sync_validity_prover = SyncValidityProver::<F, C, D>::new();
        let mut sync_sender_prover = SyncBalanceProver::<F, C, D>::new();
        let balance_processor = BalanceProcessor::new(sync_validity_prover.validity_circuit());

        // send tx0
        let transfer0 = Transfer::rand(&mut rng);
        local_manager.send_tx_and_update(&mut rng, &mut block_builder, &[transfer0]);

        // send tx1
        let transfer1 = Transfer::rand(&mut rng);
        local_manager.send_tx_and_update(&mut rng, &mut block_builder, &[transfer1]);

        sync_sender_prover.sync_send(
            &mut sync_validity_prover,
            &balance_processor,
            &block_builder,
            &local_manager,
        );
    }

    #[test]
    fn balance_processor_update() {
        let mut rng = rand::thread_rng();
        // shared state
        let mut block_builder = MockBlockBuilder::new();
        let mut sync_validity_prover = SyncValidityProver::<F, C, D>::new();
        let balance_processor = BalanceProcessor::new(sync_validity_prover.validity_circuit());

        // alice send tx0
        let mut alice = LocalManager::new_rand(&mut rng);
        let transfer0 = Transfer::rand(&mut rng);
        alice.send_tx_and_update(&mut rng, &mut block_builder, &[transfer0]);

        // bob update balance proof
        let bob = LocalManager::new_rand(&mut rng);
        let mut bob_balance_prover = SyncBalanceProver::<F, C, D>::new();
        bob_balance_prover.sync_no_send(
            &mut sync_validity_prover,
            &balance_processor,
            &block_builder,
            &bob,
        );
    }

    #[test]
    fn balance_processor_receive_tranfer() {
        let mut rng = rand::thread_rng();
        // shared state
        let mut block_builder = MockBlockBuilder::new();
        let mut sync_validity_prover = SyncValidityProver::<F, C, D>::new();
        let balance_processor = BalanceProcessor::new(sync_validity_prover.validity_circuit());

        // accounts
        let mut alice = LocalManager::new_rand(&mut rng);
        let mut alice_balance_prover = SyncBalanceProver::<F, C, D>::new();
        let bob = LocalManager::new_rand(&mut rng);
        let mut bob_balance_prover = SyncBalanceProver::<F, C, D>::new();

        let transfer = Transfer::rand_to(&mut rng, bob.get_pubkey());
        let send_witness = alice.send_tx_and_update(&mut rng, &mut block_builder, &[transfer]);
        let transfer_witness = &alice
            .get_transfer_witnesses(send_witness.get_included_block_number())
            .unwrap()[0];
        alice_balance_prover.sync_send(
            &mut sync_validity_prover,
            &balance_processor,
            &block_builder,
            &alice,
        );
        let alice_balance_proof = alice_balance_prover.last_balance_proof.clone().unwrap();

        // bob update balance proof
        bob_balance_prover.sync_no_send(
            &mut sync_validity_prover,
            &balance_processor,
            &block_builder,
            &bob,
        );
        let bob_balance_proof = bob_balance_prover.last_balance_proof.clone().unwrap();
        let private_transition_witness =
            bob.generate_witness_for_receive_transfer(&mut rng, &transfer);
        let block_merkle_proof = block_builder.get_block_merkle_proof(
            block_builder.last_block_number(),
            send_witness.get_included_block_number(),
        );
        let balance_incoming_witness = BalanceIncomingWitness {
            balance_proof: alice_balance_proof,
            block_merkle_proof,
        };

        balance_processor.prove_receive_transfer(
            bob.get_pubkey(),
            transfer_witness,
            &private_transition_witness,
            &balance_incoming_witness,
            &Some(bob_balance_proof),
        );
    }

    #[test]
    fn balance_processor_deposit() {
        let rng = &mut rand::thread_rng();
        // shared state
        let mut block_builder = MockBlockBuilder::new();
        let mut sync_validity_prover = SyncValidityProver::<F, C, D>::new();
        let balance_processor = BalanceProcessor::new(sync_validity_prover.validity_circuit());

        // alice deposit
        let mut alice = LocalManager::new_rand(rng);
        let mut alice_balance_prover = SyncBalanceProver::<F, C, D>::new();
        let deposit_amount = U256::<u32>::rand_small(rng);
        alice.deposit(rng, &mut block_builder, 0, deposit_amount);
        alice.deposit(rng, &mut block_builder, 1, deposit_amount);
        alice.deposit(rng, &mut block_builder, 2, deposit_amount);

        // post dummy block
        let transfer = Transfer::rand(rng);
        alice.send_tx_and_update(rng, &mut block_builder, &[transfer]);
        alice_balance_prover.sync_send(
            &mut sync_validity_prover,
            &balance_processor,
            &block_builder,
            &alice,
        );
        let alice_balance_proof = alice_balance_prover.last_balance_proof.clone().unwrap();

        let receive_deposit_witness = alice.generate_deposit_witness(rng, &block_builder);
        balance_processor.prove_receive_deposit(
            alice.get_pubkey(),
            &receive_deposit_witness,
            &Some(alice_balance_proof),
        );
    }
}
