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
        private_state_transition_witness::PrivateStateTransitionWitness, send_witness::SendWitness,
        transfer_witness::TransferWitness, update_public_state_witness::UpdatePublicStateWitness,
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
        update_public_state_witness: &UpdatePublicStateWitness<F, C, D>,
        prev_proof: &Option<ProofWithPublicInputs<F, C, D>>,
    ) -> ProofWithPublicInputs<F, C, D> {
        let transition_proof = self.balance_transition_processor.prove_send(
            validity_circuit,
            &self.get_verifier_only_data(),
            send_witness,
            update_public_state_witness,
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
        update_public_state_witness: &UpdatePublicStateWitness<F, C, D>,
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
            update_public_state_witness,
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
}

#[cfg(test)]
mod tests {
    use plonky2::{
        field::goldilocks_field::GoldilocksField, plonk::config::PoseidonGoldilocksConfig,
    };

    use crate::{
        circuits::validity::validity_processor::ValidityProcessor,
        common::transfer::Transfer,
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
}
