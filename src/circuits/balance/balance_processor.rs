use plonky2::{
    field::extension::Extendable,
    hash::hash_types::RichField,
    plonk::{
        circuit_data::VerifierOnlyCircuitData,
        config::{AlgebraicHasher, GenericConfig},
        proof::ProofWithPublicInputs,
    },
};

use crate::{
    circuits::validity::validity_circuit::ValidityCircuit,
    common::witness::{
        send_witness::SendWitness, update_public_state_witness::UpdatePublicStateWitness,
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
    fn test_balance_processor() {
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
}
