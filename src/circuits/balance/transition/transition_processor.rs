use plonky2::{
    field::extension::Extendable,
    hash::hash_types::RichField,
    plonk::{
        circuit_data::{CircuitConfig, VerifierOnlyCircuitData},
        config::{AlgebraicHasher, GenericConfig},
        proof::ProofWithPublicInputs,
    },
};

use crate::{
    circuits::{
        balance::{
            balance_pis::BalancePublicInputs,
            receive::{
                receive_deposit_circuit::ReceiveDepositCircuit,
                receive_transfer_circuit::ReceiveTransferCircuit, update_circuit::UpdateCircuit,
            },
            send::sender_processor::SenderProcessor,
        },
        validity::validity_circuit::ValidityCircuit,
    },
    common::witness::{
        send_witness::SendWitness, update_public_state_witness::UpdatePublicStateWitness,
    },
};

use super::transition_circuit::{
    BalanceTransitionCircuit, BalanceTransitionType, BalanceTransitionValue,
};

pub struct BalanceTransitionProcessor<F, C, const D: usize>
where
    F: RichField + Extendable<D>,
    C: GenericConfig<D, F = F>,
{
    pub receive_transfer_circuit: ReceiveTransferCircuit<F, C, D>,
    pub receive_deposit_circuit: ReceiveDepositCircuit<F, C, D>,
    pub update_circuit: UpdateCircuit<F, C, D>,
    pub sender_processor: SenderProcessor<F, C, D>,
    pub balance_transition_circuit: BalanceTransitionCircuit<F, C, D>,
}

impl<F, C, const D: usize> BalanceTransitionProcessor<F, C, D>
where
    F: RichField + Extendable<D>,
    C: GenericConfig<D, F = F> + 'static,
    <C as GenericConfig<D>>::Hasher: AlgebraicHasher<F>,
{
    pub fn new(validity_circuit: &ValidityCircuit<F, C, D>) -> Self {
        let receive_transfer_circuit = ReceiveTransferCircuit::new();
        let receive_deposit_circuit = ReceiveDepositCircuit::new();
        let update_circuit = UpdateCircuit::new(validity_circuit);
        let sender_processor = SenderProcessor::new(validity_circuit);
        let balance_transition_circuit = BalanceTransitionCircuit::new(
            &receive_transfer_circuit,
            &receive_deposit_circuit,
            &update_circuit,
            &sender_processor.sender_circuit,
        );
        Self {
            receive_transfer_circuit,
            receive_deposit_circuit,
            update_circuit,
            sender_processor,
            balance_transition_circuit,
        }
    }

    pub fn prove_dummy(
        &self,
        balance_circuit_vd: &VerifierOnlyCircuitData<C, D>,
        prev_balance_pis: &BalancePublicInputs,
    ) -> ProofWithPublicInputs<F, C, D> {
        let config = CircuitConfig::default();
        let balance_transition_value = BalanceTransitionValue::new(
            &config,
            BalanceTransitionType::Dummy,
            &self.receive_transfer_circuit,
            &self.receive_deposit_circuit,
            &self.update_circuit,
            &self.sender_processor.sender_circuit,
            None,
            None,
            None,
            None,
            prev_balance_pis.clone(),
            balance_circuit_vd.clone(),
        );
        self.balance_transition_circuit
            .prove(
                &self.receive_transfer_circuit,
                &self.receive_deposit_circuit,
                &self.update_circuit,
                &self.sender_processor.sender_circuit,
                &balance_transition_value,
            )
            .unwrap()
    }

    pub fn prove_send(
        &self,
        validity_circuit: &ValidityCircuit<F, C, D>,
        balance_circuit_vd: &VerifierOnlyCircuitData<C, D>,
        send_witness: &SendWitness,
        update_public_state_witness: &UpdatePublicStateWitness<F, C, D>,
    ) -> ProofWithPublicInputs<F, C, D> {
        let sender_proof = self.sender_processor.prove(
            validity_circuit,
            send_witness,
            update_public_state_witness,
        );

        let balance_transition_value = BalanceTransitionValue::new(
            &CircuitConfig::default(),
            BalanceTransitionType::Sender,
            &self.receive_transfer_circuit,
            &self.receive_deposit_circuit,
            &self.update_circuit,
            &self.sender_processor.sender_circuit,
            None,
            None,
            None,
            Some(sender_proof),
            send_witness.prev_balance_pis.clone(),
            balance_circuit_vd.clone(),
        );
        self.balance_transition_circuit
            .prove(
                &self.receive_transfer_circuit,
                &self.receive_deposit_circuit,
                &self.update_circuit,
                &self.sender_processor.sender_circuit,
                &balance_transition_value,
            )
            .unwrap()
    }
}

#[cfg(test)]
mod tests {
    use plonky2::{
        field::goldilocks_field::GoldilocksField, plonk::config::PoseidonGoldilocksConfig,
    };

    use crate::{
        circuits::{
            balance::{balance_pis::BalancePublicInputs, balance_processor::BalanceProcessor},
            validity::validity_processor::ValidityProcessor,
        },
        common::{generic_address::GenericAddress, salt::Salt, transfer::Transfer},
        ethereum_types::u256::U256,
        mock::{
            block_builder::MockBlockBuilder, local_manager::LocalManager,
            sync_validity_prover::SyncValidityProver,
        },
    };

    type F = GoldilocksField;
    type C = PoseidonGoldilocksConfig;
    const D: usize = 2;

    #[test]
    fn balance_transition_processor_prove_dummy() {
        let validity_processor = ValidityProcessor::<F, C, D>::new();
        let balance_processor = BalanceProcessor::new(&validity_processor.validity_circuit);

        let pubkey = U256::<u32>::rand(&mut rand::thread_rng());
        let balance_pis = BalancePublicInputs::new(pubkey);
        let balance_circuit_vd = balance_processor.get_verifier_only_data();

        let _ = balance_processor
            .balance_transition_processor
            .prove_dummy(&balance_circuit_vd, &balance_pis);
    }

    #[test]
    fn balance_transition_processor_prove_send() {
        let mut rng = rand::thread_rng();
        let mut block_builder = MockBlockBuilder::new();
        let mut local_manager = LocalManager::new_rand(&mut rng);
        let mut sync_prover = SyncValidityProver::<F, C, D>::new();

        let transfer = Transfer {
            recipient: GenericAddress::rand_pubkey(&mut rng),
            token_index: 0,
            amount: U256::<u32>::rand_small(&mut rng),
            salt: Salt::rand(&mut rng),
        };

        // send tx
        let send_witness =
            local_manager.send_tx_and_update(&mut rng, &mut block_builder, &[transfer]);
        sync_prover.sync(&block_builder);

        let block_number = send_witness.get_included_block_number();
        let prev_block_number = send_witness.get_prev_block_number();
        let update_public_state_witness = sync_prover.get_update_public_state_witness(
            &block_builder,
            block_number,
            prev_block_number,
        );
        let balance_processor =
            BalanceProcessor::new(&sync_prover.validity_processor.validity_circuit);
        let balance_circuit_vd = balance_processor.get_verifier_only_data();

        let _ = balance_processor.balance_transition_processor.prove_send(
            &sync_prover.validity_processor.validity_circuit,
            &balance_circuit_vd,
            &send_witness,
            &update_public_state_witness,
        );
    }
}
