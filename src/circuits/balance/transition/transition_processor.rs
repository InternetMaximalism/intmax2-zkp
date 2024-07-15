use plonky2::{
    field::extension::Extendable,
    hash::hash_types::RichField,
    plonk::{
        circuit_data::{CircuitConfig, VerifierCircuitData, VerifierOnlyCircuitData},
        config::{AlgebraicHasher, GenericConfig},
        proof::ProofWithPublicInputs,
    },
};

use crate::{
    circuits::{
        balance::{
            balance_circuit::common_data_for_balance_circuit,
            balance_pis::BalancePublicInputs,
            receive::{
                receive_deposit_circuit::{ReceiveDepositCircuit, ReceiveDepositValue},
                receive_targets::{
                    private_state_transition::PrivateStateTransitionValue,
                    transfer_inclusion::TransferInclusionValue,
                },
                receive_transfer_circuit::{ReceiveTransferCircuit, ReceiveTransferValue},
                update_circuit::{UpdateCircuit, UpdateValue},
            },
            send::sender_processor::SenderProcessor,
        },
        validity::validity_circuit::ValidityCircuit,
    },
    common::witness::{
        balance_incoming_witness::BalanceIncomingWitness,
        private_state_transition_witness::PrivateStateTransitionWitness,
        receive_deposit_witness::ReceiveDepositWitness, send_witness::SendWitness,
        transfer_witness::TransferWitness, update_witness::UpdateWitness,
    },
    ethereum_types::bytes32::Bytes32,
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
        let balance_common_data = common_data_for_balance_circuit::<F, C, D>();
        let receive_transfer_circuit = ReceiveTransferCircuit::new(&balance_common_data);
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
        update_witness: &UpdateWitness<F, C, D>,
    ) -> ProofWithPublicInputs<F, C, D> {
        let sender_proof =
            self.sender_processor
                .prove(validity_circuit, send_witness, update_witness);

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

    pub fn prove_update(
        &self,
        validity_circuit: &ValidityCircuit<F, C, D>,
        balance_circuit_vd: &VerifierOnlyCircuitData<C, D>,
        prev_balance_pis: &BalancePublicInputs,
        update_witness: &UpdateWitness<F, C, D>,
    ) -> ProofWithPublicInputs<F, C, D> {
        let update_value = UpdateValue::new(
            validity_circuit,
            prev_balance_pis.pubkey,
            &update_witness.validity_proof,
            &prev_balance_pis.public_state,
            &update_witness.block_merkle_proof,
            &update_witness.account_membership_proof,
        );
        let update_proof = self.update_circuit.prove(&update_value).unwrap();
        let balance_transition_value = BalanceTransitionValue::new(
            &CircuitConfig::default(),
            BalanceTransitionType::Update,
            &self.receive_transfer_circuit,
            &self.receive_deposit_circuit,
            &self.update_circuit,
            &self.sender_processor.sender_circuit,
            None,
            None,
            Some(update_proof),
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

    pub fn prove_receive_transfer(
        &self,
        balance_verifier_data: &VerifierCircuitData<F, C, D>,
        prev_balance_pis: &BalancePublicInputs,
        transfer_witness: &TransferWitness,
        private_transition_witness: &PrivateStateTransitionWitness,
        balance_incoming_witness: &BalanceIncomingWitness<F, C, D>,
    ) -> ProofWithPublicInputs<F, C, D> {
        // assertion
        let transfer = transfer_witness.transfer;
        let nullifier: Bytes32<u32> = transfer.commitment().into();
        assert_eq!(nullifier, private_transition_witness.nullifier);
        assert_eq!(transfer.token_index, private_transition_witness.token_index);
        assert_eq!(transfer.amount, private_transition_witness.amount);

        let private_state_transition = PrivateStateTransitionValue::new(
            private_transition_witness.token_index,
            private_transition_witness.amount,
            private_transition_witness.nullifier,
            private_transition_witness.new_salt,
            &private_transition_witness.prev_private_state,
            &private_transition_witness.nullifier_proof,
            &private_transition_witness.prev_asset_leaf,
            &private_transition_witness.asset_merkle_proof,
        );
        let transfer_inclusion = TransferInclusionValue::new(
            balance_verifier_data,
            &transfer,
            transfer_witness.transfer_index,
            &transfer_witness.transfer_merkle_proof,
            &transfer_witness.tx_witness.tx,
            &balance_incoming_witness.balance_proof,
        );
        let receive_transfer_value = ReceiveTransferValue::new(
            &prev_balance_pis.public_state,
            &balance_incoming_witness.block_merkle_proof,
            &transfer_inclusion,
            &private_state_transition,
        );
        let receive_transfer_proof = self
            .receive_transfer_circuit
            .prove(&receive_transfer_value)
            .unwrap();

        let balance_transition_value = BalanceTransitionValue::new(
            &CircuitConfig::default(),
            BalanceTransitionType::ReceiveTransfer,
            &self.receive_transfer_circuit,
            &self.receive_deposit_circuit,
            &self.update_circuit,
            &self.sender_processor.sender_circuit,
            Some(receive_transfer_proof),
            None,
            None,
            None,
            prev_balance_pis.clone(),
            balance_verifier_data.verifier_only.clone(),
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

    pub fn prove_receive_deposit(
        &self,
        balance_verifier_data: &VerifierCircuitData<F, C, D>,
        prev_balance_pis: &BalancePublicInputs,
        receive_deposit_witness: &ReceiveDepositWitness,
    ) -> ProofWithPublicInputs<F, C, D> {
        let deposit_witness = receive_deposit_witness.deposit_witness.clone();
        let private_transition_witness = receive_deposit_witness.private_witness.clone();

        // assertion
        let deposit = deposit_witness.deposit.clone();
        let nullifier: Bytes32<u32> = deposit.poseidon_hash().into();
        assert_eq!(nullifier, private_transition_witness.nullifier);
        assert_eq!(deposit.token_index, private_transition_witness.token_index);
        assert_eq!(deposit.amount, private_transition_witness.amount);

        let private_state_transition = PrivateStateTransitionValue::new(
            private_transition_witness.token_index,
            private_transition_witness.amount,
            private_transition_witness.nullifier,
            private_transition_witness.new_salt,
            &private_transition_witness.prev_private_state,
            &private_transition_witness.nullifier_proof,
            &private_transition_witness.prev_asset_leaf,
            &private_transition_witness.asset_merkle_proof,
        );

        let receive_deposit_value = ReceiveDepositValue::new(
            prev_balance_pis.pubkey,
            deposit_witness.deposit_salt,
            deposit_witness.deposit_index,
            &deposit_witness.deposit,
            &deposit_witness.deposit_merkle_proof,
            &prev_balance_pis.public_state,
            &private_state_transition,
        );

        let receive_deposit_proof = self
            .receive_deposit_circuit
            .prove(&receive_deposit_value)
            .unwrap();

        let balance_transition_value = BalanceTransitionValue::new(
            &CircuitConfig::default(),
            BalanceTransitionType::ReceiveDeposit,
            &self.receive_transfer_circuit,
            &self.receive_deposit_circuit,
            &self.update_circuit,
            &self.sender_processor.sender_circuit,
            None,
            Some(receive_deposit_proof),
            None,
            None,
            prev_balance_pis.clone(),
            balance_verifier_data.verifier_only.clone(),
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

        let prev_block_number = send_witness.get_prev_block_number();
        let update_witness = sync_prover.get_update_witness(
            &block_builder,
            local_manager.get_pubkey(),
            prev_block_number,
            true,
        );
        let balance_processor =
            BalanceProcessor::new(&sync_prover.validity_processor.validity_circuit);
        let balance_circuit_vd = balance_processor.get_verifier_only_data();

        let _ = balance_processor.balance_transition_processor.prove_send(
            &sync_prover.validity_processor.validity_circuit,
            &balance_circuit_vd,
            &send_witness,
            &update_witness,
        );
    }
}
