use plonky2::{
    field::extension::Extendable,
    hash::hash_types::RichField,
    plonk::{
        circuit_data::{CommonCircuitData, VerifierCircuitData},
        config::{AlgebraicHasher, GenericConfig},
        proof::ProofWithPublicInputs,
    },
};

use crate::{
    circuits::balance::{balance_pis::BalancePublicInputs, error::BalanceError},
    common::witness::{
        receive_deposit_witness::ReceiveDepositWitness,
        receive_transfer_witness::ReceiveTransferWitness, spent_witness::SpentWitness,
        tx_witness::TxWitness, update_witness::UpdateWitness,
    },
    ethereum_types::u256::U256,
};

use super::{
    balance_circuit::BalanceCircuit, send::spent_circuit::SpentCircuit,
    transition::transition_processor::BalanceTransitionProcessor,
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

    pub fn get_verifier_data(&self) -> VerifierCircuitData<F, C, D> {
        self.balance_circuit.get_verifier_data()
    }

    pub fn spent_circuit(&self) -> &SpentCircuit<F, C, D> {
        &self
            .balance_transition_processor
            .sender_processor
            .spent_circuit
    }

    pub fn common_data(&self) -> &CommonCircuitData<F, D> {
        &self.balance_circuit.data.common
    }

    pub fn prove_send(
        &self,
        validity_vd: &VerifierCircuitData<F, C, D>,
        pubkey: U256,
        tx_witness: &TxWitness,
        update_witness: &UpdateWitness<F, C, D>,
        spent_proof: &ProofWithPublicInputs<F, C, D>,
        prev_proof: &Option<ProofWithPublicInputs<F, C, D>>,
    ) -> Result<ProofWithPublicInputs<F, C, D>, BalanceError> {
        let prev_balance_pis = get_prev_balance_pis(pubkey, prev_proof).map_err(|e| {
            BalanceError::InvalidInput(format!(
                "Failed to get previous balance public inputs: {:?}",
                e
            ))
        })?;
        let transition_proof = self
            .balance_transition_processor
            .prove_send(
                validity_vd,
                &self.get_verifier_data().verifier_only,
                &prev_balance_pis,
                tx_witness,
                update_witness,
                spent_proof,
            )
            .map_err(BalanceError::Transition)?;
        let proof = self
            .balance_circuit
            .prove(pubkey, &transition_proof, prev_proof)
            .map_err(|e| {
                BalanceError::VerificationFailed(format!("Failed to prove send: {:?}", e))
            })?;
        Ok(proof)
    }

    pub fn prove_update(
        &self,
        validity_vd: &VerifierCircuitData<F, C, D>,
        pubkey: U256,
        update_witness: &UpdateWitness<F, C, D>,
        prev_proof: &Option<ProofWithPublicInputs<F, C, D>>,
    ) -> Result<ProofWithPublicInputs<F, C, D>, BalanceError> {
        let prev_balance_pis = get_prev_balance_pis(pubkey, prev_proof).map_err(|e| {
            BalanceError::InvalidInput(format!(
                "Failed to get previous balance public inputs: {:?}",
                e
            ))
        })?;
        let transition_proof = self
            .balance_transition_processor
            .prove_update(
                validity_vd,
                &self.get_verifier_data().verifier_only,
                &prev_balance_pis,
                update_witness,
            )
            .map_err(BalanceError::Transition)?;
        let proof = self
            .balance_circuit
            .prove(pubkey, &transition_proof, prev_proof)
            .map_err(|e| {
                BalanceError::VerificationFailed(format!("Failed to prove update: {:?}", e))
            })?;
        Ok(proof)
    }

    pub fn prove_receive_transfer(
        &self,
        pubkey: U256,
        receive_transfer_witness: &ReceiveTransferWitness<F, C, D>,
        prev_proof: &Option<ProofWithPublicInputs<F, C, D>>,
    ) -> Result<ProofWithPublicInputs<F, C, D>, BalanceError> {
        let prev_balance_pis = get_prev_balance_pis(pubkey, prev_proof).map_err(|e| {
            BalanceError::InvalidInput(format!(
                "Failed to get previous balance public inputs: {:?}",
                e
            ))
        })?;
        let transition_proof = self
            .balance_transition_processor
            .prove_receive_transfer(
                &self.get_verifier_data(),
                &prev_balance_pis,
                receive_transfer_witness,
            )
            .map_err(BalanceError::Transition)?;
        let proof = self
            .balance_circuit
            .prove(pubkey, &transition_proof, prev_proof)
            .map_err(|e| {
                BalanceError::VerificationFailed(format!(
                    "Failed to prove receive transfer: {:?}",
                    e
                ))
            })?;
        Ok(proof)
    }

    pub fn prove_receive_deposit(
        &self,
        pubkey: U256,
        receive_deposit_witness: &ReceiveDepositWitness,
        prev_proof: &Option<ProofWithPublicInputs<F, C, D>>,
    ) -> Result<ProofWithPublicInputs<F, C, D>, BalanceError> {
        let prev_balance_pis = get_prev_balance_pis(pubkey, prev_proof).map_err(|e| {
            BalanceError::InvalidInput(format!(
                "Failed to get previous balance public inputs: {:?}",
                e
            ))
        })?;
        let transition_proof = self
            .balance_transition_processor
            .prove_receive_deposit(
                &self.get_verifier_data(),
                &prev_balance_pis,
                receive_deposit_witness,
            )
            .map_err(BalanceError::Transition)?;
        let proof = self
            .balance_circuit
            .prove(pubkey, &transition_proof, prev_proof)
            .map_err(|e| {
                BalanceError::VerificationFailed(format!(
                    "Failed to prove receive deposit: {:?}",
                    e
                ))
            })?;
        Ok(proof)
    }

    pub fn prove_spent(
        &self,
        spent_witness: &SpentWitness,
    ) -> Result<ProofWithPublicInputs<F, C, D>, BalanceError> {
        let proof = self
            .balance_transition_processor
            .sender_processor
            .prove_spent(spent_witness)?;
        Ok(proof)
    }
}

/// Get previous balance public inputs from previous balance proof
/// or create new balance public inputs from pubkey if no previous proof
pub fn get_prev_balance_pis<F, C, const D: usize>(
    pubkey: U256,
    prev_proof: &Option<ProofWithPublicInputs<F, C, D>>,
) -> Result<BalancePublicInputs, BalanceError>
where
    F: RichField + Extendable<D>,
    C: GenericConfig<D, F = F>,
{
    if let Some(prev_proof) = prev_proof {
        // Safely extract public inputs from the previous proof
        BalancePublicInputs::from_pis(&prev_proof.public_inputs)
    } else {
        Ok(BalancePublicInputs::new(pubkey))
    }
}

#[cfg(test)]
mod tests {
    use crate::{
        circuits::{
            balance::send::spent_circuit::SpentCircuit,
            test_utils::witness_generator::{construct_spent_and_transfer_witness, MockTxRequest},
        },
        common::{
            deposit::{get_pubkey_salt_hash, Deposit},
            private_state::FullPrivateState,
            salt::Salt,
            signature_content::key_set::KeySet,
            transfer::Transfer,
            witness::{
                deposit_witness::DepositWitness,
                private_transition_witness::PrivateTransitionWitness,
                receive_deposit_witness::ReceiveDepositWitness,
            },
        },
        ethereum_types::{address::Address, u256::U256, u32limb_trait::U32LimbTrait},
    };

    use plonky2::{
        field::goldilocks_field::GoldilocksField, plonk::config::PoseidonGoldilocksConfig,
    };
    use rand::Rng as _;
    use std::sync::Arc;

    use crate::circuits::{
        test_utils::state_manager::ValidityStateManager,
        validity::validity_processor::ValidityProcessor,
    };

    use super::BalanceProcessor;

    type F = GoldilocksField;
    type C = PoseidonGoldilocksConfig;
    const D: usize = 2;

    #[test]
    fn test_balance_processor_setup() {
        let validity_processor = ValidityProcessor::<F, C, D>::new();
        let _balance_processor =
            BalanceProcessor::new(&validity_processor.validity_circuit.data.verifier_data());
    }

    #[test]
    fn test_balance_processor_send() {
        let mut rng: rand::prelude::ThreadRng = rand::thread_rng();
        let validity_processor = Arc::new(ValidityProcessor::<F, C, D>::new());
        let balance_processor = BalanceProcessor::new(&validity_processor.get_verifier_data());
        let mut validity_state_manager =
            ValidityStateManager::new(validity_processor.clone(), Address::default());
        let spent_circuit = SpentCircuit::new();

        // local state
        let alice_key = KeySet::rand(&mut rng);
        let mut alice_state = FullPrivateState::new();

        // alice send transfer
        let transfer = Transfer::rand(&mut rng);

        let (spent_witness, _) =
            construct_spent_and_transfer_witness(&mut alice_state, &[transfer]).unwrap();
        let spent_witness_value = spent_witness.to_value().unwrap();
        let spent_proof = spent_circuit.prove(&spent_witness_value).unwrap();
        let tx_request = MockTxRequest {
            tx: spent_witness.tx,
            sender_key: alice_key,
            will_return_sig: true,
        };
        let tx_witnesses = validity_state_manager
            .tick(true, &[tx_request], 0, 0)
            .unwrap();
        let update_witness = validity_state_manager
            .get_update_witness(alice_key.pubkey, 1, 0, true)
            .unwrap();

        let _alice_balance_proof = balance_processor
            .prove_send(
                &validity_processor.get_verifier_data(),
                alice_key.pubkey,
                &tx_witnesses[0],
                &update_witness,
                &spent_proof,
                &None,
            )
            .unwrap();
    }

    #[test]
    fn test_balance_processor_update() {
        let mut rng = rand::thread_rng();
        let validity_processor = Arc::new(ValidityProcessor::<F, C, D>::new());
        let balance_processor = BalanceProcessor::new(&validity_processor.get_verifier_data());
        let mut validity_state_manager =
            ValidityStateManager::new(validity_processor.clone(), Address::default());

        // post empty block
        validity_state_manager.tick(false, &[], 0, 0).unwrap();

        // alice update balance
        let alice_key = KeySet::rand(&mut rng);
        let update_witness = validity_state_manager
            .get_update_witness(alice_key.pubkey, 1, 0, false)
            .unwrap();
        let _alice_balance_proof = balance_processor
            .prove_update(
                &validity_processor.get_verifier_data(),
                alice_key.pubkey,
                &update_witness,
                &None,
            )
            .unwrap();
    }

    #[test]
    #[cfg(feature = "skip_insufficient_check")]
    fn test_balance_processor_receive_transfer() {
        use rand::Rng;

        use crate::{
            common::{
                salt::Salt,
                witness::{
                    private_transition_witness::PrivateTransitionWitness,
                    receive_transfer_witness::ReceiveTransferWitness,
                },
            },
            ethereum_types::u256::U256,
        };

        let mut rng = rand::thread_rng();
        let validity_processor = Arc::new(ValidityProcessor::<F, C, D>::new());
        let balance_processor = BalanceProcessor::new(&validity_processor.get_verifier_data());
        let spent_circuit = SpentCircuit::new();

        // public state
        let mut validity_state_manager =
            ValidityStateManager::new(validity_processor.clone(), Address::default());

        // local state
        let alice_key = KeySet::rand(&mut rng);
        let mut alice_state = FullPrivateState::new();
        let bob_key = KeySet::rand(&mut rng);
        let mut bob_state = FullPrivateState::new();

        // alice send transfer
        let transfer = Transfer {
            recipient: bob_key.pubkey.into(),
            token_index: rng.gen(),
            amount: U256::rand_small(&mut rng),
            salt: Salt::rand(&mut rng),
        };

        let (spent_witness, transfer_witnesses) =
            construct_spent_and_transfer_witness(&mut alice_state, &[transfer]).unwrap();
        let transfer_witness = transfer_witnesses[0].clone();
        let spent_witness_value = spent_witness.to_value().unwrap();
        let spent_proof = spent_circuit.prove(&spent_witness_value).unwrap();
        let tx_request = MockTxRequest {
            tx: spent_witness.tx,
            sender_key: alice_key,
            will_return_sig: true,
        };
        let tx_witnesses = validity_state_manager
            .tick(true, &[tx_request], 0, 0)
            .unwrap();
        let tx_witness = tx_witnesses[0].clone();
        let update_witness = validity_state_manager
            .get_update_witness(alice_key.pubkey, 1, 0, true)
            .unwrap();
        let alice_balance_proof = balance_processor
            .prove_send(
                &validity_processor.get_verifier_data(),
                alice_key.pubkey,
                &tx_witness,
                &update_witness,
                &spent_proof,
                &None,
            )
            .unwrap();

        // bob update balance proof
        let update_witness = validity_state_manager
            .get_update_witness(bob_key.pubkey, 1, 0, false)
            .unwrap();
        let bob_balance_proof = balance_processor
            .prove_update(
                &validity_processor.get_verifier_data(),
                bob_key.pubkey,
                &update_witness,
                &None,
            )
            .unwrap();
        let private_transition_witness =
            PrivateTransitionWitness::from_transfer(&mut bob_state, transfer, Salt::rand(&mut rng))
                .unwrap();
        let block_merkle_proof = validity_state_manager.get_block_merkle_proof(1, 1).unwrap();
        let receive_transfer_witness = ReceiveTransferWitness {
            transfer_witness,
            private_transition_witness,
            sender_balance_proof: alice_balance_proof,
            block_merkle_proof,
        };
        balance_processor
            .prove_receive_transfer(
                bob_key.pubkey,
                &receive_transfer_witness,
                &Some(bob_balance_proof),
            )
            .unwrap();
    }

    #[test]
    fn test_balance_processor_receive_deposit() {
        let mut rng = rand::thread_rng();
        let validity_processor = Arc::new(ValidityProcessor::<F, C, D>::new());
        let balance_processor = BalanceProcessor::new(&validity_processor.get_verifier_data());
        let mut validity_state_manager =
            ValidityStateManager::new(validity_processor.clone(), Address::default());

        // local state
        let alice_key = KeySet::rand(&mut rng);
        let mut alice_state = FullPrivateState::new();

        // deposit
        let deposit_salt = Salt::rand(&mut rng);
        let deposit_salt_hash = get_pubkey_salt_hash(alice_key.pubkey, deposit_salt);
        let deposit = Deposit {
            depositor: Address::rand(&mut rng),
            pubkey_salt_hash: deposit_salt_hash,
            amount: U256::rand_small(&mut rng),
            token_index: rng.gen(),
            is_eligible: true,
        };
        let deposit_index = validity_state_manager.deposit(&deposit).unwrap();

        // post empty block to sync deposit tree
        validity_state_manager.tick(false, &[], 0, 0).unwrap();

        // alice update balance proof
        let update_witness = validity_state_manager
            .get_update_witness(alice_key.pubkey, 1, 0, false)
            .unwrap();
        let alice_balance_proof = balance_processor
            .prove_update(
                &validity_processor.get_verifier_data(),
                alice_key.pubkey,
                &update_witness,
                &None,
            )
            .unwrap();

        // alice receive deposit proof
        let deposit_merkle_proof = validity_state_manager
            .get_deposit_merkle_proof(1, deposit_index)
            .unwrap();
        let deposit_witness = DepositWitness {
            deposit_salt,
            deposit_index,
            deposit: deposit.clone(),
            deposit_merkle_proof,
        };
        let private_transition_witness = PrivateTransitionWitness::from_deposit(
            &mut alice_state,
            &deposit,
            Salt::rand(&mut rng),
        )
        .unwrap();
        let receive_deposit_witness = ReceiveDepositWitness {
            deposit_witness,
            private_transition_witness,
        };
        let _alice_balance_proof = balance_processor
            .prove_receive_deposit(
                alice_key.pubkey,
                &receive_deposit_witness,
                &Some(alice_balance_proof),
            )
            .unwrap();
    }
}
