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
        balance_pis::BalancePublicInputs,
        send::{error::SendError, spent_circuit::SpentPublicInputs},
    },
    common::witness::{
        spent_witness::SpentWitness, tx_witness::TxWitness, update_witness::UpdateWitness,
    },
};

use super::{
    sender_circuit::{SenderCircuit, SenderValue},
    spent_circuit::SpentCircuit,
    tx_inclusion_circuit::{TxInclusionCircuit, TxInclusionValue},
};

pub struct SenderProcessor<F, C, const D: usize>
where
    F: RichField + Extendable<D>,
    C: GenericConfig<D, F = F>,
{
    pub spent_circuit: SpentCircuit<F, C, D>,
    pub tx_inclusion_circuit: TxInclusionCircuit<F, C, D>,
    pub sender_circuit: SenderCircuit<F, C, D>,
}

impl<F, C, const D: usize> SenderProcessor<F, C, D>
where
    F: RichField + Extendable<D>,
    C: GenericConfig<D, F = F> + 'static,
    <C as GenericConfig<D>>::Hasher: AlgebraicHasher<F>,
{
    pub fn new(validity_vd: &VerifierCircuitData<F, C, D>) -> Self {
        let spent_circuit = SpentCircuit::new();
        let tx_inclusion_circuit = TxInclusionCircuit::new(validity_vd);
        let sender_circuit = SenderCircuit::new(
            &spent_circuit.data.verifier_data(),
            &tx_inclusion_circuit.data.verifier_data(),
        );
        Self {
            spent_circuit,
            tx_inclusion_circuit,
            sender_circuit,
        }
    }

    pub fn prove_spent(
        &self,
        spent_witness: &SpentWitness,
    ) -> Result<ProofWithPublicInputs<F, C, D>, SendError> {
        let spent_value = spent_witness
            .to_value()
            .map_err(|e| SendError::InvalidInput(format!("Failed to create spent value: {}", e)))?;
        self.spent_circuit
            .prove(&spent_value)
            .map_err(|e| SendError::ProofGenerationError(format!("Failed to prove spent: {}", e)))
    }

    pub fn prove_send(
        &self,
        validity_vd: &VerifierCircuitData<F, C, D>,
        prev_balance_pis: &BalancePublicInputs,
        tx_witness: &TxWitness,
        update_witness: &UpdateWitness<F, C, D>,
        spent_proof: &ProofWithPublicInputs<F, C, D>,
    ) -> Result<ProofWithPublicInputs<F, C, D>, SendError> {
        let spent_pis = SpentPublicInputs::from_pis(&spent_proof.public_inputs);

        if spent_pis.prev_private_commitment != prev_balance_pis.private_commitment {
            return Err(SendError::InvalidInput(format!(
                "Prev private commitment mismatch: expected {:?}, got {:?}",
                prev_balance_pis.private_commitment, spent_pis.prev_private_commitment
            )));
        }

        if spent_pis.tx != tx_witness.tx {
            return Err(SendError::InvalidInput(format!(
                "TX mismatch: expected {:?}, got {:?}",
                tx_witness.tx, spent_pis.tx
            )));
        }

        let tx_inclusion_proof =
            self.prove_tx_inclusion(validity_vd, prev_balance_pis, tx_witness, update_witness)?;

        let sender_value = SenderValue::new(
            &self.spent_circuit,
            &self.tx_inclusion_circuit,
            spent_proof,
            &tx_inclusion_proof,
            prev_balance_pis,
        )
        .map_err(|e| SendError::InvalidInput(format!("Failed to create sender value: {}", e)))?;

        self.sender_circuit
            .prove(&sender_value)
            .map_err(|e| SendError::ProofGenerationError(format!("Failed to prove sender: {}", e)))
    }

    fn prove_tx_inclusion(
        &self,
        validity_vd: &VerifierCircuitData<F, C, D>,
        prev_balance_pis: &BalancePublicInputs,
        tx_witness: &TxWitness,
        update_witness: &UpdateWitness<F, C, D>,
    ) -> Result<ProofWithPublicInputs<F, C, D>, SendError> {
        let update_validity_pis = update_witness.validity_pis();
        if update_validity_pis != tx_witness.validity_pis {
            return Err(SendError::InvalidInput(format!(
                "Validity proof pis mismatch: expected {:?}, got {:?}",
                tx_witness.validity_pis, update_validity_pis
            )));
        }

        let sender_tree = tx_witness.get_sender_tree();
        let sender_leaf = sender_tree.get_leaf(tx_witness.tx_index as u64);

        if sender_leaf.sender != prev_balance_pis.pubkey {
            return Err(SendError::InvalidInput(format!(
                "Sender pubkey mismatch: expected {}, got {}",
                prev_balance_pis.pubkey, sender_leaf.sender
            )));
        }

        let sender_merkle_proof = sender_tree.prove(tx_witness.tx_index as u64);
        let tx_inclusion_value = TxInclusionValue::new(
            validity_vd,
            prev_balance_pis.pubkey,
            &prev_balance_pis.public_state,
            &update_witness.validity_proof,
            &update_witness.block_merkle_proof,
            &update_witness
                .prev_account_membership_proof()
                .map_err(|e| {
                    SendError::InvalidInput(format!(
                        "Failed to get prev account membership proof: {}",
                        e
                    ))
                })?,
            tx_witness.tx_index,
            &tx_witness.tx,
            &tx_witness.tx_merkle_proof,
            &sender_leaf,
            &sender_merkle_proof,
        )
        .map_err(|e| {
            SendError::InvalidInput(format!("Failed to create tx inclusion value: {}", e))
        })?;

        self.tx_inclusion_circuit
            .prove(&tx_inclusion_value)
            .map_err(|e| {
                SendError::ProofGenerationError(format!("Failed to prove tx inclusion: {}", e))
            })
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use plonky2::{
        field::goldilocks_field::GoldilocksField, plonk::config::PoseidonGoldilocksConfig,
    };

    use crate::{
        circuits::{
            balance::balance_pis::BalancePublicInputs,
            test_utils::{
                state_manager::ValidityStateManager,
                witness_generator::{construct_spent_and_transfer_witness, MockTxRequest},
            },
            validity::validity_processor::ValidityProcessor,
        },
        common::{
            private_state::FullPrivateState, signature_content::key_set::KeySet, transfer::Transfer,
        },
        ethereum_types::address::Address,
    };

    use super::SenderProcessor;

    type F = GoldilocksField;
    type C = PoseidonGoldilocksConfig;
    const D: usize = 2;

    #[test]
    fn test_sender_processor() {
        let mut rng = rand::thread_rng();

        let key = KeySet::rand(&mut rng);
        let mut full_private_state = FullPrivateState::new();

        let validity_processor = Arc::new(ValidityProcessor::<F, C, D>::new());
        let validity_vd = validity_processor.get_verifier_data();
        let mut validity_state_manager =
            ValidityStateManager::new(validity_processor.clone(), Address::default());

        let transfer = Transfer::rand(&mut rng);
        let (spent_witness, _) =
            construct_spent_and_transfer_witness(&mut full_private_state, &[transfer]).unwrap();

        let tx_request = MockTxRequest {
            tx: spent_witness.tx,
            sender_key: key,
            will_return_sig: true,
        };
        let tx_witnesses = validity_state_manager
            .tick(true, &[tx_request], 0, 0)
            .unwrap();
        let block_number = validity_state_manager.get_block_number();

        let tx_witness = tx_witnesses[0].clone();
        let update_witness = validity_state_manager
            .get_update_witness(key.pubkey, block_number, 0, true)
            .unwrap();

        let prev_balance_pis = &BalancePublicInputs::new(key.pubkey);
        let sender_processor = SenderProcessor::new(&validity_vd);

        let spent_proof = sender_processor
            .spent_circuit
            .prove(&spent_witness.to_value().unwrap())
            .unwrap();
        let sender_proof = sender_processor
            .prove_send(
                &validity_vd,
                prev_balance_pis,
                &tx_witness,
                &update_witness,
                &spent_proof,
            )
            .unwrap();

        sender_processor
            .sender_circuit
            .data
            .verify(sender_proof)
            .unwrap();
    }
}
