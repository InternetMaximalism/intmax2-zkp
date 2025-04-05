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
        send::{
            error::SendError,
            spent_circuit::SpentPublicInputs
        }
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
            .map_err(|e| SendError::InvalidInput(
                format!("Failed to create spent value: {}", e)
            ))?;
        self.spent_circuit
            .prove(&spent_value)
            .map_err(|e| SendError::ProofGenerationError(
                format!("Failed to prove spent: {}", e)
            ))
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
            return Err(SendError::InvalidInput(
                format!("Validity proof pis mismatch: expected {:?}, got {:?}", 
                    tx_witness.validity_pis, update_validity_pis)
            ));
        }
        
        let sender_tree = tx_witness.get_sender_tree();
        let sender_leaf = sender_tree.get_leaf(tx_witness.tx_index as u64);
        
        if sender_leaf.sender != prev_balance_pis.pubkey {
            return Err(SendError::InvalidInput(
                format!("Sender pubkey mismatch: expected {}, got {}", 
                    prev_balance_pis.pubkey, sender_leaf.sender)
            ));
        }
        
        let sender_merkle_proof = sender_tree.prove(tx_witness.tx_index as u64);
        let tx_inclusion_value = TxInclusionValue::new(
            validity_vd,
            prev_balance_pis.pubkey,
            &prev_balance_pis.public_state,
            &update_witness.validity_proof,
            &update_witness.block_merkle_proof,
            &update_witness.prev_account_membership_proof()
                .map_err(|e| SendError::InvalidInput(
                    format!("Failed to get prev account membership proof: {}", e)
                ))?,
            tx_witness.tx_index,
            &tx_witness.tx,
            &tx_witness.tx_merkle_proof,
            &sender_leaf,
            &sender_merkle_proof,
        )
        .map_err(|e| SendError::InvalidInput(
            format!("Failed to create tx inclusion value: {}", e)
        ))?;
        
        self.tx_inclusion_circuit
            .prove(&tx_inclusion_value)
            .map_err(|e| SendError::ProofGenerationError(
                format!("Failed to prove tx inclusion: {}", e)
            ))
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
            return Err(SendError::InvalidInput(
                format!("Prev private commitment mismatch: expected {:?}, got {:?}", 
                    prev_balance_pis.private_commitment, spent_pis.prev_private_commitment)
            ));
        }
        
        if spent_pis.tx != tx_witness.tx {
            return Err(SendError::InvalidInput(
                format!("TX mismatch: expected {:?}, got {:?}", 
                    tx_witness.tx, spent_pis.tx)
            ));
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
        .map_err(|e| SendError::InvalidInput(
            format!("Failed to create sender value: {}", e)
        ))?;
        
        self.sender_circuit
            .prove(&sender_value)
            .map_err(|e| SendError::ProofGenerationError(
                format!("Failed to prove sender: {}", e)
            ))
    }
}

// #[cfg(test)]
// mod tests {
//     use plonky2::{
//         field::goldilocks_field::GoldilocksField, plonk::config::PoseidonGoldilocksConfig,
//     };

//     use crate::{
//         common::{generic_address::GenericAddress, salt::Salt, transfer::Transfer},
//         ethereum_types::u256::U256,
//     };

//     use super::SenderProcessor;

//     type F = GoldilocksField;
//     type C = PoseidonGoldilocksConfig;
//     const D: usize = 2;

//     #[test]
//     fn sender_processor() {
//         let mut rng = rand::thread_rng();
//         let mut block_builder = MockBlockBuilder::new();
//         let mut wallet = MockWallet::new_rand(&mut rng);
//         let mut sync_prover = SyncValidityProver::<F, C, D>::new();
//         let sender_processor =
//             SenderProcessor::new(&sync_prover.validity_processor.validity_circuit);

//         let transfer = Transfer {
//             recipient: GenericAddress::rand_pubkey(&mut rng),
//             token_index: 0,
//             amount: U256::rand_small(&mut rng),
//             salt: Salt::rand(&mut rng),
//         };

//         // send tx
//         let send_witness = wallet.send_tx_and_update(&mut rng, &mut block_builder, &[transfer]);
//         sync_prover.sync(&block_builder);

//         let block_number = send_witness.get_included_block_number();
//         let prev_block_number = send_witness.get_prev_block_number();
//         println!(
//             "block_number: {}, prev_block_number: {}",
//             block_number, prev_block_number
//         );
//         let update_witness = sync_prover.get_update_witness(
//             &block_builder,
//             wallet.get_pubkey(),
//             block_builder.last_block_number(),
//             prev_block_number,
//             true,
//         );

//         sender_processor
//             .prove(
//                 &sync_prover.validity_processor.validity_circuit,
//                 &send_witness,
//                 &update_witness,
//             )
//             .unwrap();
//     }
// }
