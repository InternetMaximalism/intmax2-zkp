pub mod single_withdrawal_circuit;

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use plonky2::{
        field::goldilocks_field::GoldilocksField, plonk::config::PoseidonGoldilocksConfig,
    };

    use crate::{
        circuits::{
            balance::balance_processor::BalanceProcessor,
            test_utils::{
                state_manager::ValidityStateManager,
                witness_generator::{construct_spent_and_transfer_witness, MockTxRequest},
            },
            validity::validity_processor::ValidityProcessor,
            withdrawal::single_withdrawal_circuit::SingleWithdrawalCircuit,
        },
        common::{
            generic_address::GenericAddress, private_state::FullPrivateState, salt::Salt,
            signature::key_set::KeySet, transfer::Transfer,
            witness::withdrawal_witness::WithdrawalWitness,
        },
        ethereum_types::address::Address,
        utils::{hash_chain::hash_chain_processor::HashChainProcessor, wrapper::WrapperCircuit},
        wrapper_config::plonky2_config::PoseidonBN128GoldilocksConfig,
    };

    type F = GoldilocksField;
    type C = PoseidonGoldilocksConfig;
    type OuterC = PoseidonBN128GoldilocksConfig;
    const D: usize = 2;

    #[test]
    fn withdrawal_processor() -> anyhow::Result<()> {
        let mut rng = rand::thread_rng();
        let validity_processor = Arc::new(ValidityProcessor::<F, C, D>::new());
        let balance_processor = BalanceProcessor::new(&validity_processor.get_verifier_data());
        let mut validity_state_manager = ValidityStateManager::new(validity_processor.clone());
        let spent_circuit = balance_processor.spent_circuit();
        let single_withdrawal_circuit =
            SingleWithdrawalCircuit::new(balance_processor.common_data());
        let withdrawal_processor =
            HashChainProcessor::new(&single_withdrawal_circuit.data.verifier_data());

        let inner_wrapper_circuit = WrapperCircuit::<F, C, C, D>::new(
            &withdrawal_processor.chain_end_circuit.data.verifier_data(),
        );
        let final_circuit =
            WrapperCircuit::<F, C, OuterC, D>::new(&inner_wrapper_circuit.data.verifier_data());

        // withdraw transfer
        let mut private_state = FullPrivateState::new();
        let key = KeySet::rand(&mut rng);
        let transfer = Transfer {
            recipient: GenericAddress::from_address(Address::default()),
            token_index: 0,
            amount: 0.into(),
            salt: Salt::default(),
        };
        let (spent_witness, transfer_witnesses) =
            construct_spent_and_transfer_witness(&mut private_state, &[transfer])?;
        let spent_proof = spent_circuit.prove(&spent_witness.to_value()?)?;
        let tx_request = MockTxRequest {
            tx: spent_witness.tx,
            sender_key: key,
            will_return_sig: true,
        };
        let tx_witnesses = validity_state_manager.tick(true, &[tx_request], 0)?;
        let update_witness = validity_state_manager.get_update_witness(key.pubkey, 1, 0, true)?;

        let balance_proof = balance_processor.prove_send(
            &validity_processor.get_verifier_data(),
            key.pubkey,
            &tx_witnesses[0],
            &update_witness,
            &spent_proof,
            &None,
        )?;
        let transfer_witness = transfer_witnesses[0].clone();

        let withdrawal_witness = WithdrawalWitness {
            transfer_witness,
            balance_proof,
        };
        let transition_inclusion_value = withdrawal_witness
            .to_transition_inclusion_value(&balance_processor.get_verifier_data())?;
        let single_withdrawal_proof =
            single_withdrawal_circuit.prove(&transition_inclusion_value)?;
        let chained_withdrawal_proof =
            withdrawal_processor.prove_chain(&single_withdrawal_proof, &None)?;
        let wrapped_withdrawal_proof =
            withdrawal_processor.prove_end(&chained_withdrawal_proof, Address::default())?;

        let inner_wrapper_proof = inner_wrapper_circuit.prove(&wrapped_withdrawal_proof)?;
        let final_proof = final_circuit.prove(&inner_wrapper_proof)?;

        println!(
            "Final circuit degree: {}",
            final_circuit.data.common.degree_bits()
        );

        let final_proof_str = serde_json::to_string_pretty(&final_proof)?;
        let final_circuit_vd = serde_json::to_string_pretty(&final_circuit.data.verifier_only)?;
        let final_circuit_cd = serde_json::to_string_pretty(&final_circuit.data.common)?;
        // save to files
        std::fs::create_dir_all("circuit_data/withdrawal")?;
        std::fs::write(
            "circuit_data/withdrawal/proof_with_public_inputs.json",
            final_proof_str,
        )?;
        std::fs::write(
            "circuit_data/withdrawal/verifier_only_circuit_data.json",
            final_circuit_vd,
        )?;
        std::fs::write(
            "circuit_data/withdrawal/common_circuit_data.json",
            final_circuit_cd,
        )?;
        Ok(())
    }
}
