use anyhow::Result;
use plonky2::{
    field::extension::Extendable,
    hash::hash_types::RichField,
    plonk::{
        circuit_data::CommonCircuitData,
        config::{AlgebraicHasher, GenericConfig},
        proof::ProofWithPublicInputs,
    },
};

use crate::{
    ethereum_types::{
        address::Address,
        bytes32::{Bytes32, BYTES32_LEN},
        u32limb_trait::U32LimbTrait as _,
    },
    utils::conversion::ToU64,
};

use super::{
    single_withdrawal_circuit::SingleWithdrawalCircuit, withdrawal_circuit::WithdrawalCircuit,
    withdrawal_inner_circuit::WithdrawalInnerCircuit,
    withdrawal_wrapper_circuit::WithdrawalWrapperCircuit,
};

pub struct WithdrawalProcessor<F, C, const D: usize>
where
    F: RichField + Extendable<D>,
    C: GenericConfig<D, F = F>,
{
    pub single_withdrawal_circuit: SingleWithdrawalCircuit<F, C, D>,
    pub withdrawal_inner_circuit: WithdrawalInnerCircuit<F, C, D>,
    pub withdrawal_circuit: WithdrawalCircuit<F, C, D>,
    pub withdrawal_wrapper_circuit: WithdrawalWrapperCircuit<F, C, D>,
}

impl<F, C, const D: usize> WithdrawalProcessor<F, C, D>
where
    F: RichField + Extendable<D>,
    C: GenericConfig<D, F = F> + 'static,
    C::Hasher: AlgebraicHasher<F>,
{
    pub fn new(balance_common_data: &CommonCircuitData<F, D>) -> Self {
        let single_withdrawal_circuit = SingleWithdrawalCircuit::new(balance_common_data);
        let withdrawal_inner_circuit =
            WithdrawalInnerCircuit::new(&single_withdrawal_circuit.data.verifier_data());
        let withdrawal_circuit =
            WithdrawalCircuit::new(&withdrawal_inner_circuit.data.verifier_data());
        let withdrawal_wrapper_circuit =
            WithdrawalWrapperCircuit::new(&withdrawal_circuit.data.verifier_data());
        Self {
            single_withdrawal_circuit,
            withdrawal_inner_circuit,
            withdrawal_circuit,
            withdrawal_wrapper_circuit,
        }
    }

    // Prove a withdrawal chain, given a single withdrawal proof and the previous withdrawal proof.
    pub fn prove_chain(
        &self,
        single_withdrawal_proof: &ProofWithPublicInputs<F, C, D>,
        prev_withdrawal_proof: &Option<ProofWithPublicInputs<F, C, D>>,
    ) -> Result<ProofWithPublicInputs<F, C, D>> {
        let prev_withdrawal_hash = if prev_withdrawal_proof.is_some() {
            Bytes32::from_u64_slice(
                &prev_withdrawal_proof.as_ref().unwrap().public_inputs[0..BYTES32_LEN].to_u64_vec(),
            )
        } else {
            Bytes32::default()
        };
        let withdrawal_inner_proof = self
            .withdrawal_inner_circuit
            .prove(prev_withdrawal_hash, single_withdrawal_proof)
            .map_err(|e| anyhow::anyhow!("Failed to prove withdrawal inner: {}", e))?;
        let withdrawal_proof = self
            .withdrawal_circuit
            .prove(&withdrawal_inner_proof, prev_withdrawal_proof)
            .map_err(|e| anyhow::anyhow!("Failed to prove withdrawal: {}", e))?;
        Ok(withdrawal_proof)
    }

    pub fn prove_wrap(
        &self,
        withdrawal_proof: &ProofWithPublicInputs<F, C, D>,
        withdrawal_aggregator: Address,
    ) -> Result<ProofWithPublicInputs<F, C, D>> {
        let withdrawal_wrapper_proof = self
            .withdrawal_wrapper_circuit
            .prove(withdrawal_proof, withdrawal_aggregator)?;
        Ok(withdrawal_wrapper_proof)
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
        utils::wrapper::WrapperCircuit,
        wrapper_config::plonky2_config::PoseidonBN128GoldilocksConfig,
    };

    use super::WithdrawalProcessor;

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
        let withdrawal_processor = WithdrawalProcessor::new(balance_processor.common_data());
        let inner_wrapper_circuit = WrapperCircuit::<F, C, C, D>::new(
            &withdrawal_processor
                .withdrawal_wrapper_circuit
                .data
                .verifier_data(),
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
        let tx_witnesses = validity_state_manager.tick(true, &[tx_request])?;
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
            withdrawal_processor.prove_wrap(&chained_withdrawal_proof, Address::default())?;

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
        std::fs::create_dir_all("circuit_data")?;
        std::fs::write(
            "circuit_data/proof_with_public_inputs.json",
            final_proof_str,
        )?;
        std::fs::write(
            "circuit_data/verifier_only_circuit_data.json",
            final_circuit_vd,
        )?;
        std::fs::write("circuit_data/common_circuit_data.json", final_circuit_cd)?;
        Ok(())
    }
}
