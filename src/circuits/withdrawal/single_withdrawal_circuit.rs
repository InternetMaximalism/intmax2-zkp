//! Single withdrawal circuit for processing user withdrawals to Ethereum addresses.
//!
//! This circuit verifies that a transfer intended for withdrawal is included in a rollup block by:
//! 1. Verifying the balance proof is valid using TransferInclusionTarget
//! 2. Extracting the recipient's Ethereum address from the transfer
//! 3. Computing a unique nullifier to prevent double withdrawals
//! 4. Creating a withdrawal structure with all necessary information
//!
//! The withdrawal nullifier is stored in the withdrawal contract on Ethereum,
//! which prevents the same withdrawal from being processed twice.

use super::error::WithdrawalError;
use plonky2::{
    field::extension::Extendable,
    hash::hash_types::RichField,
    iop::witness::PartialWitness,
    plonk::{
        circuit_builder::CircuitBuilder,
        circuit_data::{CircuitConfig, CircuitData, VerifierCircuitData},
        config::{AlgebraicHasher, GenericConfig},
        proof::ProofWithPublicInputs,
    },
};

use crate::{
    circuits::balance::receive::receive_targets::transfer_inclusion::{
        TransferInclusionTarget, TransferInclusionValue,
    },
    common::withdrawal::{get_withdrawal_nullifier_circuit, WithdrawalTarget},
};

/// Circuit for verifying and processing a single withdrawal operation.
///
/// This circuit takes a balance proof containing a transfer and creates a withdrawal
/// that can be processed on Ethereum. It verifies that the transfer is valid and included
/// in a rollup block, then exposes the withdrawal information as public inputs.
#[derive(Debug)]
pub struct SingleWithdrawalCircuit<F, C, const D: usize>
where
    F: RichField + Extendable<D>,
    C: GenericConfig<D, F = F>,
{
    /// The circuit data containing the compiled circuit
    pub data: CircuitData<F, C, D>,

    /// Target for verifying transfer inclusion in a balance proof
    transfer_inclusion_target: TransferInclusionTarget<D>,
}

impl<F, C, const D: usize> SingleWithdrawalCircuit<F, C, D>
where
    F: RichField + Extendable<D>,
    C: GenericConfig<D, F = F> + 'static,
    C::Hasher: AlgebraicHasher<F>,
{
    /// Creates a new SingleWithdrawalCircuit that verifies a transfer and creates a withdrawal.
    ///
    /// This function:
    /// 1. Creates a circuit that verifies the transfer inclusion in a balance proof
    /// 2. Computes a unique nullifier for the withdrawal to prevent double-spending
    /// 3. Extracts the recipient's Ethereum address from the transfer
    /// 4. Creates a withdrawal structure with all necessary information
    /// 5. Registers the withdrawal data as public inputs
    ///
    /// # Arguments
    /// * `balance_vd` - Verifier data for the balance circuit
    ///
    /// # Returns
    /// A new SingleWithdrawalCircuit ready to verify withdrawals
    pub fn new(balance_vd: &VerifierCircuitData<F, C, D>) -> Self {
        let mut builder =
            CircuitBuilder::<F, D>::new(CircuitConfig::standard_recursion_zk_config());

        // Create transfer inclusion target to verify the transfer is valid and included in a block
        let transfer_inclusion_target =
            TransferInclusionTarget::new::<F, C>(&balance_vd.common, &mut builder, true);

        // Connect the balance circuit verifier data to ensure we're using the correct circuit
        let balance_vd_target = builder.constant_verifier_data(&balance_vd.verifier_only);
        builder.connect_verifier_data(
            &transfer_inclusion_target.balance_circuit_vd,
            &balance_vd_target,
        );

        // Extract the transfer from the inclusion target
        let transfer = transfer_inclusion_target.transfer.clone();

        // Compute the withdrawal nullifier to prevent double withdrawals
        let nullifier = get_withdrawal_nullifier_circuit(&mut builder, &transfer);

        // Convert the recipient from GenericAddress to Ethereum Address
        let recipient = transfer.recipient.to_address(&mut builder);

        // Create the withdrawal target with all necessary information
        let withdrawal = WithdrawalTarget {
            recipient,                         // Ethereum address to receive funds
            token_index: transfer.token_index, // Token type being withdrawn
            amount: transfer.amount,           // Amount being withdrawn
            nullifier,                         // Unique identifier to prevent double withdrawals
            block_hash: transfer_inclusion_target.public_state.block_hash, /* Block hash for
                                                * verification */
            block_number: transfer_inclusion_target.public_state.block_number, /* Block number for verification */
        };

        // Register the withdrawal data as public inputs
        builder.register_public_inputs(&withdrawal.to_vec());

        // Build the circuit
        let data = builder.build();
        Self {
            data,
            transfer_inclusion_target,
        }
    }

    pub fn prove(
        &self,
        transfer_inclusion_value: &TransferInclusionValue<F, C, D>,
    ) -> Result<ProofWithPublicInputs<F, C, D>, WithdrawalError> {
        let mut pw = PartialWitness::<F>::new();
        self.transfer_inclusion_target
            .set_witness(&mut pw, transfer_inclusion_value);
        self.data
            .prove(pw)
            .map_err(|e| WithdrawalError::ProofGenerationError(format!("{:?}", e)))
    }

    pub fn verify(&self, proof: &ProofWithPublicInputs<F, C, D>) -> Result<(), WithdrawalError> {
        self.data.verify(proof.clone()).map_err(|e| {
            WithdrawalError::VerificationFailed(format!("Proof verification failed: {:?}", e))
        })
    }
}

#[cfg(test)]
mod tests {
    use crate::{
        circuits::{
            balance::{
                balance_processor::BalanceProcessor,
                receive::receive_targets::transfer_inclusion::TransferInclusionValue,
            },
            test_utils::witness_generator::{construct_spent_and_transfer_witness, MockTxRequest},
        },
        common::{
            private_state::FullPrivateState, salt::Salt, signature_content::key_set::KeySet,
            transfer::Transfer,
        },
        ethereum_types::{address::Address, u256::U256, u32limb_trait::U32LimbTrait},
    };
    use plonky2::{
        field::goldilocks_field::GoldilocksField, plonk::config::PoseidonGoldilocksConfig,
    };
    use rand::Rng;

    use crate::circuits::test_utils::state_manager::ValidityStateManager;

    type F = GoldilocksField;
    type C = PoseidonGoldilocksConfig;
    const D: usize = 2;

    #[test]
    fn test_single_withdrawal_circuit() {
        use std::sync::Arc;

        use crate::circuits::{
            validity::validity_processor::ValidityProcessor,
            withdrawal::single_withdrawal_circuit::SingleWithdrawalCircuit,
        };

        let mut rng = rand::thread_rng();
        let validity_processor = Arc::new(ValidityProcessor::<F, C, D>::new());
        let mut validity_state_manager =
            ValidityStateManager::new(validity_processor.clone(), Address::default());
        let balance_processor = BalanceProcessor::new(&validity_processor.get_verifier_data());

        let key = KeySet::rand(&mut rng);
        let mut full_private_state = FullPrivateState::new();

        // generate withdrawal transfer
        let transfer = Transfer {
            recipient: Address::rand(&mut rng).into(),
            token_index: rng.gen(),
            amount: U256::zero(), // because the user don't have balance
            salt: Salt::rand(&mut rng),
        };
        let (spent_witness, transfer_witnesses) =
            construct_spent_and_transfer_witness(&mut full_private_state, &[transfer]).unwrap();
        let transfer_witness = transfer_witnesses[0].clone();
        let spent_proof = balance_processor
            .balance_transition_processor
            .sender_processor
            .prove_spent(&spent_witness)
            .unwrap();

        // post block
        let tx_request = MockTxRequest {
            tx: spent_witness.tx,
            sender_key: key,
            will_return_sig: true,
        };
        let tx_witnesses = validity_state_manager
            .tick(true, &[tx_request], 0, 0)
            .unwrap();
        let tx_witness = tx_witnesses[0].clone();
        let update_witness = validity_state_manager
            .get_update_witness(key.pubkey, 1, 0, true)
            .unwrap();

        let balance_proof = balance_processor
            .prove_send(
                &validity_processor.get_verifier_data(),
                key.pubkey,
                &tx_witness,
                &update_witness,
                &spent_proof,
                &None,
            )
            .unwrap();

        let transfer_inclusion_value = TransferInclusionValue::new(
            &balance_processor.get_verifier_data(),
            &transfer_witness.transfer,
            transfer_witness.transfer_index,
            &transfer_witness.transfer_merkle_proof,
            &transfer_witness.tx,
            &balance_proof,
        )
        .unwrap();

        let single_withdrawal_circuit =
            SingleWithdrawalCircuit::<F, C, D>::new(&balance_processor.get_verifier_data());
        let single_withdrawal_proof = single_withdrawal_circuit
            .prove(&transfer_inclusion_value)
            .unwrap();

        single_withdrawal_circuit
            .verify(&single_withdrawal_proof)
            .unwrap();
    }
}
