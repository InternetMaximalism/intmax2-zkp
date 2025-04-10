//! Transfer inclusion circuit for verifying transfers in balance proofs.
//!
//! This circuit verifies that a transfer is included in a transaction by:
//! 1. Verifying the balance proof is valid
//! 2. Checking that the last_tx_hash in the balance PIs corresponds to the tx containing the
//!    transfer
//! 3. Verifying that the corresponding insufficient flag is false
//! 4. Validating the transfer's inclusion in the transfer merkle tree
//!
//! This circuit is used when receiving tokens, allowing recipients to verify
//! that a sender's balance proof includes the transfer they're claiming.

use super::error::ReceiveTargetsError;
use crate::{
    circuits::balance::balance_pis::{BalancePublicInputs, BalancePublicInputsTarget},
    common::{
        public_state::{PublicState, PublicStateTarget},
        transfer::{Transfer, TransferTarget},
        trees::transfer_tree::{TransferMerkleProof, TransferMerkleProofTarget},
        tx::{Tx, TxTarget},
    },
    constants::TRANSFER_TREE_HEIGHT,
    utils::{
        cyclic::{vd_from_pis_slice, vd_from_pis_slice_target},
        leafable::{Leafable as _, LeafableTarget},
    },
};
use plonky2::{
    field::extension::Extendable,
    hash::hash_types::RichField,
    iop::{target::Target, witness::WitnessWrite},
    plonk::{
        circuit_builder::CircuitBuilder,
        circuit_data::{
            CommonCircuitData, VerifierCircuitData, VerifierCircuitTarget, VerifierOnlyCircuitData,
        },
        config::{AlgebraicHasher, GenericConfig},
        proof::{ProofWithPublicInputs, ProofWithPublicInputsTarget},
    },
};

/// TransferInclusionValue contains all the data needed to verify that a transfer
/// is included in a transaction and that the corresponding balance proof is valid.
///
/// This structure is used when receiving tokens, allowing recipients to verify
/// that a sender's balance proof includes the transfer they're claiming.
#[derive(Debug, Clone)]
pub struct TransferInclusionValue<
    F: RichField + Extendable<D>,
    C: GenericConfig<D, F = F> + 'static,
    const D: usize,
> {
    pub transfer: Transfer,  // Transfer to be proved included
    pub transfer_index: u32, // The index of the transfer in the transfer merkle tree
    pub transfer_merkle_proof: TransferMerkleProof, // Merkle proof for transfer inclusion
    pub tx: Tx,              // Transaction that includes the transfer
    pub balance_proof: ProofWithPublicInputs<F, C, D>, // Balance proof that includes the tx
    pub balance_circuit_vd: VerifierOnlyCircuitData<C, D>, // Balance circuit verifier data
    pub public_state: PublicState, // Public state from the balance proof
}

impl<F: RichField + Extendable<D>, C: GenericConfig<D, F = F>, const D: usize>
    TransferInclusionValue<F, C, D>
where
    <C as GenericConfig<D>>::Hasher: AlgebraicHasher<F>,
{
    /// Creates a new TransferInclusionValue by validating the transfer's inclusion in a
    /// transaction.
    ///
    /// This function:
    /// 1. Parses and verifies the balance proof
    /// 2. Checks that the last_tx_hash in the balance PIs matches the tx hash
    /// 3. Verifies that the corresponding insufficient flag is false
    /// 4. Validates the transfer's inclusion in the transfer merkle tree
    ///
    /// # Arguments
    /// * `balance_vd` - Verifier data for the balance circuit
    /// * `transfer` - Transfer to be verified
    /// * `transfer_index` - Index of the transfer in the transfer merkle tree
    /// * `transfer_merkle_proof` - Merkle proof for the transfer
    /// * `tx` - Transaction that includes the transfer
    /// * `balance_proof` - Balance proof that includes the transaction
    ///
    /// # Returns
    /// A Result containing either the new TransferInclusionValue or an error
    pub fn new(
        balance_vd: &VerifierCircuitData<F, C, D>,
        transfer: &Transfer,
        transfer_index: u32,
        transfer_merkle_proof: &TransferMerkleProof,
        tx: &Tx,
        balance_proof: &ProofWithPublicInputs<F, C, D>,
    ) -> Result<Self, ReceiveTargetsError> {
        let balance_pis =
            BalancePublicInputs::from_pis(&balance_proof.public_inputs).map_err(|e| {
                ReceiveTargetsError::VerificationFailed(format!(
                    "Failed to parse balance public inputs: {}",
                    e
                ))
            })?;
        let balance_circuit_vd = vd_from_pis_slice::<F, C, D>(
            &balance_proof.public_inputs,
            &balance_vd.common.config,
        )
        .map_err(|e| {
            ReceiveTargetsError::VerificationFailed(format!("Failed to parse balance vd: {}", e))
        })?;

        if balance_circuit_vd != balance_vd.verifier_only {
            return Err(ReceiveTargetsError::VerificationFailed(
                "Balance vd mismatch".to_string(),
            ));
        }

        balance_vd
            .verify(balance_proof.clone())
            .map_err(|e| {
                ReceiveTargetsError::VerificationFailed(format!(
                    "Failed to verify balance proof: {}",
                    e
                ))
            })?;

        if balance_pis.last_tx_hash != tx.hash() {
            return Err(ReceiveTargetsError::VerificationFailed(format!(
                "Last tx hash mismatch: expected {:?}, got {:?}",
                tx.hash(),
                balance_pis.last_tx_hash
            )));
        }

        let _is_insufficient = balance_pis
            .last_tx_insufficient_flags
            .random_access(transfer_index as usize);

        #[cfg(not(feature = "skip_insufficient_check"))]
        if _is_insufficient {
            return Err(ReceiveTargetsError::VerificationFailed(format!(
                "Transfer is insufficient at index {}",
                transfer_index
            )));
        }

        // check merkle proof
        transfer_merkle_proof
            .verify(transfer, transfer_index as u64, tx.transfer_tree_root)
            .map_err(|e| {
                ReceiveTargetsError::VerificationFailed(format!(
                    "Invalid transfer merkle proof: {}",
                    e
                ))
            })?;

        Ok(Self {
            transfer: *transfer,
            transfer_index,
            transfer_merkle_proof: transfer_merkle_proof.clone(),
            tx: *tx,
            balance_proof: balance_proof.clone(),
            balance_circuit_vd,
            public_state: balance_pis.public_state.clone(),
        })
    }
}

/// Target version of TransferInclusionValue for use in ZKP circuits.
///
/// This struct contains circuit targets for all components needed to verify
/// a transfer's inclusion in a transaction and the validity of the balance proof.
#[derive(Debug, Clone)]
pub struct TransferInclusionTarget<const D: usize> {
    pub transfer: TransferTarget,
    pub transfer_index: Target,
    pub transfer_merkle_proof: TransferMerkleProofTarget,
    pub tx: TxTarget,
    pub balance_proof: ProofWithPublicInputsTarget<D>,
    pub balance_circuit_vd: VerifierCircuitTarget,
    pub public_state: PublicStateTarget,
}

impl<const D: usize> TransferInclusionTarget<D> {
    /// Creates a new TransferInclusionTarget with circuit constraints that enforce
    /// the transfer inclusion verification rules.
    ///
    /// The circuit enforces:
    /// 1. Valid balance proof verification
    /// 2. Matching last_tx_hash with the tx hash
    /// 3. False insufficient flag for the transfer
    /// 4. Valid transfer merkle proof
    ///
    /// # Arguments
    /// * `balance_common_data` - Common circuit data for the balance circuit
    /// * `builder` - Circuit builder
    /// * `is_checked` - Whether to add constraints for checking the values
    ///
    /// # Returns
    /// A new TransferInclusionTarget with all necessary targets and constraints
    pub fn new<F: RichField + Extendable<D>, C: GenericConfig<D, F = F> + 'static>(
        balance_common_data: &CommonCircuitData<F, D>,
        builder: &mut CircuitBuilder<F, D>,
        is_checked: bool,
    ) -> Self
    where
        <C as GenericConfig<D>>::Hasher: AlgebraicHasher<F>,
    {
        let transfer = TransferTarget::new(builder, is_checked);
        let transfer_index = builder.add_virtual_target();
        let transfer_merkle_proof = TransferMerkleProofTarget::new(builder, TRANSFER_TREE_HEIGHT);
        let tx = TxTarget::new(builder);

        let balance_proof = builder.add_virtual_proof_with_pis(balance_common_data);
        let balance_pis = BalancePublicInputsTarget::from_pis(&balance_proof.public_inputs);
        let balance_circuit_vd =
            vd_from_pis_slice_target(&balance_proof.public_inputs, &balance_common_data.config)
                .expect("Failed to parse balance vd");
        builder.verify_proof::<C>(&balance_proof, &balance_circuit_vd, balance_common_data);

        let tx_hash = tx.hash::<F, C, D>(builder);
        balance_pis.last_tx_hash.connect(builder, tx_hash);
        let _is_insufficient = balance_pis
            .last_tx_insufficient_flags
            .random_access(builder, transfer_index);
        #[cfg(not(feature = "skip_insufficient_check"))]
        builder.assert_zero(_is_insufficient.target);
        // check merkle proof
        transfer_merkle_proof.verify::<F, C, D>(
            builder,
            &transfer,
            transfer_index,
            tx.transfer_tree_root,
        );
        Self {
            transfer,
            transfer_index,
            transfer_merkle_proof,
            tx,
            balance_proof,
            balance_circuit_vd,
            public_state: balance_pis.public_state,
        }
    }

    /// Sets the witness values for all targets in this TransferInclusionTarget.
    ///
    /// # Arguments
    /// * `witness` - Witness to set values in
    /// * `value` - TransferInclusionValue containing the values to set
    pub fn set_witness<
        F: RichField + Extendable<D>,
        C: GenericConfig<D, F = F>,
        W: WitnessWrite<F>,
    >(
        &self,
        witness: &mut W,
        value: &TransferInclusionValue<F, C, D>,
    ) where
        <C as GenericConfig<D>>::Hasher: AlgebraicHasher<F>,
    {
        self.transfer.set_witness(witness, value.transfer);
        witness.set_target(
            self.transfer_index,
            F::from_canonical_u32(value.transfer_index),
        );
        self.transfer_merkle_proof
            .set_witness(witness, &value.transfer_merkle_proof);
        self.tx.set_witness(witness, value.tx);
        witness.set_proof_with_pis_target(&self.balance_proof, &value.balance_proof);
        witness.set_verifier_data_target(&self.balance_circuit_vd, &value.balance_circuit_vd);
        self.public_state.set_witness(witness, &value.public_state);
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use plonky2::{
        field::goldilocks_field::GoldilocksField,
        iop::witness::PartialWitness,
        plonk::{
            circuit_builder::CircuitBuilder, circuit_data::CircuitConfig,
            config::PoseidonGoldilocksConfig,
        },
    };
    use rand::Rng;

    use crate::{
        circuits::{
            balance::{
                balance_processor::BalanceProcessor,
                receive::receive_targets::transfer_inclusion::TransferInclusionTarget,
                send::spent_circuit::SpentCircuit,
            },
            test_utils::{
                state_manager::ValidityStateManager,
                witness_generator::{construct_spent_and_transfer_witness, MockTxRequest},
            },
            validity::validity_processor::ValidityProcessor,
        },
        common::{
            private_state::FullPrivateState, salt::Salt, signature_content::key_set::KeySet,
            transfer::Transfer,
        },
        ethereum_types::{address::Address, u256::U256, u32limb_trait::U32LimbTrait},
    };

    use super::TransferInclusionValue;

    type F = GoldilocksField;
    type C = PoseidonGoldilocksConfig;
    const D: usize = 2;

    #[test]
    fn test_transfer_inclusion() {
        let mut rng = rand::thread_rng();
        let validity_processor = Arc::new(ValidityProcessor::<F, C, D>::new());
        let balance_processor = BalanceProcessor::new(&validity_processor.get_verifier_data());
        let spent_circuit = SpentCircuit::new();
        let mut validity_state_manager =
            ValidityStateManager::new(validity_processor.clone(), Address::default());

        // local state
        let alice_key = KeySet::rand(&mut rng);
        let mut alice_state = FullPrivateState::new();

        // alice send transfer
        let transfer = Transfer {
            recipient: Address::rand(&mut rng).into(),
            token_index: rng.gen(),
            amount: U256::zero(), // should be zero, otherwise it will be cause insufficient balance
            salt: Salt::rand(&mut rng),
        };

        let (spent_witness, transfer_witnesses) =
            construct_spent_and_transfer_witness(&mut alice_state, &[transfer]).unwrap();
        let spent_proof = spent_circuit
            .prove(&spent_witness.to_value().unwrap())
            .unwrap();
        let tx_request = MockTxRequest {
            tx: spent_witness.tx,
            sender_key: alice_key,
            will_return_sig: true,
        };
        let transfer_witness = transfer_witnesses[0].clone();
        let tx_witnesses = validity_state_manager
            .tick(true, &[tx_request], 0, 0)
            .unwrap();
        let update_witness = validity_state_manager
            .get_update_witness(alice_key.pubkey, 1, 0, true)
            .unwrap();
        let alice_balance_proof = balance_processor
            .prove_send(
                &validity_processor.get_verifier_data(),
                alice_key.pubkey,
                &tx_witnesses[0],
                &update_witness,
                &spent_proof,
                &None,
            )
            .unwrap();

        let transfer_inclusion_value = TransferInclusionValue::new(
            &balance_processor.get_verifier_data(),
            &transfer,
            transfer_witness.transfer_index,
            &transfer_witness.transfer_merkle_proof,
            &transfer_witness.tx,
            &alice_balance_proof,
        )
        .unwrap();

        let mut builder = CircuitBuilder::new(CircuitConfig::default());
        let target = TransferInclusionTarget::new::<F, C>(
            &balance_processor.get_verifier_data().common,
            &mut builder,
            true,
        );
        let mut pw = PartialWitness::<F>::new();
        target.set_witness(&mut pw, &transfer_inclusion_value);

        let data = builder.build::<C>();
        let proof = data.prove(pw).unwrap();
        data.verify(proof.clone()).unwrap();
    }
}
