//! Receive transfer circuit for verifying and processing incoming transfers.
//!
//! This circuit proves the correctness of a private state transition when receiving a transfer by:
//! 1. Verifying the transfer is included in the sender's balance proof (`transfer_inclusion`)
//! 2. Confirming the sender's block hash is included in the recipient's block tree
//! 3. Adding the transfer's nullifier to the nullifier tree to prevent double-spending
//! 4. Adding the transfer to the asset tree, updating the recipient's balance
//!
//! The receive transfer circuit handles private state transitions without updating
//! public state, so no validity proof is required.

use super::error::ReceiveError;
use crate::{
    common::{
        public_state::{PublicState, PublicStateTarget, PUBLIC_STATE_LEN},
        trees::block_hash_tree::{BlockHashMerkleProof, BlockHashMerkleProofTarget},
    },
    constants::BLOCK_HASH_TREE_HEIGHT,
    ethereum_types::{
        u256::{U256Target, U256},
        u32limb_trait::{U32LimbTargetTrait as _, U32LimbTrait},
    },
    utils::{
        conversion::ToU64 as _,
        cyclic::{vd_from_pis_slice, vd_from_pis_slice_target, vd_to_vec, vd_to_vec_target},
        dummy::DummyProof,
        poseidon_hash_out::{PoseidonHashOut, PoseidonHashOutTarget},
    },
};
use plonky2::{
    field::extension::Extendable,
    hash::hash_types::RichField,
    iop::{
        target::Target,
        witness::{PartialWitness, WitnessWrite},
    },
    plonk::{
        circuit_builder::CircuitBuilder,
        circuit_data::{
            CircuitConfig, CircuitData, CommonCircuitData, VerifierCircuitTarget,
            VerifierOnlyCircuitData,
        },
        config::{AlgebraicHasher, GenericConfig},
        proof::ProofWithPublicInputs,
    },
};

use super::receive_targets::{
    private_state_transition::{PrivateStateTransitionTarget, PrivateStateTransitionValue},
    transfer_inclusion::{TransferInclusionTarget, TransferInclusionValue},
};

/// Public inputs for the receive transfer circuit.
///
/// This struct contains all the public inputs needed to verify a receive transfer proof:
/// - Previous and new private state commitments to verify state transition
/// - Recipient's public key
/// - Public state containing the block tree root for block hash verification
/// - Balance circuit verifier data for transfer inclusion verification
#[derive(Debug, Clone)]
pub struct ReceiveTransferPublicInputs<
    F: RichField + Extendable<D>,
    C: GenericConfig<D, F = F>,
    const D: usize,
> {
    pub prev_private_commitment: PoseidonHashOut,
    pub new_private_commitment: PoseidonHashOut,
    pub pubkey: U256,
    pub public_state: PublicState,
    pub balance_circuit_vd: VerifierOnlyCircuitData<C, D>,
}

impl<F: RichField + Extendable<D>, C: GenericConfig<D, F = F>, const D: usize>
    ReceiveTransferPublicInputs<F, C, D>
where
    <C as GenericConfig<D>>::Hasher: AlgebraicHasher<F>,
{
    pub fn to_vec(&self, config: &CircuitConfig) -> Vec<F> {
        let mut vec = [
            self.prev_private_commitment.to_u64_vec(),
            self.new_private_commitment.to_u64_vec(),
            self.pubkey.to_u64_vec(),
            self.public_state.to_u64_vec(),
        ]
        .concat()
        .into_iter()
        .map(|x| F::from_canonical_u64(x))
        .collect::<Vec<_>>();
        vec.extend(vd_to_vec(config, &self.balance_circuit_vd));
        vec
    }

    pub fn from_slice(config: &CircuitConfig, input: &[F]) -> Self {
        let non_vd = input[0..16 + PUBLIC_STATE_LEN].to_u64_vec();
        let prev_private_commitment = PoseidonHashOut::from_u64_slice(&non_vd[0..4])
            .unwrap_or_else(|e| panic!("Failed to create PoseidonHashOut from u64 slice: {}", e));
        let new_private_commitment = PoseidonHashOut::from_u64_slice(&non_vd[4..8])
            .unwrap_or_else(|e| panic!("Failed to create PoseidonHashOut from u64 slice: {}", e));
        let pubkey = U256::from_u64_slice(&non_vd[8..16]).unwrap();
        let public_state = PublicState::from_u64_slice(&non_vd[16..16 + PUBLIC_STATE_LEN]);
        let balance_circuit_vd = vd_from_pis_slice(input, config).unwrap();
        ReceiveTransferPublicInputs {
            prev_private_commitment,
            new_private_commitment,
            pubkey,
            public_state,
            balance_circuit_vd,
        }
    }
}

/// Target version of ReceiveTransferPublicInputs for use in ZKP circuits.
///
/// This struct contains circuit targets for all components needed to verify
/// a receive transfer proof in the circuit.
#[derive(Debug, Clone)]
pub struct ReceiveTransferPublicInputsTarget {
    pub prev_private_commitment: PoseidonHashOutTarget,
    pub new_private_commitment: PoseidonHashOutTarget,
    pub pubkey: U256Target,
    pub public_state: PublicStateTarget,
    pub balance_circuit_vd: VerifierCircuitTarget,
}

impl ReceiveTransferPublicInputsTarget {
    pub fn to_vec(&self, config: &CircuitConfig) -> Vec<Target> {
        let mut vec = [
            self.prev_private_commitment.to_vec(),
            self.new_private_commitment.to_vec(),
            self.pubkey.to_vec(),
            self.public_state.to_vec(),
        ]
        .concat();
        vec.extend(vd_to_vec_target(config, &self.balance_circuit_vd));
        vec
    }

    pub fn from_slice(config: &CircuitConfig, input: &[Target]) -> Self {
        let prev_private_commitment = PoseidonHashOutTarget::from_slice(&input[0..4]);
        let new_private_commitment = PoseidonHashOutTarget::from_slice(&input[4..8]);
        let pubkey = U256Target::from_slice(&input[8..16]);
        let public_state = PublicStateTarget::from_slice(&input[16..16 + PUBLIC_STATE_LEN]);
        let balance_circuit_vd = vd_from_pis_slice_target(input, config).unwrap();
        ReceiveTransferPublicInputsTarget {
            prev_private_commitment,
            new_private_commitment,
            pubkey,
            public_state,
            balance_circuit_vd,
        }
    }
}

/// Contains all the data needed to verify a receive transfer operation.
///
/// This struct holds all the components required to prove the correctness of a private state
/// transition when receiving a transfer:
/// - Recipient's public key
/// - Public state with block tree root for block hash verification
/// - Block merkle proof to verify sender's block hash inclusion
/// - Transfer inclusion data to verify the transfer is in the sender's balance proof
/// - Private state transition data for asset and nullifier tree updates
/// - Previous and new private state commitments
/// - Balance circuit verifier data for transfer inclusion verification
#[derive(Debug, Clone)]
pub struct ReceiveTransferValue<
    F: RichField + Extendable<D>,
    C: GenericConfig<D, F = F> + 'static,
    const D: usize,
> {
    pub pubkey: U256,
    pub public_state: PublicState,
    pub block_merkle_proof: BlockHashMerkleProof,
    pub transfer_inclusion: TransferInclusionValue<F, C, D>,
    pub private_state_transition: PrivateStateTransitionValue,
    pub prev_private_commitment: PoseidonHashOut,
    pub new_private_commitment: PoseidonHashOut,
    pub balance_circuit_vd: VerifierOnlyCircuitData<C, D>,
}

impl<F: RichField + Extendable<D>, C: GenericConfig<D, F = F>, const D: usize>
    ReceiveTransferValue<F, C, D>
{
    /// Creates a new ReceiveTransferValue by validating and computing the state transition.
    ///
    /// This function:
    /// 1. Verifies the sender's block hash is included in the recipient's block tree
    /// 2. Extracts the transfer and computes its nullifier
    /// 3. Verifies the recipient's public key matches the transfer recipient
    /// 4. Validates that the private state transition matches the transfer (token index, amount, nullifier)
    /// 5. Computes the private state commitments
    ///
    /// # Arguments
    /// * `public_state` - Recipient's public state with block tree root
    /// * `block_merkle_proof` - Proof that sender's block hash is in recipient's block tree
    /// * `transfer_inclusion` - Data proving the transfer is in sender's balance proof
    /// * `private_state_transition` - Data for updating recipient's private state
    ///
    /// # Returns
    /// A Result containing either the new ReceiveTransferValue or an error
    pub fn new(
        public_state: &PublicState,
        block_merkle_proof: &BlockHashMerkleProof,
        transfer_inclusion: &TransferInclusionValue<F, C, D>,
        private_state_transition: &PrivateStateTransitionValue,
    ) -> Result<Self, ReceiveError>
    where
        C::Hasher: AlgebraicHasher<F>,
    {
        // verify public state inclusion
        block_merkle_proof
            .verify(
                &transfer_inclusion.public_state.block_hash,
                transfer_inclusion.public_state.block_number as u64,
                public_state.block_tree_root,
            )
            .map_err(|e| {
                ReceiveError::VerificationFailed(format!(
                    "Block merkle proof verification failed: {:?}",
                    e
                ))
            })?;

        let transfer = transfer_inclusion.transfer;
        let nullifier = transfer.nullifier();
        let pubkey = transfer.recipient.to_pubkey().map_err(|e| {
            ReceiveError::VerificationFailed(format!("Transfer recipient is not pubkey: {:?}", e))
        })?;

        if private_state_transition.token_index != transfer.token_index {
            return Err(ReceiveError::VerificationFailed(format!(
                "Token index mismatch: expected {}, got {}",
                transfer.token_index, private_state_transition.token_index
            )));
        }

        if private_state_transition.amount != transfer.amount {
            return Err(ReceiveError::VerificationFailed(format!(
                "Amount mismatch: expected {:?}, got {:?}",
                transfer.amount, private_state_transition.amount
            )));
        }

        if private_state_transition.nullifier != nullifier {
            return Err(ReceiveError::VerificationFailed(format!(
                "Nullifier mismatch: expected {:?}, got {:?}",
                nullifier, private_state_transition.nullifier
            )));
        }

        let prev_private_commitment = private_state_transition.prev_private_state.commitment();
        let new_private_commitment = private_state_transition.new_private_state.commitment();
        let balance_circuit_vd = transfer_inclusion.balance_circuit_vd.clone();

        Ok(ReceiveTransferValue {
            pubkey,
            public_state: public_state.clone(),
            block_merkle_proof: block_merkle_proof.clone(),
            transfer_inclusion: transfer_inclusion.clone(),
            private_state_transition: private_state_transition.clone(),
            prev_private_commitment,
            new_private_commitment,
            balance_circuit_vd,
        })
    }
}

/// Target version of ReceiveTransferValue for use in ZKP circuits.
///
/// This struct contains circuit targets for all components needed to verify
/// a receive transfer operation in the circuit, including:
/// - Block hash verification targets
/// - Transfer inclusion verification targets
/// - Private state transition targets
/// - Commitment targets for the private state before and after the transfer
#[derive(Debug, Clone)]
pub struct ReceiveTransferTarget<const D: usize> {
    pub pubkey: U256Target,
    pub public_state: PublicStateTarget,
    pub block_merkle_proof: BlockHashMerkleProofTarget,
    pub transfer_inclusion: TransferInclusionTarget<D>,
    pub private_state_transition: PrivateStateTransitionTarget,
    pub prev_private_commitment: PoseidonHashOutTarget,
    pub new_private_commitment: PoseidonHashOutTarget,
    pub balance_circuit_vd: VerifierCircuitTarget,
}

impl<const D: usize> ReceiveTransferTarget<D> {
    /// Creates a new ReceiveTransferTarget with circuit constraints that enforce
    /// the receive transfer verification rules.
    ///
    /// The circuit enforces:
    /// 1. Valid block hash inclusion in the recipient's block tree
    /// 2. Valid transfer inclusion in the sender's balance proof
    /// 3. Matching token index, amount, and nullifier between transfer and private state transition
    /// 4. Correct computation of private state commitments
    ///
    /// # Arguments
    /// * `balance_common_data` - Common circuit data for the balance circuit
    /// * `builder` - Circuit builder
    /// * `is_checked` - Whether to add constraints for checking the values
    ///
    /// # Returns
    /// A new ReceiveTransferTarget with all necessary targets and constraints
    pub fn new<F: RichField + Extendable<D>, C: GenericConfig<D, F = F> + 'static>(
        balance_common_data: &CommonCircuitData<F, D>,
        builder: &mut CircuitBuilder<F, D>,
        is_checked: bool,
    ) -> Self
    where
        <C as GenericConfig<D>>::Hasher: AlgebraicHasher<F>,
    {
        let public_state = PublicStateTarget::new(builder, is_checked);
        let block_merkle_proof = BlockHashMerkleProofTarget::new(builder, BLOCK_HASH_TREE_HEIGHT);
        let transfer_inclusion =
            TransferInclusionTarget::new::<F, C>(balance_common_data, builder, is_checked);
        let private_state_transition =
            PrivateStateTransitionTarget::new::<F, C, D>(builder, is_checked);
        block_merkle_proof.verify::<F, C, D>(
            builder,
            &transfer_inclusion.public_state.block_hash,
            transfer_inclusion.public_state.block_number,
            public_state.block_tree_root,
        );

        let transfer = transfer_inclusion.transfer.clone();
        let nullifier = transfer.nullifier(builder);
        let pubkey = transfer.recipient.to_pubkey(builder);
        builder.connect(private_state_transition.token_index, transfer.token_index);
        private_state_transition
            .amount
            .connect(builder, transfer.amount);
        private_state_transition
            .nullifier
            .connect(builder, nullifier);

        let prev_private_commitment = private_state_transition
            .prev_private_state
            .commitment(builder);
        let new_private_commitment = private_state_transition
            .new_private_state
            .commitment(builder);
        let balance_circuit_vd = transfer_inclusion.balance_circuit_vd.clone();
        ReceiveTransferTarget {
            pubkey,
            public_state,
            block_merkle_proof,
            transfer_inclusion,
            private_state_transition,
            prev_private_commitment,
            new_private_commitment,
            balance_circuit_vd,
        }
    }

    /// Sets the witness values for all targets in this ReceiveTransferTarget.
    ///
    /// # Arguments
    /// * `witness` - Witness to set values in
    /// * `value` - ReceiveTransferValue containing the values to set
    pub fn set_witness<
        F: RichField + Extendable<D>,
        C: GenericConfig<D, F = F>,
        W: WitnessWrite<F>,
    >(
        &self,
        witness: &mut W,
        value: &ReceiveTransferValue<F, C, D>,
    ) where
        <C as GenericConfig<D>>::Hasher: AlgebraicHasher<F>,
    {
        self.pubkey.set_witness(witness, value.pubkey);
        self.public_state.set_witness(witness, &value.public_state);
        self.block_merkle_proof
            .set_witness(witness, &value.block_merkle_proof);
        self.transfer_inclusion
            .set_witness(witness, &value.transfer_inclusion);
        self.private_state_transition
            .set_witness(witness, &value.private_state_transition);
        self.prev_private_commitment
            .set_witness(witness, value.prev_private_commitment);
        self.new_private_commitment
            .set_witness(witness, value.new_private_commitment);
        witness.set_verifier_data_target(&self.balance_circuit_vd, &value.balance_circuit_vd);
    }
}

/// Main circuit for verifying receive transfer operations.
///
/// This circuit combines all the components needed to verify a receive transfer:
/// - Block hash verification
/// - Transfer inclusion verification
/// - Private state transition verification
///
/// It provides methods to build the circuit and generate proofs that can be
/// verified by others to confirm the correctness of a receive transfer operation.
pub struct ReceiveTransferCircuit<F, C, const D: usize>
where
    F: RichField + Extendable<D>,
    C: GenericConfig<D, F = F>,
{
    pub data: CircuitData<F, C, D>,
    pub target: ReceiveTransferTarget<D>,
    pub dummy_proof: DummyProof<F, C, D>,
}

impl<F, C, const D: usize> ReceiveTransferCircuit<F, C, D>
where
    F: RichField + Extendable<D>,
    C: GenericConfig<D, F = F> + 'static,
    C::Hasher: AlgebraicHasher<F>,
{
    /// Creates a new ReceiveTransferCircuit with all necessary constraints.
    ///
    /// This function:
    /// 1. Creates a new circuit builder
    /// 2. Adds all targets and constraints for receive transfer verification
    /// 3. Registers the public inputs
    /// 4. Builds the circuit
    ///
    /// # Arguments
    /// * `balance_common_data` - Common circuit data for the balance circuit
    ///
    /// # Returns
    /// A new ReceiveTransferCircuit ready to generate proofs
    pub fn new(balance_common_data: &CommonCircuitData<F, D>) -> Self {
        let config = CircuitConfig::default();
        let mut builder = CircuitBuilder::<F, D>::new(config.clone());
        let target =
            ReceiveTransferTarget::<D>::new::<F, C>(balance_common_data, &mut builder, true);
        let pis = ReceiveTransferPublicInputsTarget {
            pubkey: target.pubkey,
            prev_private_commitment: target.prev_private_commitment,
            new_private_commitment: target.new_private_commitment,
            public_state: target.public_state.clone(),
            balance_circuit_vd: target.balance_circuit_vd.clone(),
        };
        builder.register_public_inputs(&pis.to_vec(&config));
        let data = builder.build();
        let dummy_proof = DummyProof::new(&data.common);
        Self {
            data,
            target,
            dummy_proof,
        }
    }

    /// Generates a proof for the given receive transfer value.
    ///
    /// This function:
    /// 1. Creates a partial witness
    /// 2. Sets all witness values from the provided ReceiveTransferValue
    /// 3. Generates a proof that can be verified by others
    ///
    /// # Arguments
    /// * `value` - ReceiveTransferValue containing all the data needed for the proof
    ///
    /// # Returns
    /// A Result containing either the proof or an error if proof generation fails
    pub fn prove(
        &self,
        value: &ReceiveTransferValue<F, C, D>,
    ) -> Result<ProofWithPublicInputs<F, C, D>, ReceiveError> {
        let mut pw = PartialWitness::<F>::new();
        self.target.set_witness(&mut pw, value);
        self.data
            .prove(pw)
            .map_err(|e| ReceiveError::ProofGenerationError(format!("{:?}", e)))
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use plonky2::{
        field::goldilocks_field::GoldilocksField, plonk::config::PoseidonGoldilocksConfig,
    };
    use rand::Rng;

    use crate::{
        circuits::{
            balance::{balance_processor::BalanceProcessor, send::spent_circuit::SpentCircuit},
            test_utils::{
                state_manager::ValidityStateManager,
                witness_generator::{construct_spent_and_transfer_witness, MockTxRequest},
            },
            validity::validity_processor::ValidityProcessor,
        },
        common::{
            private_state::FullPrivateState, salt::Salt, signature_content::key_set::KeySet,
            transfer::Transfer, witness::private_transition_witness::PrivateTransitionWitness,
        },
        ethereum_types::{address::Address, u256::U256, u32limb_trait::U32LimbTrait},
    };

    use super::{ReceiveTransferValue, TransferInclusionValue};

    type F = GoldilocksField;
    type C = PoseidonGoldilocksConfig;
    const D: usize = 2;

    #[test]
    fn test_receive_transfer_circuit() {
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
            recipient: U256::rand(&mut rng).into(),
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
        let private_state_transition = PrivateTransitionWitness::from_transfer(
            &mut alice_state,
            transfer,
            Salt::rand(&mut rng),
        )
        .unwrap();
        let public_state = update_witness.public_state();
        let block_merkle_proof = validity_state_manager.get_block_merkle_proof(1, 1).unwrap();

        let receive_transfer_value = ReceiveTransferValue::new(
            &public_state,
            &block_merkle_proof,
            &transfer_inclusion_value,
            &private_state_transition.to_value().unwrap(),
        )
        .unwrap();
        let receive_transfer_circuit =
            super::ReceiveTransferCircuit::<F, C, D>::new(&balance_processor.common_data());

        let proof = receive_transfer_circuit
            .prove(&receive_transfer_value)
            .unwrap();
        receive_transfer_circuit.data.verify(proof).unwrap();
    }
}
