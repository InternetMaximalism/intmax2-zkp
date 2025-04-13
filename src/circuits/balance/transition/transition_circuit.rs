//! Transition circuit for aggregating different balance state transitions.
//!
//! This circuit serves as a proof aggregation layer that switches between four different
//! transition types based on circuit flags:
//! 1. ReceiveTransfer - Processes incoming transfers by verifying transfer inclusion and updating
//!    private state
//! 2. ReceiveDeposit - Processes deposits by verifying deposit inclusion and updating private state
//! 3. Update - Updates the user's public state without modifying private state
//! 4. Sender - Updates both public and private states when sending transactions
//!
//! The transition circuit selects which transition to apply based on circuit flags,
//! verifies the corresponding proof, and computes the new balance public inputs.

use super::error::TransitionError;
use plonky2::{
    field::extension::Extendable,
    hash::hash_types::{HashOutTarget, RichField},
    iop::{
        target::{BoolTarget, Target},
        witness::{PartialWitness, WitnessWrite},
    },
    plonk::{
        circuit_builder::CircuitBuilder,
        circuit_data::{
            CircuitConfig, CircuitData, VerifierCircuitData, VerifierCircuitTarget,
            VerifierOnlyCircuitData,
        },
        config::{AlgebraicHasher, GenericConfig},
        proof::{ProofWithPublicInputs, ProofWithPublicInputsTarget},
    },
};

use crate::{
    circuits::balance::{
        balance_pis::{BalancePublicInputs, BalancePublicInputsTarget},
        receive::{
            receive_deposit_circuit::{
                ReceiveDepositCircuit, ReceiveDepositPublicInputs, ReceiveDepositPublicInputsTarget,
            },
            receive_transfer_circuit::{
                ReceiveTransferCircuit, ReceiveTransferPublicInputs,
                ReceiveTransferPublicInputsTarget,
            },
            update_circuit::{UpdateCircuit, UpdatePublicInputs, UpdatePublicInputsTarget},
        },
        send::sender_circuit::{SenderCircuit, SenderPublicInputs, SenderPublicInputsTarget},
    },
    ethereum_types::u32limb_trait::U32LimbTargetTrait as _,
    utils::{
        conversion::ToU64,
        cyclic::conditionally_connect_vd,
        poseidon_hash_out::{PoseidonHashOut, PoseidonHashOutTarget},
        recursively_verifiable::add_proof_target_and_conditionally_verify,
    },
};

#[derive(Debug, Clone, Copy, PartialEq)]
pub enum BalanceTransitionType {
    ReceiveTransfer = 0,
    ReceiveDeposit = 1,
    Update = 2,
    Sender = 3,
}

/// Values required for the balance transition circuit.
///
/// This struct contains all the data needed to prove a valid transition between
/// balance states using one of the four transition types (ReceiveTransfer, ReceiveDeposit,
/// Update, or Sender). It holds the proofs for each transition type, but only one
/// will be verified based on the circuit_type flag.
#[derive(Debug, Clone)]
pub struct BalanceTransitionValue<
    F: RichField + Extendable<D>,
    C: GenericConfig<D, F = F>,
    const D: usize,
> {
    pub circuit_type: BalanceTransitionType, // Type of transition to apply
    pub circuit_flags: [bool; 4],            // Flags for each transition type (only one is true)
    pub receive_transfer_proof: Option<ProofWithPublicInputs<F, C, D>>, // Proof for ReceiveTransfer
    pub receive_deposit_proof: Option<ProofWithPublicInputs<F, C, D>>, // Proof for ReceiveDeposit
    pub update_proof: Option<ProofWithPublicInputs<F, C, D>>, // Proof for Update
    pub sender_proof: Option<ProofWithPublicInputs<F, C, D>>, // Proof for Sender
    pub prev_balance_pis: BalancePublicInputs, // Previous balance public inputs
    pub new_balance_pis: BalancePublicInputs, // New balance public inputs (witness)
    pub new_balance_pis_commitment: PoseidonHashOut, // Commitment to new balance public inputs
    pub balance_circuit_vd: VerifierOnlyCircuitData<C, D>, // Verifier data for balance circuit
}

impl<F: RichField + Extendable<D>, C: GenericConfig<D, F = F>, const D: usize>
    BalanceTransitionValue<F, C, D>
where
    <C as GenericConfig<D>>::Hasher: AlgebraicHasher<F>,
{
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        config: &CircuitConfig,
        circuit_type: BalanceTransitionType,
        receive_transfer_circuit: &ReceiveTransferCircuit<F, C, D>,
        receive_deposit_circuit: &ReceiveDepositCircuit<F, C, D>,
        update_circuit: &UpdateCircuit<F, C, D>,
        sender_circuit: &SenderCircuit<F, C, D>,
        receive_transfer_proof: Option<ProofWithPublicInputs<F, C, D>>,
        receive_deposit_proof: Option<ProofWithPublicInputs<F, C, D>>,
        update_proof: Option<ProofWithPublicInputs<F, C, D>>,
        sender_proof: Option<ProofWithPublicInputs<F, C, D>>,
        prev_balance_pis: BalancePublicInputs,
        balance_circuit_vd: VerifierOnlyCircuitData<C, D>,
    ) -> Result<Self, TransitionError> {
        let mut circuit_flags = [false; 4];
        circuit_flags[circuit_type as usize] = true;

        let new_balance_pis = match circuit_type {
            BalanceTransitionType::ReceiveTransfer => {
                let receive_transfer_proof = receive_transfer_proof.clone().ok_or_else(|| {
                    TransitionError::InvalidValue("receive_transfer_proof is None".to_string())
                })?;

                receive_transfer_circuit
                    .data
                    .verify(receive_transfer_proof.clone())
                    .map_err(|e| {
                        TransitionError::VerificationFailed(format!(
                            "receive_transfer_proof is invalid: {}",
                            e
                        ))
                    })?;

                let pis = ReceiveTransferPublicInputs::<F, C, D>::from_slice(
                    config,
                    &receive_transfer_proof.public_inputs,
                );

                if pis.balance_circuit_vd != balance_circuit_vd {
                    return Err(TransitionError::VerificationFailed(
                        "balance_circuit_vd mismatch in receive_transfer_proof".to_string(),
                    ));
                }

                if pis.prev_private_commitment != prev_balance_pis.private_commitment {
                    return Err(TransitionError::VerificationFailed(
                        "prev_private_commitment mismatch in receive_transfer_proof".to_string(),
                    ));
                }

                if pis.pubkey != prev_balance_pis.pubkey {
                    return Err(TransitionError::VerificationFailed(
                        "pubkey mismatch in receive_transfer_proof".to_string(),
                    ));
                }

                if pis.public_state != prev_balance_pis.public_state {
                    return Err(TransitionError::VerificationFailed(
                        "public_state mismatch in receive_transfer_proof".to_string(),
                    ));
                }

                BalancePublicInputs {
                    pubkey: pis.pubkey,
                    private_commitment: pis.new_private_commitment,
                    ..prev_balance_pis.clone()
                }
            }
            BalanceTransitionType::ReceiveDeposit => {
                let receive_deposit_proof = receive_deposit_proof.clone().ok_or_else(|| {
                    TransitionError::InvalidValue("receive_deposit_proof is None".to_string())
                })?;

                receive_deposit_circuit
                    .data
                    .verify(receive_deposit_proof.clone())
                    .map_err(|e| {
                        TransitionError::VerificationFailed(format!(
                            "receive_deposit_proof is invalid: {}",
                            e
                        ))
                    })?;

                let pis = ReceiveDepositPublicInputs::from_u64_slice(
                    &receive_deposit_proof
                        .public_inputs
                        .iter()
                        .map(|x| x.to_canonical_u64())
                        .collect::<Vec<_>>(),
                )
                .map_err(|e| {
                    TransitionError::VerificationFailed(format!(
                        "Failed to parse receive_deposit_proof public inputs: {}",
                        e
                    ))
                })?;

                if pis.prev_private_commitment != prev_balance_pis.private_commitment {
                    return Err(TransitionError::VerificationFailed(
                        "prev_private_commitment mismatch in receive_deposit_proof".to_string(),
                    ));
                }

                if pis.pubkey != prev_balance_pis.pubkey {
                    return Err(TransitionError::VerificationFailed(
                        "pubkey mismatch in receive_deposit_proof".to_string(),
                    ));
                }

                if pis.public_state != prev_balance_pis.public_state {
                    return Err(TransitionError::VerificationFailed(
                        "public_state mismatch in receive_deposit_proof".to_string(),
                    ));
                }

                BalancePublicInputs {
                    pubkey: pis.pubkey,
                    private_commitment: pis.new_private_commitment,
                    ..prev_balance_pis.clone()
                }
            }
            BalanceTransitionType::Update => {
                let update_proof = update_proof.clone().ok_or_else(|| {
                    TransitionError::InvalidValue("update_proof is None".to_string())
                })?;

                update_circuit
                    .data
                    .verify(update_proof.clone())
                    .map_err(|e| {
                        TransitionError::VerificationFailed(format!(
                            "update_proof is invalid: {}",
                            e
                        ))
                    })?;

                let pis =
                    UpdatePublicInputs::from_u64_slice(&update_proof.public_inputs.to_u64_vec())
                        .map_err(|e| {
                            TransitionError::VerificationFailed(format!(
                                "Failed to parse update_proof public inputs: {}",
                                e
                            ))
                        })?;

                if pis.prev_public_state != prev_balance_pis.public_state {
                    return Err(TransitionError::VerificationFailed(
                        "prev_public_state mismatch in update_proof".to_string(),
                    ));
                }

                BalancePublicInputs {
                    public_state: pis.new_public_state,
                    ..prev_balance_pis
                }
            }
            BalanceTransitionType::Sender => {
                let sender_proof = sender_proof.clone().ok_or_else(|| {
                    TransitionError::InvalidValue("sender_proof is None".to_string())
                })?;

                sender_circuit
                    .data
                    .verify(sender_proof.clone())
                    .map_err(|e| {
                        TransitionError::VerificationFailed(format!(
                            "sender_proof is invalid: {}",
                            e
                        ))
                    })?;

                let pis = SenderPublicInputs::from_u64_slice(
                    &sender_proof
                        .public_inputs
                        .iter()
                        .map(|x| x.to_canonical_u64())
                        .collect::<Vec<_>>(),
                )
                .map_err(|e| {
                    TransitionError::VerificationFailed(format!(
                        "Failed to parse sender_proof public inputs: {}",
                        e
                    ))
                })?;

                if pis.prev_balance_pis != prev_balance_pis {
                    return Err(TransitionError::VerificationFailed(
                        "prev_balance_pis mismatch".to_string(),
                    ));
                }

                pis.new_balance_pis
            }
        };

        let new_balance_pis_commitment = new_balance_pis.commitment();

        Ok(Self {
            circuit_type,
            circuit_flags,
            receive_transfer_proof,
            receive_deposit_proof,
            update_proof,
            sender_proof,
            prev_balance_pis,
            new_balance_pis,
            new_balance_pis_commitment,
            balance_circuit_vd,
        })
    }
}

/// Target version of BalanceTransitionValue for use in ZKP circuits.
///
/// This struct contains circuit targets for all components needed to verify
/// a balance state transition, including targets for the four different transition types
/// and the logic to select between them based on circuit flags.
#[derive(Debug, Clone)]
pub struct BalanceTransitionTarget<const D: usize> {
    pub circuit_type: Target,           // Target for transition type index
    pub circuit_flags: [BoolTarget; 4], // Boolean flags for each transition type
    pub receive_transfer_proof: ProofWithPublicInputsTarget<D>, // Target for ReceiveTransfer proof
    pub receive_deposit_proof: ProofWithPublicInputsTarget<D>, // Target for ReceiveDeposit proof
    pub update_proof: ProofWithPublicInputsTarget<D>, // Target for Update proof
    pub sender_proof: ProofWithPublicInputsTarget<D>, // Target for Sender proof
    pub prev_balance_pis: BalancePublicInputsTarget, // Previous balance public inputs
    pub new_balance_pis: BalancePublicInputsTarget, // New balance public inputs (witness)
    pub new_balance_pis_commitment: PoseidonHashOutTarget, /* Commitment to new balance public
                                         * inputs */
    pub balance_circuit_vd: VerifierCircuitTarget, // Verifier data for balance circuit
}

impl<const D: usize> BalanceTransitionTarget<D> {
    /// Creates a new BalanceTransitionTarget with circuit constraints that enforce
    /// the balance transition rules for all four transition types.
    ///
    /// This method builds a circuit that:
    /// 1. Ensures exactly one circuit flag is set to true (the selected transition type)
    /// 2. Conditionally verifies the proof for the selected transition type
    /// 3. Validates that the proof's public inputs match the expected previous balance state
    /// 4. Computes the new balance public inputs based on the selected transition
    /// 5. Ensures the commitment to the new balance public inputs is correct
    ///
    /// # Arguments
    /// * `receive_transfer_vd` - Verifier data for the ReceiveTransfer circuit
    /// * `receive_deposit_vd` - Verifier data for the ReceiveDeposit circuit
    /// * `update_vd` - Verifier data for the Update circuit
    /// * `sender_vd` - Verifier data for the Sender circuit
    /// * `config` - Circuit configuration
    /// * `builder` - Circuit builder to add constraints to
    ///
    /// # Returns
    /// A new BalanceTransitionTarget with all necessary targets and constraints
    pub fn new<F: RichField + Extendable<D>, C: GenericConfig<D, F = F> + 'static>(
        receive_transfer_vd: &VerifierCircuitData<F, C, D>,
        receive_deposit_vd: &VerifierCircuitData<F, C, D>,
        update_vd: &VerifierCircuitData<F, C, D>,
        sender_vd: &VerifierCircuitData<F, C, D>,
        config: &CircuitConfig,
        builder: &mut CircuitBuilder<F, D>,
    ) -> Self
    where
        <C as GenericConfig<D>>::Hasher: AlgebraicHasher<F>,
    {
        let circuit_type = builder.add_virtual_target();
        let circuit_flags = [(); 4].map(|_| builder.add_virtual_bool_target_safe());
        let circuit_flags_target = circuit_flags.iter().map(|x| x.target).collect::<Vec<_>>();
        let one = builder.one();
        let bit_selected = builder.random_access(circuit_type, circuit_flags_target);
        builder.connect(bit_selected, one);
        // sum of circuit_flags should be 1
        let sum = circuit_flags
            .iter()
            .fold(builder.zero(), |acc, x| builder.add(acc, x.target));
        builder.connect(sum, one);

        let balance_circuit_vd = builder.add_virtual_verifier_data(config.fri_config.cap_height);
        let prev_balance_pis = BalancePublicInputsTarget::new(builder, false);

        let receive_transfer_proof = add_proof_target_and_conditionally_verify(
            receive_transfer_vd,
            builder,
            circuit_flags[0],
        );
        let new_balance_pis0 = {
            let condition = circuit_flags[0];
            let pis = ReceiveTransferPublicInputsTarget::from_slice(
                config,
                &receive_transfer_proof.public_inputs,
            );
            conditionally_connect_vd(
                builder,
                condition,
                &pis.balance_circuit_vd,
                &balance_circuit_vd,
            );
            pis.prev_private_commitment.conditional_assert_eq(
                builder,
                prev_balance_pis.private_commitment,
                condition,
            );
            pis.pubkey
                .conditional_assert_eq(builder, prev_balance_pis.pubkey, condition);
            pis.public_state.conditional_assert_eq(
                builder,
                &prev_balance_pis.public_state,
                condition,
            );
            BalancePublicInputsTarget {
                pubkey: pis.pubkey,
                private_commitment: pis.new_private_commitment,
                ..prev_balance_pis.clone()
            }
        };
        let receive_deposit_proof = add_proof_target_and_conditionally_verify(
            receive_deposit_vd,
            builder,
            circuit_flags[1],
        );
        let new_balance_pis1 = {
            let condition = circuit_flags[1];
            let pis =
                ReceiveDepositPublicInputsTarget::from_slice(&receive_deposit_proof.public_inputs);
            pis.prev_private_commitment.conditional_assert_eq(
                builder,
                prev_balance_pis.private_commitment,
                condition,
            );
            pis.pubkey
                .conditional_assert_eq(builder, prev_balance_pis.pubkey, condition);
            pis.public_state.conditional_assert_eq(
                builder,
                &prev_balance_pis.public_state,
                condition,
            );
            BalancePublicInputsTarget {
                pubkey: pis.pubkey,
                private_commitment: pis.new_private_commitment,
                ..prev_balance_pis.clone()
            }
        };
        let update_proof =
            add_proof_target_and_conditionally_verify(update_vd, builder, circuit_flags[2]);
        let new_balance_pis2 = {
            let condition = circuit_flags[2];
            let pis = UpdatePublicInputsTarget::from_slice(&update_proof.public_inputs);
            pis.prev_public_state.conditional_assert_eq(
                builder,
                &prev_balance_pis.public_state,
                condition,
            );
            prev_balance_pis
                .pubkey
                .conditional_assert_eq(builder, pis.pubkey, condition);
            BalancePublicInputsTarget {
                pubkey: pis.pubkey,
                public_state: pis.new_public_state,
                ..prev_balance_pis.clone()
            }
        };
        let sender_proof =
            add_proof_target_and_conditionally_verify(sender_vd, builder, circuit_flags[3]);
        let new_balance_pis3 = {
            let condition = circuit_flags[3];
            let pis = SenderPublicInputsTarget::from_slice(&sender_proof.public_inputs);
            pis.prev_balance_pis
                .conditional_assert_eq(builder, &prev_balance_pis, condition);
            pis.new_balance_pis
        };

        let candidates = vec![
            new_balance_pis0.clone(),
            new_balance_pis1.clone(),
            new_balance_pis2.clone(),
            new_balance_pis3.clone(),
        ];
        let candidate_commitments = candidates
            .iter()
            .map(|pis| HashOutTarget {
                elements: pis.commitment(builder).elements,
            })
            .collect::<Vec<_>>();
        let selected_commitment = PoseidonHashOutTarget {
            elements: builder
                .random_access_hash(circuit_type, candidate_commitments)
                .elements,
        };
        let new_balance_pis = BalancePublicInputsTarget::new(builder, true);
        let new_balance_pis_commitment = new_balance_pis.commitment(builder);
        selected_commitment.connect(builder, new_balance_pis_commitment);

        Self {
            circuit_type,
            circuit_flags,
            receive_transfer_proof,
            receive_deposit_proof,
            update_proof,
            sender_proof,
            prev_balance_pis,
            new_balance_pis,
            new_balance_pis_commitment,
            balance_circuit_vd,
        }
    }

    pub fn set_witness<
        F: RichField + Extendable<D>,
        C: GenericConfig<D, F = F> + 'static,
        W: WitnessWrite<F>,
    >(
        &self,
        receive_transfer_circuit: &ReceiveTransferCircuit<F, C, D>,
        receive_deposit_circuit: &ReceiveDepositCircuit<F, C, D>,
        update_circuit: &UpdateCircuit<F, C, D>,
        sender_circuit: &SenderCircuit<F, C, D>,
        witness: &mut W,
        value: &BalanceTransitionValue<F, C, D>,
    ) where
        <C as GenericConfig<D>>::Hasher: AlgebraicHasher<F>,
    {
        witness.set_target(
            self.circuit_type,
            F::from_canonical_usize(value.circuit_type as usize),
        );
        self.circuit_flags
            .iter()
            .zip(value.circuit_flags.iter())
            .for_each(|(x, y)| witness.set_bool_target(*x, *y));

        if value.receive_transfer_proof.is_some() {
            witness.set_proof_with_pis_target(
                &self.receive_transfer_proof,
                &value.receive_transfer_proof.clone().unwrap(),
            );
        } else {
            witness.set_proof_with_pis_target(
                &self.receive_transfer_proof,
                &receive_transfer_circuit.dummy_proof.proof,
            );
        }
        if value.receive_deposit_proof.is_some() {
            witness.set_proof_with_pis_target(
                &self.receive_deposit_proof,
                &value.receive_deposit_proof.clone().unwrap(),
            );
        } else {
            witness.set_proof_with_pis_target(
                &self.receive_deposit_proof,
                &receive_deposit_circuit.dummy_proof.proof,
            );
        }
        if value.update_proof.is_some() {
            witness.set_proof_with_pis_target(
                &self.update_proof,
                &value.update_proof.clone().unwrap(),
            );
        } else {
            witness
                .set_proof_with_pis_target(&self.update_proof, &update_circuit.dummy_proof.proof);
        }
        if value.sender_proof.is_some() {
            witness.set_proof_with_pis_target(
                &self.sender_proof,
                &value.sender_proof.clone().unwrap(),
            );
        } else {
            witness
                .set_proof_with_pis_target(&self.sender_proof, &sender_circuit.dummy_proof.proof);
        }
        self.prev_balance_pis
            .set_witness(witness, &value.prev_balance_pis);
        self.new_balance_pis
            .set_witness(witness, &value.new_balance_pis);
        self.new_balance_pis_commitment
            .set_witness(witness, value.new_balance_pis_commitment);
        witness.set_verifier_data_target(&self.balance_circuit_vd, &value.balance_circuit_vd);
    }
}

/// Main circuit for verifying balance state transitions.
///
/// This circuit combines all four transition types (ReceiveTransfer, ReceiveDeposit, Update,
/// Sender) into a single circuit that can verify any of them based on circuit flags. It provides a
/// unified interface for balance state transitions while allowing different transition types to be
/// used as needed.
pub struct BalanceTransitionCircuit<F, C, const D: usize>
where
    F: RichField + Extendable<D>,
    C: GenericConfig<D, F = F>,
{
    pub data: CircuitData<F, C, D>, // Circuit data containing the compiled circuit
    pub target: BalanceTransitionTarget<D>, // Target containing all circuit constraints
    pub balance_circuit_vd: VerifierCircuitTarget, // Verifier data for balance circuit
}

impl<F, C, const D: usize> BalanceTransitionCircuit<F, C, D>
where
    F: RichField + Extendable<D>,
    C: GenericConfig<D, F = F> + 'static,
    C::Hasher: AlgebraicHasher<F>,
{
    pub fn new(
        receive_transfer_vd: &VerifierCircuitData<F, C, D>,
        receive_deposit_vd: &VerifierCircuitData<F, C, D>,
        update_vd: &VerifierCircuitData<F, C, D>,
        sender_vd: &VerifierCircuitData<F, C, D>,
    ) -> Self {
        let config = CircuitConfig::standard_recursion_zk_config();
        let mut builder = CircuitBuilder::<F, D>::new(config.clone());
        let target = BalanceTransitionTarget::new::<F, C>(
            receive_transfer_vd,
            receive_deposit_vd,
            update_vd,
            sender_vd,
            &config,
            &mut builder,
        );
        let pis = [
            target.prev_balance_pis.to_vec(),
            target.new_balance_pis.to_vec(),
        ]
        .concat();
        builder.register_public_inputs(&pis);
        let balance_circuit_vd = builder.add_verifier_data_public_inputs();
        builder.connect_verifier_data(&balance_circuit_vd, &target.balance_circuit_vd);
        let data = builder.build();

        Self {
            data,
            target,
            balance_circuit_vd,
        }
    }

    pub fn prove(
        &self,
        receive_transfer_circuit: &ReceiveTransferCircuit<F, C, D>,
        receive_deposit_circuit: &ReceiveDepositCircuit<F, C, D>,
        update_circuit: &UpdateCircuit<F, C, D>,
        sender_circuit: &SenderCircuit<F, C, D>,
        value: &BalanceTransitionValue<F, C, D>,
    ) -> Result<ProofWithPublicInputs<F, C, D>, TransitionError> {
        let mut pw = PartialWitness::<F>::new();
        self.target.set_witness(
            receive_transfer_circuit,
            receive_deposit_circuit,
            update_circuit,
            sender_circuit,
            &mut pw,
            value,
        );
        pw.set_verifier_data_target(&self.balance_circuit_vd, &value.balance_circuit_vd);
        self.data
            .prove(pw)
            .map_err(|e| TransitionError::ProofGenerationError(format!("{:?}", e)))
    }
}

#[cfg(test)]
mod tests {
    use crate::{
        circuits::{
            balance::{
                balance_pis::BalancePublicInputs,
                balance_processor::BalanceProcessor,
                receive::{
                    receive_deposit_circuit::{ReceiveDepositCircuit, ReceiveDepositValue},
                    receive_transfer_circuit::ReceiveTransferCircuit,
                    update_circuit::UpdateCircuit,
                },
                send::sender_processor::SenderProcessor,
            },
            test_utils::witness_generator::{construct_spent_and_transfer_witness, MockTxRequest},
        },
        common::{
            deposit::{get_pubkey_salt_hash, Deposit},
            private_state::FullPrivateState,
            public_state::PublicState,
            salt::Salt,
            signature_content::key_set::KeySet,
            transfer::Transfer,
            witness::private_transition_witness::PrivateTransitionWitness,
        },
        ethereum_types::{address::Address, u256::U256, u32limb_trait::U32LimbTrait},
    };
    use plonky2::{
        field::goldilocks_field::GoldilocksField,
        plonk::{circuit_data::CircuitConfig, config::PoseidonGoldilocksConfig},
    };
    use rand::Rng;
    use std::sync::Arc;

    use crate::circuits::{
        test_utils::state_manager::ValidityStateManager,
        validity::validity_processor::ValidityProcessor,
    };

    use super::{BalanceTransitionCircuit, BalanceTransitionType, BalanceTransitionValue};

    type F = GoldilocksField;
    type C = PoseidonGoldilocksConfig;
    const D: usize = 2;

    #[test]
    fn test_transition_circuit_send() {
        let mut rng: rand::prelude::ThreadRng = rand::thread_rng();
        let validity_processor = Arc::new(ValidityProcessor::<F, C, D>::new());
        let mut validity_state_manager =
            ValidityStateManager::new(validity_processor.clone(), Address::default());

        let key = KeySet::rand(&mut rng);
        let mut full_private_state = FullPrivateState::new();
        let balance_pis = BalancePublicInputs::new(key.pubkey);

        // alice send transfer
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
        let tx_witness = tx_witnesses[0].clone();
        let update_witness = validity_state_manager
            .get_update_witness(key.pubkey, 1, 0, true)
            .unwrap();

        let validity_vd = validity_processor.get_verifier_data();
        let balance_vd = BalanceProcessor::new(&validity_vd).get_verifier_data();
        let balance_common = balance_vd.common;
        let receive_transfer_circuit = ReceiveTransferCircuit::<F, C, D>::new(&balance_common);
        let receive_deposit_circuit = ReceiveDepositCircuit::<F, C, D>::new();
        let update_circuit = UpdateCircuit::<F, C, D>::new(&validity_vd);
        let sender_processor = SenderProcessor::<F, C, D>::new(&validity_vd);

        let spent_proof = sender_processor.prove_spent(&spent_witness).unwrap();
        let sender_proof = sender_processor
            .prove_send(
                &validity_vd,
                &balance_pis,
                &tx_witness,
                &update_witness,
                &spent_proof,
            )
            .unwrap();

        let transition_value = BalanceTransitionValue::new(
            &CircuitConfig::default(),
            BalanceTransitionType::Sender,
            &receive_transfer_circuit,
            &receive_deposit_circuit,
            &update_circuit,
            &sender_processor.sender_circuit,
            None,
            None,
            None,
            Some(sender_proof),
            balance_pis.clone(),
            balance_vd.verifier_only,
        )
        .unwrap();

        let transition_circuit = BalanceTransitionCircuit::<F, C, D>::new(
            &receive_transfer_circuit.data.verifier_data(),
            &receive_deposit_circuit.data.verifier_data(),
            &update_circuit.data.verifier_data(),
            &sender_processor.sender_circuit.data.verifier_data(),
        );
        let transition_proof = transition_circuit
            .prove(
                &receive_transfer_circuit,
                &receive_deposit_circuit,
                &update_circuit,
                &sender_processor.sender_circuit,
                &transition_value,
            )
            .unwrap();

        transition_circuit.data.verify(transition_proof).unwrap();
    }

    #[test]
    fn test_transition_circuit_update() {
        let mut rng = rand::thread_rng();
        let validity_processor = Arc::new(ValidityProcessor::<F, C, D>::new());
        let mut validity_state_manager =
            ValidityStateManager::new(validity_processor.clone(), Address::default());

        // post empty block
        validity_state_manager.tick(false, &[], 0, 0).unwrap();

        // update balance
        let key = KeySet::rand(&mut rng);
        let update_witness = validity_state_manager
            .get_update_witness(key.pubkey, 1, 0, false)
            .unwrap();

        let validity_vd = validity_processor.get_verifier_data();
        let balance_vd = BalanceProcessor::new(&validity_vd).get_verifier_data();
        let balance_common = balance_vd.common;
        let receive_transfer_circuit = ReceiveTransferCircuit::<F, C, D>::new(&balance_common);
        let receive_deposit_circuit = ReceiveDepositCircuit::<F, C, D>::new();
        let update_circuit = UpdateCircuit::<F, C, D>::new(&validity_vd);
        let sender_processor = SenderProcessor::<F, C, D>::new(&validity_vd);

        let update_proof = update_circuit
            .prove(
                &update_witness
                    .to_value(&validity_vd, key.pubkey, &PublicState::genesis())
                    .unwrap(),
            )
            .unwrap();

        let transition_value = BalanceTransitionValue::new(
            &CircuitConfig::default(),
            BalanceTransitionType::Update,
            &receive_transfer_circuit,
            &receive_deposit_circuit,
            &update_circuit,
            &sender_processor.sender_circuit,
            None,
            None,
            Some(update_proof),
            None,
            BalancePublicInputs::new(key.pubkey),
            balance_vd.verifier_only,
        )
        .unwrap();

        let transition_circuit = BalanceTransitionCircuit::<F, C, D>::new(
            &receive_transfer_circuit.data.verifier_data(),
            &receive_deposit_circuit.data.verifier_data(),
            &update_circuit.data.verifier_data(),
            &sender_processor.sender_circuit.data.verifier_data(),
        );
        let transition_proof = transition_circuit
            .prove(
                &receive_transfer_circuit,
                &receive_deposit_circuit,
                &update_circuit,
                &sender_processor.sender_circuit,
                &transition_value,
            )
            .unwrap();

        transition_circuit.data.verify(transition_proof).unwrap();
    }

    #[cfg(feature = "skip_insufficient_check")]
    #[test]
    fn test_transition_circuit_receive_transfer() {
        use crate::circuits::balance::receive::{
            receive_targets::transfer_inclusion::TransferInclusionValue,
            receive_transfer_circuit::ReceiveTransferValue,
        };

        let mut rng = rand::thread_rng();
        let validity_processor = Arc::new(ValidityProcessor::<F, C, D>::new());
        let mut validity_state_manager =
            ValidityStateManager::new(validity_processor.clone(), Address::default());
        let balance_processor = BalanceProcessor::new(&validity_processor.get_verifier_data());
        let validity_vd = validity_processor.get_verifier_data();
        let balance_vd = balance_processor.get_verifier_data();
        let balance_common = balance_vd.common.clone();

        let key = KeySet::rand(&mut rng);
        let mut full_private_state = FullPrivateState::new();
        let mut balance_proof = None;

        // generate balance proof
        let (funded_balance_proof, transfer_witness) = {
            let alice_key = KeySet::rand(&mut rng);
            let mut alice_state = FullPrivateState::new();
            let transfer = Transfer {
                recipient: key.pubkey.into(),
                token_index: rng.gen(),
                amount: U256::rand_small(&mut rng),
                salt: Salt::rand(&mut rng),
            };
            let (spent_witness, transfer_witnesses) =
                construct_spent_and_transfer_witness(&mut alice_state, &[transfer]).unwrap();
            let spent_proof = balance_processor
                .balance_transition_processor
                .sender_processor
                .prove_spent(&spent_witness)
                .unwrap();

            // post block
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

            let balance_proof = balance_processor
                .prove_send(
                    &validity_processor.get_verifier_data(),
                    alice_key.pubkey,
                    &tx_witness,
                    &update_witness,
                    &spent_proof,
                    &None,
                )
                .unwrap();

            (balance_proof, transfer_witnesses[0].clone())
        };

        // update balance proof
        let update_witness = validity_state_manager
            .get_update_witness(key.pubkey, 1, 0, false)
            .unwrap();
        balance_proof = Some(
            balance_processor
                .prove_update(&validity_vd, key.pubkey, &update_witness, &balance_proof)
                .unwrap(),
        );
        let public_state = update_witness.public_state();

        let transfer_inclusion_value = TransferInclusionValue::new(
            &balance_vd,
            &transfer_witness.transfer,
            transfer_witness.transfer_index,
            &transfer_witness.transfer_merkle_proof,
            &transfer_witness.tx,
            &funded_balance_proof,
        )
        .unwrap();

        let private_transition_witness = PrivateTransitionWitness::from_transfer(
            &mut full_private_state,
            transfer_witness.transfer,
            Salt::rand(&mut rng),
        )
        .unwrap();

        let block_merkle_proof = validity_state_manager.get_block_merkle_proof(1, 1).unwrap();

        let receive_transfer_circuit = ReceiveTransferCircuit::<F, C, D>::new(&balance_common);
        let receive_deposit_circuit = ReceiveDepositCircuit::<F, C, D>::new();
        let update_circuit = UpdateCircuit::<F, C, D>::new(&validity_vd);
        let sender_processor = SenderProcessor::<F, C, D>::new(&validity_vd);

        let receive_transfer_value = ReceiveTransferValue::new(
            &public_state,
            &block_merkle_proof,
            &transfer_inclusion_value,
            &private_transition_witness.to_value().unwrap(),
        )
        .unwrap();
        let receive_transfer_proof = receive_transfer_circuit
            .prove(&receive_transfer_value)
            .unwrap();

        let balance_pis =
            BalancePublicInputs::from_pis(&balance_proof.unwrap().public_inputs).unwrap();
        let transition_value = BalanceTransitionValue::new(
            &CircuitConfig::default(),
            BalanceTransitionType::ReceiveTransfer,
            &receive_transfer_circuit,
            &receive_deposit_circuit,
            &update_circuit,
            &sender_processor.sender_circuit,
            Some(receive_transfer_proof),
            None,
            None,
            None,
            balance_pis,
            balance_vd.verifier_only,
        )
        .unwrap();

        let transition_circuit = BalanceTransitionCircuit::<F, C, D>::new(
            &receive_transfer_circuit.data.verifier_data(),
            &receive_deposit_circuit.data.verifier_data(),
            &update_circuit.data.verifier_data(),
            &sender_processor.sender_circuit.data.verifier_data(),
        );
        let transition_proof = transition_circuit
            .prove(
                &receive_transfer_circuit,
                &receive_deposit_circuit,
                &update_circuit,
                &sender_processor.sender_circuit,
                &transition_value,
            )
            .unwrap();
        transition_circuit.data.verify(transition_proof).unwrap();
    }

    #[test]
    fn test_transition_circuit_receive_deposit() {
        let mut rng = rand::thread_rng();
        let validity_processor = Arc::new(ValidityProcessor::<F, C, D>::new());
        let balance_processor = BalanceProcessor::new(&validity_processor.get_verifier_data());
        let mut validity_state_manager =
            ValidityStateManager::new(validity_processor.clone(), Address::default());
        let validity_vd = validity_processor.get_verifier_data();
        let balance_vd = balance_processor.get_verifier_data();
        let balance_common = balance_vd.common.clone();

        // local state
        let key = KeySet::rand(&mut rng);
        let mut full_private_state = FullPrivateState::new();

        // deposit
        let deposit_salt = Salt::rand(&mut rng);
        let deposit_salt_hash = get_pubkey_salt_hash(key.pubkey, deposit_salt);
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

        // update balance proof
        let update_witness = validity_state_manager
            .get_update_witness(key.pubkey, 1, 0, false)
            .unwrap();
        let balance_proof = balance_processor
            .prove_update(
                &validity_processor.get_verifier_data(),
                key.pubkey,
                &update_witness,
                &None,
            )
            .unwrap();

        // receive deposit proof
        let deposit_merkle_proof = validity_state_manager
            .get_deposit_merkle_proof(1, deposit_index)
            .unwrap();
        let private_transition_witness = PrivateTransitionWitness::from_deposit(
            &mut full_private_state,
            &deposit,
            Salt::rand(&mut rng),
        )
        .unwrap();

        let receive_transfer_circuit = ReceiveTransferCircuit::<F, C, D>::new(&balance_common);
        let receive_deposit_circuit = ReceiveDepositCircuit::<F, C, D>::new();
        let update_circuit = UpdateCircuit::<F, C, D>::new(&validity_vd);
        let sender_processor = SenderProcessor::<F, C, D>::new(&validity_vd);

        let receive_deposit_value = ReceiveDepositValue::new(
            key.pubkey,
            deposit_salt,
            deposit_index,
            &deposit,
            &deposit_merkle_proof,
            &update_witness.public_state(),
            &private_transition_witness.to_value().unwrap(),
        )
        .unwrap();

        let receive_deposit_proof = receive_deposit_circuit
            .prove(&receive_deposit_value)
            .unwrap();

        let balance_pis = BalancePublicInputs::from_pis(&balance_proof.public_inputs)
            .expect("Failed to parse balance public inputs");
        let transition_value = BalanceTransitionValue::new(
            &CircuitConfig::default(),
            BalanceTransitionType::ReceiveDeposit,
            &receive_transfer_circuit,
            &receive_deposit_circuit,
            &update_circuit,
            &sender_processor.sender_circuit,
            None,
            Some(receive_deposit_proof),
            None,
            None,
            balance_pis,
            balance_vd.verifier_only,
        )
        .unwrap();

        let transition_circuit = BalanceTransitionCircuit::<F, C, D>::new(
            &receive_transfer_circuit.data.verifier_data(),
            &receive_deposit_circuit.data.verifier_data(),
            &update_circuit.data.verifier_data(),
            &sender_processor.sender_circuit.data.verifier_data(),
        );
        let transition_proof = transition_circuit
            .prove(
                &receive_transfer_circuit,
                &receive_deposit_circuit,
                &update_circuit,
                &sender_processor.sender_circuit,
                &transition_value,
            )
            .unwrap();
        transition_circuit.data.verify(transition_proof).unwrap();
    }
}
