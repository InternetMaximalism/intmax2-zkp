//! Balance circuit for proving the correctness of user balance state.
//!
//! This circuit implements an Incremental Verifiable Computation ZKP that:
//! 1. Verifies the previous balance proof (or initializes with genesis state if first step)
//! 2. Verifies a transition proof that updates the user's balance state
//! 3. Produces a new balance proof that can be used in subsequent balance updates
//!
//! The balance circuit advances one step each time a user's balance is updated through:
//! - Receiving transfers from other users
//! - Receiving deposits from L1
//! - Sending transfers to other users
//! - Updating public state without changing private state
//!
//! This forms a chain of proofs that maintains the integrity of a user's balance history.

use crate::circuits::balance::error::BalanceError;
use plonky2::{
    field::extension::Extendable,
    gates::noop::NoopGate,
    hash::hash_types::RichField,
    iop::{
        target::BoolTarget,
        witness::{PartialWitness, WitnessWrite as _},
    },
    plonk::{
        circuit_builder::CircuitBuilder,
        circuit_data::{
            CircuitConfig, CircuitData, CommonCircuitData, VerifierCircuitData,
            VerifierCircuitTarget,
        },
        config::{AlgebraicHasher, GenericConfig},
        proof::{ProofWithPublicInputs, ProofWithPublicInputsTarget},
    },
    recursion::{
        cyclic_recursion::check_cyclic_proof_verifier_data, dummy_circuit::cyclic_base_proof,
    },
};

use crate::{
    circuits::balance::balance_pis::BalancePublicInputsTarget,
    common::{
        insufficient_flags::{InsufficientFlags, InsufficientFlagsTarget},
        private_state::PrivateState,
        public_state::{PublicState, PublicStateTarget},
    },
    constants::CYCLIC_CIRCUIT_PADDING_DEGREE,
    ethereum_types::{
        u256::{U256Target, U256},
        u32limb_trait::U32LimbTargetTrait,
    },
    utils::{
        conversion::ToField as _,
        cyclic::vd_vec_len,
        poseidon_hash_out::{PoseidonHashOut, PoseidonHashOutTarget},
        recursively_verifiable::add_proof_target_and_verify,
    },
};

use super::balance_pis::{BalancePublicInputs, BALANCE_PUBLIC_INPUTS_LEN};

use crate::utils::cyclic::vd_from_pis_slice_target;

/// Balance circuit for proving the correctness of user balance state.
///
/// This circuit implements an IVC (Incremental Verifiable Computation) pattern where:
/// - Each proof represents a valid state of the user's balance
/// - The circuit recursively verifies the previous proof in the chain
/// - A transition proof is verified to ensure the state transition is valid
/// - A new proof is generated that can be used in the next balance update
///
/// The circuit handles both the first step (genesis state) and subsequent steps
/// by conditionally verifying either a dummy proof or the actual previous proof.
#[derive(Debug)]
pub struct BalanceCircuit<F, C, const D: usize>
where
    F: RichField + Extendable<D>,
    C: GenericConfig<D, F = F>,
{
    pub data: CircuitData<F, C, D>, // Circuit data containing the compiled circuit
    pub is_first_step: BoolTarget,  // Flag indicating if this is the first proof in the chain
    pub pubkey: U256Target,         // User's public key
    pub transition_proof: ProofWithPublicInputsTarget<D>, // Proof of the balance state transition
    pub prev_proof: ProofWithPublicInputsTarget<D>, // Previous balance proof in the chain
    pub verifier_data_target: VerifierCircuitTarget, // Verifier data for the circuit
}

impl<F, C, const D: usize> BalanceCircuit<F, C, D>
where
    F: RichField + Extendable<D>,
    C: GenericConfig<D, F = F> + 'static,
    C::Hasher: AlgebraicHasher<F>,
{
    pub fn new(balance_transition_verifier_data: &VerifierCircuitData<F, C, D>) -> Self {
        let mut builder = CircuitBuilder::<F, D>::new(CircuitConfig::default());
        let is_first_step = builder.add_virtual_bool_target_safe();
        let is_not_first_step = builder.not(is_first_step);

        let transition_proof =
            add_proof_target_and_verify(balance_transition_verifier_data, &mut builder);

        let prev_pis_ = BalancePublicInputsTarget::from_slice(
            &transition_proof.public_inputs[0..BALANCE_PUBLIC_INPUTS_LEN],
        );
        let new_pis = BalancePublicInputsTarget::from_slice(
            &transition_proof.public_inputs
                [BALANCE_PUBLIC_INPUTS_LEN..2 * BALANCE_PUBLIC_INPUTS_LEN],
        );
        let inner_balance_vd = vd_from_pis_slice_target(
            &transition_proof.public_inputs,
            &balance_transition_verifier_data.common.config,
        )
        .expect("Failed to parse inner balance vd");
        builder.register_public_inputs(&new_pis.to_vec());

        let common_data = common_data_for_balance_circuit::<F, C, D>();
        let verifier_data_target = builder.add_verifier_data_public_inputs();
        builder.connect_verifier_data(&inner_balance_vd, &verifier_data_target);

        let prev_proof = builder.add_virtual_proof_with_pis(&common_data);
        builder
            .conditionally_verify_cyclic_proof_or_dummy::<C>(
                is_not_first_step,
                &prev_proof,
                &common_data,
            )
            .expect("Failed to conditionally verify cyclic proof or dummy");
        let prev_pis = BalancePublicInputsTarget::from_slice(
            &prev_proof.public_inputs[0..BALANCE_PUBLIC_INPUTS_LEN],
        );
        prev_pis.connect(&mut builder, &prev_pis_);

        let initial_private_commitment =
            PoseidonHashOutTarget::constant(&mut builder, PrivateState::new().commitment());
        let initial_last_tx_hash =
            PoseidonHashOutTarget::constant(&mut builder, PoseidonHashOut::default());
        let initial_public_state =
            PublicStateTarget::constant(&mut builder, &PublicState::genesis());
        let initial_last_tx_insufficient_flags =
            InsufficientFlagsTarget::constant(&mut builder, InsufficientFlags::default());
        let pubkey = U256Target::new(&mut builder, true);
        let initial_balance_pis = BalancePublicInputsTarget {
            pubkey,
            private_commitment: initial_private_commitment,
            last_tx_hash: initial_last_tx_hash,
            last_tx_insufficient_flags: initial_last_tx_insufficient_flags,
            public_state: initial_public_state,
        };
        prev_pis.conditional_assert_eq(&mut builder, &initial_balance_pis, is_first_step);

        let (data, success) = builder.try_build_with_options::<C>(true);
        assert_eq!(
            data.common, common_data,
            "Common data mismatch in balance circuit"
        );
        assert!(success, "Failed to build balance circuit");

        Self {
            data,
            is_first_step,
            pubkey,
            transition_proof,
            prev_proof,
            verifier_data_target,
        }
    }

    /// Generates a ZK proof for the balance circuit.
    ///
    /// This method:
    /// 1. Validates that the transition proof's previous balance public inputs match either the
    ///    previous proof's public inputs or the initial state
    /// 2. Creates a partial witness with all necessary values
    /// 3. Sets the appropriate flags based on whether this is the first step
    /// 4. Generates a proof that can be verified by others
    ///
    /// # Arguments
    /// * `pubkey` - User's public key
    /// * `transition_proof` - Proof of the balance state transition
    /// * `prev_proof` - Optional previous balance proof (None if this is the first step)
    ///
    /// # Returns
    /// A Result containing either the proof or an error if validation or proof generation fails
    pub fn prove(
        &self,
        pubkey: U256,
        transition_proof: &ProofWithPublicInputs<F, C, D>,
        prev_proof: &Option<ProofWithPublicInputs<F, C, D>>,
    ) -> Result<ProofWithPublicInputs<F, C, D>, BalanceError> {
        // validation of public inputs equivalence
        let transition_prev_balance_pis =
            BalancePublicInputs::from_pis(&transition_proof.public_inputs)?;
        if prev_proof.is_some() {
            let prev_balance_pis =
                BalancePublicInputs::from_pis(&prev_proof.as_ref().unwrap().public_inputs)?;
            if transition_prev_balance_pis != prev_balance_pis {
                return Err(BalanceError::VerificationFailed(format!(
                    "Previous balance public inputs mismatch: expected {:?}, got {:?}",
                    prev_balance_pis, transition_prev_balance_pis
                )));
            }
        } else {
            let initial_balance_pis = BalancePublicInputs::new(pubkey);
            if transition_prev_balance_pis != initial_balance_pis {
                return Err(BalanceError::VerificationFailed(format!(
                    "Initial balance public inputs mismatch: expected {:?}, got {:?}",
                    initial_balance_pis, transition_prev_balance_pis
                )));
            }
        }

        let mut pw = PartialWitness::<F>::new();
        pw.set_verifier_data_target(&self.verifier_data_target, &self.data.verifier_only);
        pw.set_proof_with_pis_target(&self.transition_proof, transition_proof);
        self.pubkey.set_witness(&mut pw, pubkey);
        if prev_proof.is_none() {
            let dummy_proof = cyclic_base_proof(
                &self.data.common,
                &self.data.verifier_only,
                BalancePublicInputs::new(pubkey)
                    .to_u64_vec()
                    .to_field_vec::<F>()
                    .into_iter()
                    .enumerate()
                    .collect(),
            );
            pw.set_bool_target(self.is_first_step, true);
            pw.set_proof_with_pis_target(&self.prev_proof, &dummy_proof);
        } else {
            pw.set_bool_target(self.is_first_step, false);
            pw.set_proof_with_pis_target(&self.prev_proof, prev_proof.as_ref().unwrap());
        }
        self.data.prove(pw).map_err(|e| {
            BalanceError::ProofGenerationError(format!("Failed to generate proof: {:?}", e))
        })
    }

    pub fn get_verifier_data(&self) -> VerifierCircuitData<F, C, D> {
        self.data.verifier_data()
    }

    pub fn verify(&self, proof: &ProofWithPublicInputs<F, C, D>) -> Result<(), BalanceError> {
        check_cyclic_proof_verifier_data(proof, &self.data.verifier_only, &self.data.common)
            .map_err(|e| {
                BalanceError::VerificationFailed(format!(
                    "Failed to check cyclic proof verifier data: {:?}",
                    e
                ))
            })?;
        self.data.verify(proof.clone()).map_err(|e| {
            BalanceError::VerificationFailed(format!("Failed to verify proof: {:?}", e))
        })
    }
}

/// Generates `CommonCircuitData` for the cyclic balance circuit.
pub(crate) fn common_data_for_balance_circuit<
    F: RichField + Extendable<D>,
    C: GenericConfig<D, F = F>,
    const D: usize,
>() -> CommonCircuitData<F, D>
where
    C::Hasher: AlgebraicHasher<F>,
{
    let builder = CircuitBuilder::<F, D>::new(CircuitConfig::default());
    let data = builder.build::<C>();

    let mut builder = CircuitBuilder::<F, D>::new(CircuitConfig::default());
    let proof = builder.add_virtual_proof_with_pis(&data.common);
    let verifier_data = VerifierCircuitTarget {
        constants_sigmas_cap: builder.add_virtual_cap(data.common.config.fri_config.cap_height),
        circuit_digest: builder.add_virtual_hash(),
    };
    builder.verify_proof::<C>(&proof, &verifier_data, &data.common);
    let data = builder.build::<C>();

    let mut builder = CircuitBuilder::<F, D>::new(CircuitConfig::default());
    let proof = builder.add_virtual_proof_with_pis(&data.common);
    let verifier_data = VerifierCircuitTarget {
        constants_sigmas_cap: builder.add_virtual_cap(data.common.config.fri_config.cap_height),
        circuit_digest: builder.add_virtual_hash(),
    };
    builder.verify_proof::<C>(&proof, &verifier_data, &data.common);
    while builder.num_gates() < 1 << CYCLIC_CIRCUIT_PADDING_DEGREE {
        builder.add_gate(NoopGate, vec![]);
    }
    let mut common = builder.build::<C>().common;
    common.num_public_inputs = BALANCE_PUBLIC_INPUTS_LEN + vd_vec_len(&common.config);
    common
}
