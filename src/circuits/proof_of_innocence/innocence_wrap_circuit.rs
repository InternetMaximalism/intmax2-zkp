//! Innocence Wrap Circuit for making the innocence circuit zero-knowledge and computing private
//! state commitment.
//!
//! This circuit serves two purposes in the proof of innocence system:
//! 1. Makes the innocence circuit zero-knowledge by wrapping it (the original innocence circuit is
//!    not ZK)
//! 2. Computes the commitment of the private state.
//!
//! The circuit takes a proof from the innocence circuit as input, verifies it,
//! and then computes a commitment to the private state. This commitment can be
//! publicly shared without revealing the underlying private state details.

use plonky2::{
    field::{extension::Extendable, types::PrimeField64},
    hash::hash_types::RichField,
    iop::{
        target::{BoolTarget, Target},
        witness::{PartialWitness, WitnessWrite as _},
    },
    plonk::{
        circuit_builder::CircuitBuilder,
        circuit_data::{CircuitConfig, CircuitData, VerifierCircuitData},
        config::{AlgebraicHasher, GenericConfig},
        proof::{ProofWithPublicInputs, ProofWithPublicInputsTarget},
    },
};

use super::error::InnocenceError;

use crate::{
    common::private_state::{PrivateState, PrivateStateTarget},
    utils::{
        conversion::ToU64 as _,
        poseidon_hash_out::{PoseidonHashOut, PoseidonHashOutTarget, POSEIDON_HASH_OUT_LEN},
        recursively_verifiable::add_proof_target_and_verify_cyclic,
    },
};

use super::innocence_circuit::InnocencePublicInputsTarget;

pub const INNOCENCE_WRAP_PUBLIC_INPUTS_LEN: usize = 1 + 3 * POSEIDON_HASH_OUT_LEN;

pub struct InnocenceWrapPublicInputs {
    pub use_allow_list: bool, // Flag indicating if allow list checking is enabled
    pub allow_list_tree_root: PoseidonHashOut, // Root of the allow list Merkle tree
    pub deny_list_tree_root: PoseidonHashOut, // Root of the deny list Merkle tree
    pub private_commitment: PoseidonHashOut, // Commitment to the private state
}

impl InnocenceWrapPublicInputs {
    pub fn to_u64_vec(&self) -> Vec<u64> {
        let vec = vec![self.use_allow_list as u64]
            .into_iter()
            .chain(self.allow_list_tree_root.to_u64_vec())
            .chain(self.deny_list_tree_root.to_u64_vec())
            .chain(self.private_commitment.to_u64_vec())
            .collect::<Vec<_>>();
        assert_eq!(vec.len(), INNOCENCE_WRAP_PUBLIC_INPUTS_LEN);
        vec
    }

    pub fn from_u64_slice(slice: &[u64]) -> Self {
        assert_eq!(slice.len(), INNOCENCE_WRAP_PUBLIC_INPUTS_LEN);
        let use_allow_list = slice[0] != 0;
        let allow_list_tree_root =
            PoseidonHashOut::from_u64_slice(&slice[1..1 + POSEIDON_HASH_OUT_LEN]).unwrap();
        let deny_list_tree_root = PoseidonHashOut::from_u64_slice(
            &slice[1 + POSEIDON_HASH_OUT_LEN..1 + 2 * POSEIDON_HASH_OUT_LEN],
        )
        .unwrap();
        let private_commitment = PoseidonHashOut::from_u64_slice(
            &slice[1 + 2 * POSEIDON_HASH_OUT_LEN..1 + 3 * POSEIDON_HASH_OUT_LEN],
        )
        .unwrap();
        Self {
            use_allow_list,
            allow_list_tree_root,
            deny_list_tree_root,
            private_commitment,
        }
    }

    pub fn from_pis<F: PrimeField64>(pis: &[F]) -> Self {
        Self::from_u64_slice(&pis[0..INNOCENCE_WRAP_PUBLIC_INPUTS_LEN].to_u64_vec())
    }
}

/// Target version of InnocenceWrapPublicInputs for use in ZKP circuits
///
/// Contains circuit targets for all public inputs that will be exposed
/// in the proof for verification.
#[derive(Clone, Debug)]
pub struct InnocenceWrapPublicInputsTarget {
    pub use_allow_list: BoolTarget, // Target for allow list flag
    pub allow_list_tree_root: PoseidonHashOutTarget, // Target for allow list root
    pub deny_list_tree_root: PoseidonHashOutTarget, // Target for deny list root
    pub private_commitment: PoseidonHashOutTarget, // Target for private state commitment
}

impl InnocenceWrapPublicInputsTarget {
    pub fn to_vec(&self) -> Vec<Target> {
        let vec = vec![self.use_allow_list.target]
            .into_iter()
            .chain(self.allow_list_tree_root.to_vec())
            .chain(self.deny_list_tree_root.to_vec())
            .chain(self.private_commitment.to_vec())
            .collect::<Vec<_>>();
        assert_eq!(vec.len(), INNOCENCE_WRAP_PUBLIC_INPUTS_LEN);
        vec
    }

    pub fn from_slice(slice: &[Target]) -> Self {
        assert_eq!(slice.len(), INNOCENCE_WRAP_PUBLIC_INPUTS_LEN);
        let use_allow_list = BoolTarget::new_unsafe(slice[0]);
        let allow_list_tree_root =
            PoseidonHashOutTarget::from_slice(&slice[1..1 + POSEIDON_HASH_OUT_LEN]);
        let deny_list_tree_root = PoseidonHashOutTarget::from_slice(
            &slice[1 + POSEIDON_HASH_OUT_LEN..1 + 2 * POSEIDON_HASH_OUT_LEN],
        );
        let private_commitment = PoseidonHashOutTarget::from_slice(
            &slice[1 + 2 * POSEIDON_HASH_OUT_LEN..1 + 3 * POSEIDON_HASH_OUT_LEN],
        );
        Self {
            use_allow_list,
            allow_list_tree_root,
            deny_list_tree_root,
            private_commitment,
        }
    }

    /// Creates target public inputs from a slice of public input targets
    ///
    /// This function extracts the relevant portion of the public inputs
    /// and parses them into the component target public inputs.
    pub fn from_pis(pis: &[Target]) -> Self {
        Self::from_slice(&pis[0..INNOCENCE_WRAP_PUBLIC_INPUTS_LEN])
    }
}

/// Circuit for wrapping the innocence circuit to make it zero-knowledge and compute private state
/// commitment
///
/// This circuit serves two critical purposes:
/// 1. Makes the innocence circuit zero-knowledge by wrapping it
/// 2. Computes the commitment of the private state
///
/// The circuit takes a proof from the innocence circuit as input, verifies it,
/// and then computes a commitment to the private state. This commitment can be
/// publicly shared without revealing the underlying private state details.
pub struct InnocenceWrapCircuit<F, C, const D: usize>
where
    F: RichField + Extendable<D>,
    C: GenericConfig<D, F = F>,
{
    innocence_proof: ProofWithPublicInputsTarget<D>, // Target for the innocence circuit proof
    private_state: PrivateStateTarget,               // Target for the private state
    data: CircuitData<F, C, D>,                      // Circuit data
}

impl<F, C, const D: usize> InnocenceWrapCircuit<F, C, D>
where
    F: RichField + Extendable<D>,
    C: GenericConfig<D, F = F> + 'static,
    C::Hasher: AlgebraicHasher<F>,
{
    pub fn new(verifier_data: &VerifierCircuitData<F, C, D>) -> Self {
        // Create a circuit builder with zero-knowledge enabled
        let mut builder =
            CircuitBuilder::<F, D>::new(CircuitConfig::standard_recursion_zk_config());

        // Create targets for the private state and innocence proof
        let private_state = PrivateStateTarget::new(&mut builder);
        let innocence_proof = add_proof_target_and_verify_cyclic(verifier_data, &mut builder);

        // Extract public inputs from the innocence proof
        let innocence_pis = InnocencePublicInputsTarget::from_pis(&innocence_proof.public_inputs);

        // Connect the nullifier tree root from the innocence proof to the private state
        // This ensures the private state's nullifier tree matches the one verified in the innocence
        // circuit
        private_state
            .nullifier_tree_root
            .connect(&mut builder, innocence_pis.nullifier_tree_root);

        // Compute the commitment to the private state
        let private_commitment = private_state.commitment(&mut builder);

        // Create the public inputs for this circuit
        let pis = InnocenceWrapPublicInputsTarget {
            use_allow_list: innocence_pis.use_allow_list,
            allow_list_tree_root: innocence_pis.allow_list_tree_root,
            deny_list_tree_root: innocence_pis.deny_list_tree_root,
            private_commitment,
        };

        // Register the public inputs
        builder.register_public_inputs(&pis.to_vec());

        // Build the circuit
        let data = builder.build();

        Self {
            innocence_proof,
            private_state,
            data,
        }
    }

    pub fn prove(
        &self,
        innocence_proof: &ProofWithPublicInputs<F, C, D>,
        private_state: PrivateState,
    ) -> Result<ProofWithPublicInputs<F, C, D>, InnocenceError> {
        let mut pw = PartialWitness::<F>::new();

        // Set the witness values for the innocence proof and private state
        pw.set_proof_with_pis_target(&self.innocence_proof, innocence_proof);
        self.private_state.set_witness(&mut pw, &private_state);

        // Generate the proof
        self.data
            .prove(pw)
            .map_err(|e| InnocenceError::InnocenceWrapCircuitProofFailed(e.to_string()))
    }

    pub fn verify(&self, proof: &ProofWithPublicInputs<F, C, D>) -> Result<(), InnocenceError> {
        self.data
            .verify(proof.clone())
            .map_err(|e| InnocenceError::InnocenceWrapCircuitVerificationFailed(e.to_string()))
    }
}
