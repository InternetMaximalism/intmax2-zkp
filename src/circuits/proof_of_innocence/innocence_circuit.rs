//! Innocence Circuit for validating deposits against allow/deny lists.
//!
//! This circuit implements an Incrementally Verifiable Computation (IVC) that proves:
//! 1. All assets in a user's account came through deposits
//! 2. The depositor addresses are not in a deny list
//! 3. If allow list is enabled, the depositor addresses are in the allow list
//!
//! The circuit processes deposits sequentially, creating a proof for each deposit
//! and its corresponding nullifier tree transition. Each step verifies:
//! - The depositor's address against allow/deny lists
//! - The valid insertion of the deposit's nullifier into the nullifier tree
//! - The correct transition of the nullifier tree root
//!
//! This ensures that all assets in the system came from approved sources.

use plonky2::{
    field::extension::Extendable,
    gates::noop::NoopGate,
    hash::hash_types::RichField,
    iop::{
        target::{BoolTarget, Target},
        witness::{PartialWitness, WitnessWrite as _},
    },
    plonk::{
        circuit_builder::CircuitBuilder,
        circuit_data::{CircuitConfig, CircuitData, CommonCircuitData, VerifierCircuitTarget},
        config::{AlgebraicHasher, GenericConfig},
        proof::{ProofWithPublicInputs, ProofWithPublicInputsTarget},
    },
    recursion::dummy_circuit::cyclic_base_proof,
};

use super::error::InnocenceError;

use crate::{
    common::trees::nullifier_tree::NullifierTree,
    constants::CYCLIC_CIRCUIT_PADDING_DEGREE,
    ethereum_types::{
        u256::{U256Target, U256},
        u32limb_trait::U32LimbTargetTrait,
    },
    utils::{
        conversion::ToField as _,
        cyclic::vd_vec_len,
        poseidon_hash_out::{PoseidonHashOut, PoseidonHashOutTarget, POSEIDON_HASH_OUT_LEN},
    },
};

use super::innocence_inner_target::{InnocenceInnerTarget, InnocenceInnerValue};

/// Length of public inputs for the innocence circuit
pub const INNOCENCE_PUBLIC_INPUTS_LEN: usize = 1 + 3 * POSEIDON_HASH_OUT_LEN;

/// Public inputs for the innocence circuit
///
/// These values are made public in the ZKP and are used to verify that deposits
/// comply with allow/deny lists and to track the nullifier tree state.
#[derive(Clone, Debug)]
pub struct InnocencePublicInputs {
    pub use_allow_list: bool, // Flag indicating if allow list checking is enabled
    pub allow_list_tree_root: PoseidonHashOut, // Root of the allow list Merkle tree
    pub deny_list_tree_root: PoseidonHashOut, // Root of the deny list Merkle tree
    pub nullifier_tree_root: PoseidonHashOut, // Current root of the nullifier tree
}

impl InnocencePublicInputs {
    pub fn to_u64_vec(&self) -> Vec<u64> {
        let vec = vec![self.use_allow_list as u64]
            .into_iter()
            .chain(self.allow_list_tree_root.to_u64_vec())
            .chain(self.deny_list_tree_root.to_u64_vec())
            .chain(self.nullifier_tree_root.to_u64_vec())
            .collect::<Vec<_>>();
        assert_eq!(vec.len(), INNOCENCE_PUBLIC_INPUTS_LEN);
        vec
    }

    pub fn from_u64_slice(slice: &[u64]) -> Result<Self, InnocenceError> {
        if slice.len() != INNOCENCE_PUBLIC_INPUTS_LEN {
            return Err(InnocenceError::InvalidInput(format!(
                "Invalid length for InnocencePublicInputs: expected {}, got {}",
                INNOCENCE_PUBLIC_INPUTS_LEN,
                slice.len()
            )));
        }
        let use_allow_list = slice[0] != 0;
        let allow_list_tree_root =
            PoseidonHashOut::from_u64_slice(&slice[1..1 + POSEIDON_HASH_OUT_LEN]).unwrap();
        let deny_list_tree_root = PoseidonHashOut::from_u64_slice(
            &slice[1 + POSEIDON_HASH_OUT_LEN..1 + 2 * POSEIDON_HASH_OUT_LEN],
        )
        .unwrap();
        let nullifier_tree_root = PoseidonHashOut::from_u64_slice(
            &slice[1 + 2 * POSEIDON_HASH_OUT_LEN..1 + 3 * POSEIDON_HASH_OUT_LEN],
        )
        .unwrap();
        Ok(Self {
            use_allow_list,
            allow_list_tree_root,
            deny_list_tree_root,
            nullifier_tree_root,
        })
    }
}

/// Target version of InnocencePublicInputs for use in ZKP circuits
///
/// Contains circuit targets for all public inputs that will be exposed
/// in the proof for verification.
#[derive(Clone, Debug)]
pub struct InnocencePublicInputsTarget {
    pub use_allow_list: BoolTarget, // Target for allow list flag
    pub allow_list_tree_root: PoseidonHashOutTarget, // Target for allow list root
    pub deny_list_tree_root: PoseidonHashOutTarget, // Target for deny list root
    pub nullifier_tree_root: PoseidonHashOutTarget, // Target for nullifier tree root
}

impl InnocencePublicInputsTarget {
    /// Converts the target public inputs to a vector of targets for registration
    pub fn to_vec(&self) -> Vec<Target> {
        let vec = vec![self.use_allow_list.target]
            .into_iter()
            .chain(self.allow_list_tree_root.to_vec())
            .chain(self.deny_list_tree_root.to_vec())
            .chain(self.nullifier_tree_root.to_vec())
            .collect::<Vec<_>>();
        assert_eq!(vec.len(), INNOCENCE_PUBLIC_INPUTS_LEN);
        vec
    }

    /// Creates target public inputs from a slice of targets
    pub fn from_slice(slice: &[Target]) -> Self {
        assert_eq!(slice.len(), INNOCENCE_PUBLIC_INPUTS_LEN);
        let use_allow_list = BoolTarget::new_unsafe(slice[0]);
        let allow_list_tree_root =
            PoseidonHashOutTarget::from_slice(&slice[1..1 + POSEIDON_HASH_OUT_LEN]);
        let deny_list_tree_root = PoseidonHashOutTarget::from_slice(
            &slice[1 + POSEIDON_HASH_OUT_LEN..1 + 2 * POSEIDON_HASH_OUT_LEN],
        );
        let nullifier_tree_root = PoseidonHashOutTarget::from_slice(
            &slice[1 + 2 * POSEIDON_HASH_OUT_LEN..1 + 3 * POSEIDON_HASH_OUT_LEN],
        );
        Self {
            use_allow_list,
            allow_list_tree_root,
            deny_list_tree_root,
            nullifier_tree_root,
        }
    }

    /// Creates target public inputs from a slice of public input targets
    pub fn from_pis(pis: &[Target]) -> Self {
        Self::from_slice(&pis[0..INNOCENCE_PUBLIC_INPUTS_LEN])
    }
}

/// Circuit for verifying deposits against allow/deny lists using IVC
///
/// This circuit implements an Incrementally Verifiable Computation (IVC) that processes
/// deposits sequentially, creating a proof for each deposit and its corresponding
/// nullifier tree transition. It ensures that all assets in the system came from
/// approved sources by validating depositor addresses against allow/deny lists.
pub struct InnocenceCircuit<F, C, const D: usize>
where
    F: RichField + Extendable<D>,
    C: GenericConfig<D, F = F>,
{
    is_first_step: BoolTarget, // Flag indicating if this is the first step in the IVC
    inner_target: InnocenceInnerTarget, /* Target for the inner circuit that validates a single
                                * deposit */
    prev_proof: ProofWithPublicInputsTarget<D>, // Target for the proof of the previous step
    verifier_data_target: VerifierCircuitTarget, // Target for verifier data
    pub data: CircuitData<F, C, D>,             // Circuit data
}

impl<F, C, const D: usize> Default for InnocenceCircuit<F, C, D>
where
    F: RichField + Extendable<D>,
    C: GenericConfig<D, F = F> + 'static,
    C::Hasher: AlgebraicHasher<F>,
{
    fn default() -> Self {
        Self::new()
    }
}

impl<F, C, const D: usize> InnocenceCircuit<F, C, D>
where
    F: RichField + Extendable<D>,
    C: GenericConfig<D, F = F> + 'static,
    C::Hasher: AlgebraicHasher<F>,
{
    /// Creates a new InnocenceCircuit with the necessary constraints for IVC
    ///
    /// This circuit implements an Incrementally Verifiable Computation (IVC) that:
    /// 1. Validates each deposit against allow/deny lists using the inner circuit
    /// 2. Connects the nullifier tree roots between steps to ensure valid transitions
    /// 3. Handles the first step specially by initializing with an empty nullifier tree
    ///
    /// # Returns
    /// A new InnocenceCircuit ready to generate proofs
    pub fn new() -> Self {
        let mut builder = CircuitBuilder::<F, D>::new(CircuitConfig::default());

        // Create targets for the IVC circuit
        let is_first_step = builder.add_virtual_bool_target_safe();
        let is_not_first_step = builder.not(is_first_step);

        // Create the inner circuit target that validates a single deposit
        let inner_target = InnocenceInnerTarget::new::<F, C, D>(&mut builder, true);

        // Register public inputs from the inner circuit
        let pis = InnocencePublicInputsTarget {
            use_allow_list: inner_target.use_allow_list,
            allow_list_tree_root: inner_target.allow_list_tree_root,
            deny_list_tree_root: inner_target.deny_list_tree_root,
            nullifier_tree_root: inner_target.new_nullifier_tree_root,
        };
        builder.register_public_inputs(&pis.to_vec());

        // Set up the cyclic circuit for IVC
        let common_data = common_data_for_innocence_circuit::<F, C, D>();
        let verifier_data_target = builder.add_verifier_data_public_inputs();

        // Add the previous proof target and verify it conditionally
        let prev_proof = builder.add_virtual_proof_with_pis(&common_data);
        builder
            .conditionally_verify_cyclic_proof_or_dummy::<C>(
                is_not_first_step,
                &prev_proof,
                &common_data,
            )
            .unwrap();
        let prev_pis = InnocencePublicInputsTarget::from_pis(&prev_proof.public_inputs);

        // Connect the previous proof's outputs to the current step's inputs
        // This ensures continuity in the IVC chain
        builder.connect(
            prev_pis.use_allow_list.target,
            inner_target.use_allow_list.target,
        );
        prev_pis
            .allow_list_tree_root
            .connect(&mut builder, inner_target.allow_list_tree_root);
        prev_pis
            .deny_list_tree_root
            .connect(&mut builder, inner_target.deny_list_tree_root);
        prev_pis
            .nullifier_tree_root
            .connect(&mut builder, inner_target.prev_nullifier_tree_root);

        // For the first step, ensure the previous nullifier tree root is the empty tree root
        let initial_nullifier_tree_root = NullifierTree::new().get_root();
        let initial_nullifier_tree_root_target =
            PoseidonHashOutTarget::constant(&mut builder, initial_nullifier_tree_root);
        prev_pis.nullifier_tree_root.conditional_assert_eq(
            &mut builder,
            initial_nullifier_tree_root_target,
            is_first_step,
        );

        // Build the circuit
        let (data, success) = builder.try_build_with_options::<C>(true);
        assert_eq!(data.common, common_data);
        assert!(success);

        Self {
            is_first_step,
            inner_target,
            prev_proof,
            verifier_data_target,
            data,
        }
    }

    pub fn prove(
        &self,
        inner_value: &InnocenceInnerValue,
        prev_proof: &Option<ProofWithPublicInputs<F, C, D>>,
    ) -> Result<ProofWithPublicInputs<F, C, D>, InnocenceError> {
        let mut pw = PartialWitness::<F>::new();
        pw.set_verifier_data_target(&self.verifier_data_target, &self.data.verifier_only);
        self.inner_target.set_witness(&mut pw, inner_value);

        if prev_proof.is_none() {
            // This is the first step in the IVC chain
            // Create initial public inputs with an empty nullifier tree
            let initial_pis = InnocencePublicInputs {
                use_allow_list: inner_value.use_allow_list,
                allow_list_tree_root: inner_value.allow_list_tree_root,
                deny_list_tree_root: inner_value.deny_list_tree_root,
                nullifier_tree_root: NullifierTree::new().get_root(),
            };

            // Create a dummy proof for the first step
            let dummy_proof = cyclic_base_proof(
                &self.data.common,
                &self.data.verifier_only,
                initial_pis
                    .to_u64_vec()
                    .to_field_vec::<F>()
                    .into_iter()
                    .enumerate()
                    .collect(),
            );
            pw.set_bool_target(self.is_first_step, true);
            pw.set_proof_with_pis_target(&self.prev_proof, &dummy_proof);
        } else {
            // This is a subsequent step in the IVC chain
            pw.set_bool_target(self.is_first_step, false);
            pw.set_proof_with_pis_target(&self.prev_proof, prev_proof.as_ref().unwrap());
        }

        // Generate the proof
        self.data
            .prove(pw)
            .map_err(|e| InnocenceError::InnocenceCircuitProofFailed(e.to_string()))
    }
}

/// Creates the common circuit data for the innocence circuit
fn common_data_for_innocence_circuit<
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
    while builder.num_gates() < 1 << (CYCLIC_CIRCUIT_PADDING_DEGREE - 1) {
        builder.add_gate(NoopGate, vec![]);
    }
    let zero = U256Target::zero::<F, D, U256>(&mut builder);
    let one = U256Target::constant::<F, D, U256>(&mut builder, 1.into());
    zero.is_le(&mut builder, &one); // to add comparison gate
    let mut common = builder.build::<C>().common;
    common.num_public_inputs = INNOCENCE_PUBLIC_INPUTS_LEN + vd_vec_len(&common.config);
    common
}

#[cfg(test)]
mod tests {
    use plonky2::{
        field::goldilocks_field::GoldilocksField, plonk::config::PoseidonGoldilocksConfig,
    };

    use crate::{
        circuits::proof_of_innocence::address_list_tree::AddressListTree,
        common::{deposit::Deposit, trees::nullifier_tree::NullifierTree},
        ethereum_types::{address::Address, bytes32::Bytes32, u32limb_trait::U32LimbTrait},
    };

    use super::{InnocenceCircuit, InnocenceInnerValue};

    type F = GoldilocksField;
    type C = PoseidonGoldilocksConfig;
    const D: usize = 2;

    #[test]
    fn test_innocence_circuit() {
        let mut rng = rand::thread_rng();
        let depositor = Address::rand(&mut rng);

        let allow_list_tree = AddressListTree::new(&[depositor]).unwrap();
        let deny_list_tree = AddressListTree::new(&[]).unwrap();
        let mut nullifier_tree = NullifierTree::new();
        let prev_nullifier_tree_root = nullifier_tree.get_root();

        let deposit = Deposit {
            depositor,
            pubkey_salt_hash: Bytes32::rand(&mut rng),
            amount: 100.into(),
            token_index: 0,
            is_eligible: true,
        };
        let nullifier_proof = nullifier_tree
            .prove_and_insert(deposit.poseidon_hash().into())
            .unwrap();
        let allow_list_membership_proof = allow_list_tree.prove_membership(depositor);
        let deny_list_membership_proof = deny_list_tree.prove_membership(depositor);

        let value = InnocenceInnerValue::new(
            true,
            allow_list_tree.get_root(),
            deny_list_tree.get_root(),
            prev_nullifier_tree_root,
            deposit,
            nullifier_proof,
            allow_list_membership_proof,
            deny_list_membership_proof,
        )
        .unwrap();

        let circuit = InnocenceCircuit::<F, C, D>::new();
        let proof = circuit.prove(&value, &None).unwrap();
        circuit.data.verify(proof).unwrap();
    }
}
