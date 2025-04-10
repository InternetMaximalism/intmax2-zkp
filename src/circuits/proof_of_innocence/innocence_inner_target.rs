//! Innocence Inner Circuit for deposit validation against allow/deny lists.
//!
//! This circuit proves that a deposit's depositor address is not in a deny list
//! and (optionally) is in an allow list. It also proves the transition of the
//! nullifier tree root after inserting the deposit's nullifier.
//!
//! The circuit performs the following validations:
//! 1. If use_allow_list is true, verifies the depositor is in the allow list
//! 2. Verifies the depositor is not in the deny list
//! 3. Verifies the nullifier tree transition by inserting the deposit's nullifier
use plonky2::{
    field::{extension::Extendable, types::Field},
    hash::hash_types::RichField,
    iop::{target::BoolTarget, witness::WitnessWrite},
    plonk::{
        circuit_builder::CircuitBuilder,
        config::{AlgebraicHasher, GenericConfig},
    },
};

use super::error::InnocenceError;

use crate::{
    circuits::proof_of_innocence::address_list_tree::AddressMembershipProofTarget,
    common::{
        deposit::{Deposit, DepositTarget},
        trees::nullifier_tree::{NullifierInsertionProof, NullifierInsertionProofTarget},
    },
    utils::poseidon_hash_out::{PoseidonHashOut, PoseidonHashOutTarget},
};

use super::address_list_tree::AddressMembershipProof;

/// Values needed for the innocence inner circuit
///
/// Contains all the data required to prove that a deposit's depositor is not in a deny list,
/// optionally is in an allow list, and to track the nullifier tree transition.
#[derive(Debug, Clone)]
pub struct InnocenceInnerValue {
    pub use_allow_list: bool, // Flag to enable allow list checking
    pub allow_list_tree_root: PoseidonHashOut, // Root of the allow list Merkle tree
    pub deny_list_tree_root: PoseidonHashOut, // Root of the deny list Merkle tree
    pub prev_nullifier_tree_root: PoseidonHashOut, // Root of the nullifier tree before insertion
    pub new_nullifier_tree_root: PoseidonHashOut, // Root of the nullifier tree after insertion
    pub deposit: Deposit,     // The deposit being validated
    pub nullifier_proof: NullifierInsertionProof, // Proof for nullifier insertion
    pub allow_list_membership_proof: AddressMembershipProof, // Proof of depositor in allow list
    pub deny_list_membership_proof: AddressMembershipProof, // Proof of depositor in deny list
}

impl InnocenceInnerValue {
    /// Creates a new InnocenceInnerValue by validating the deposit against allow/deny lists
    /// and calculating the new nullifier tree root.
    ///
    /// This function:
    /// 1. Verifies the allow list membership proof for the depositor
    /// 2. If use_allow_list is true, ensures the depositor is in the allow list
    /// 3. Verifies the deny list membership proof for the depositor
    /// 4. Ensures the depositor is not in the deny list
    /// 5. Calculates the new nullifier tree root after inserting the deposit's nullifier
    ///
    /// # Arguments
    /// * `use_allow_list` - Flag to enable allow list checking
    /// * `allow_list_tree_root` - Root of the allow list Merkle tree
    /// * `deny_list_tree_root` - Root of the deny list Merkle tree
    /// * `prev_nullifier_tree_root` - Root of the nullifier tree before insertion
    /// * `deposit` - The deposit being validated
    /// * `nullifier_proof` - Proof for nullifier insertion
    /// * `allow_list_membership_proof` - Proof of depositor in allow list
    /// * `deny_list_membership_proof` - Proof of depositor in deny list
    ///
    /// # Returns
    /// A Result containing either the new InnocenceInnerValue or an error
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        use_allow_list: bool,
        allow_list_tree_root: PoseidonHashOut,
        deny_list_tree_root: PoseidonHashOut,
        prev_nullifier_tree_root: PoseidonHashOut,
        deposit: Deposit,
        nullifier_proof: NullifierInsertionProof,
        allow_list_membership_proof: AddressMembershipProof,
        deny_list_membership_proof: AddressMembershipProof,
    ) -> Result<Self, InnocenceError> {
        // Verify allow list membership proof
        allow_list_membership_proof
            .verify(deposit.depositor, allow_list_tree_root)
            .map_err(|e| {
                InnocenceError::AllowListMembershipProofVerificationFailed(e.to_string())
            })?;

        // If allow list is enabled, ensure depositor is in the allow list
        if use_allow_list && !allow_list_membership_proof.is_included() {
            return Err(InnocenceError::DepositorNotInAllowList(deposit.depositor));
        }

        // Verify deny list membership proof
        deny_list_membership_proof
            .verify(deposit.depositor, deny_list_tree_root)
            .map_err(|e| {
                InnocenceError::DenyListMembershipProofVerificationFailed(e.to_string())
            })?;

        // Ensure depositor is not in the deny list
        if deny_list_membership_proof.is_included() {
            return Err(InnocenceError::DepositorInDenyList(deposit.depositor));
        }

        // Calculate the new nullifier tree root after inserting the deposit's nullifier
        let nullifier = deposit.nullifier();
        let new_nullifier_tree_root = nullifier_proof
            .get_new_root(prev_nullifier_tree_root, nullifier)
            .map_err(|e| InnocenceError::InvalidNullifierMerkleProof(e.to_string()))?;

        Ok(Self {
            use_allow_list,
            allow_list_tree_root,
            deny_list_tree_root,
            prev_nullifier_tree_root,
            new_nullifier_tree_root,
            deposit,
            nullifier_proof,
            allow_list_membership_proof,
            deny_list_membership_proof,
        })
    }
}

/// Target version of InnocenceInnerValue for use in ZKP circuits
///
/// Contains circuit targets for all components needed to verify a deposit's
/// compliance with allow/deny lists and track nullifier tree transitions.
#[derive(Debug, Clone)]
pub struct InnocenceInnerTarget {
    pub use_allow_list: BoolTarget, // Target for allow list flag
    pub allow_list_tree_root: PoseidonHashOutTarget, // Target for allow list root
    pub deny_list_tree_root: PoseidonHashOutTarget, // Target for deny list root
    pub prev_nullifier_tree_root: PoseidonHashOutTarget, // Target for previous nullifier root
    pub new_nullifier_tree_root: PoseidonHashOutTarget, // Target for new nullifier root
    pub deposit: DepositTarget,     // Target for deposit
    pub nullifier_proof: NullifierInsertionProofTarget, // Target for nullifier insertion proof
    pub allow_list_membership_proof: AddressMembershipProofTarget, // Target for allow list proof
    pub deny_list_membership_proof: AddressMembershipProofTarget, // Target for deny list proof
}

impl InnocenceInnerTarget {
    /// Creates a new InnocenceInnerTarget with circuit constraints that enforce
    /// the deposit validation rules against allow/deny lists.
    ///
    /// The circuit enforces:
    /// 1. If use_allow_list is true, the depositor must be in the allow list
    /// 2. The depositor must not be in the deny list
    /// 3. The nullifier tree transition must be valid after inserting the deposit's nullifier
    ///
    /// # Arguments
    /// * `builder` - Circuit builder
    /// * `is_checked` - Whether to add constraints for checking the values
    ///
    /// # Returns
    /// A new InnocenceInnerTarget with all necessary targets and constraints
    pub fn new<F: RichField + Extendable<D>, C: GenericConfig<D, F = F> + 'static, const D: usize>(
        builder: &mut CircuitBuilder<F, D>,
        is_checked: bool,
    ) -> Self
    where
        <C as GenericConfig<D>>::Hasher: AlgebraicHasher<F>,
    {
        // Create virtual targets for all inputs
        let use_allow_list = builder.add_virtual_bool_target_safe();
        let allow_list_tree_root = PoseidonHashOutTarget::new(builder);
        let deny_list_tree_root = PoseidonHashOutTarget::new(builder);
        let prev_nullifier_tree_root = PoseidonHashOutTarget::new(builder);
        let deposit = DepositTarget::new(builder, is_checked);
        let nullifier_proof = NullifierInsertionProofTarget::new(builder, is_checked);
        let allow_list_membership_proof = AddressMembershipProofTarget::new(builder, is_checked);
        let deny_list_membership_proof = AddressMembershipProofTarget::new(builder, is_checked);

        // Verify allow list membership proof
        allow_list_membership_proof.verify::<F, C, D>(
            builder,
            deposit.depositor,
            allow_list_tree_root,
        );

        // If use_allow_list is true, ensure depositor is in the allow list
        // This is done by asserting that it's not the case that (use_allow_list is true AND
        // depositor is not in allow list)
        let not_included_allow_list = builder.not(allow_list_membership_proof.is_included());
        let use_allow_list_and_not_included_allow_list =
            builder.and(use_allow_list, not_included_allow_list);
        builder.assert_zero(use_allow_list_and_not_included_allow_list.target);

        // Verify deny list membership proof
        deny_list_membership_proof.verify::<F, C, D>(
            builder,
            deposit.depositor,
            deny_list_tree_root,
        );

        // Ensure depositor is not in the deny list
        builder.assert_zero(deny_list_membership_proof.is_included().target);

        // Calculate the new nullifier tree root after inserting the deposit's nullifier
        let nullifier = deposit.nullifier(builder);
        let new_nullifier_tree_root =
            nullifier_proof.get_new_root::<F, C, D>(builder, prev_nullifier_tree_root, nullifier);

        Self {
            use_allow_list,
            allow_list_tree_root,
            deny_list_tree_root,
            prev_nullifier_tree_root,
            new_nullifier_tree_root,
            deposit,
            nullifier_proof,
            allow_list_membership_proof,
            deny_list_membership_proof,
        }
    }

    pub fn set_witness<W: WitnessWrite<F>, F: Field>(
        &self,
        witness: &mut W,
        value: &InnocenceInnerValue,
    ) {
        witness.set_bool_target(self.use_allow_list, value.use_allow_list);
        self.allow_list_tree_root
            .set_witness(witness, value.allow_list_tree_root);
        self.deny_list_tree_root
            .set_witness(witness, value.deny_list_tree_root);
        self.prev_nullifier_tree_root
            .set_witness(witness, value.prev_nullifier_tree_root);
        self.new_nullifier_tree_root
            .set_witness(witness, value.new_nullifier_tree_root);
        self.deposit.set_witness(witness, &value.deposit);
        self.nullifier_proof
            .set_witness(witness, &value.nullifier_proof);
        self.allow_list_membership_proof
            .set_witness(witness, &value.allow_list_membership_proof);
        self.deny_list_membership_proof
            .set_witness(witness, &value.deny_list_membership_proof);
    }
}

#[cfg(test)]
mod tests {
    use plonky2::{
        field::goldilocks_field::GoldilocksField,
        iop::witness::PartialWitness,
        plonk::{
            circuit_builder::CircuitBuilder, circuit_data::CircuitConfig,
            config::PoseidonGoldilocksConfig,
        },
    };

    use crate::{
        circuits::proof_of_innocence::address_list_tree::AddressListTree,
        common::{deposit::Deposit, trees::nullifier_tree::NullifierTree},
        ethereum_types::{address::Address, bytes32::Bytes32, u32limb_trait::U32LimbTrait},
    };

    use super::{InnocenceInnerTarget, InnocenceInnerValue};

    type F = GoldilocksField;
    type C = PoseidonGoldilocksConfig;
    const D: usize = 2;

    /// Tests the innocence inner circuit by creating a scenario where a deposit's depositor
    /// is in the allow list and not in the deny list, and verifying that the circuit correctly
    /// proves this along with the nullifier tree transition.
    ///
    /// The test:
    /// 1. Creates a random depositor address
    /// 2. Creates an allow list containing the depositor
    /// 3. Creates an empty deny list
    /// 4. Creates a deposit with the depositor address
    /// 5. Generates proofs of membership in the allow list and non-membership in the deny list
    /// 6. Creates an InnocenceInnerValue with all the necessary data
    /// 7. Creates an InnocenceInnerTarget and generates a proof
    /// 8. Verifies the proof is valid
    #[test]
    fn test_innocence_inner_target() {
        let mut rng = rand::thread_rng();
        let depositor = Address::rand(&mut rng);

        // Create allow list with the depositor and an empty deny list
        let allow_list_tree = AddressListTree::new(&[depositor]).unwrap();
        let deny_list_tree = AddressListTree::new(&[]).unwrap();

        // Initialize nullifier tree
        let mut nullifier_tree = NullifierTree::new();
        let prev_nullifier_tree_root = nullifier_tree.get_root();

        // Create a deposit with the depositor address
        let deposit = Deposit {
            depositor,
            pubkey_salt_hash: Bytes32::rand(&mut rng),
            amount: 100.into(),
            token_index: 0,
            is_eligible: true,
        };

        // Generate nullifier proof and membership proofs
        let nullifier_proof = nullifier_tree
            .prove_and_insert(deposit.poseidon_hash().into())
            .unwrap();
        let allow_list_membership_proof = allow_list_tree.prove_membership(depositor);
        let deny_list_membership_proof = deny_list_tree.prove_membership(depositor);

        // Create InnocenceInnerValue
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

        // Build circuit and generate proof
        let mut builder = CircuitBuilder::new(CircuitConfig::default());
        let target = InnocenceInnerTarget::new::<F, C, D>(&mut builder, true);
        let data = builder.build::<C>();

        let mut pw = PartialWitness::new();
        target.set_witness(&mut pw, &value);
        let proof = data.prove(pw).unwrap();
        data.verify(proof).unwrap();
    }
}
