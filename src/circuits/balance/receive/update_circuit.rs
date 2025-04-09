//! Update circuit for updating a user's public state.
//!
//! This circuit proves the update of a user's public state to a new public state.
//! It is used when a user wants to update their public state without having sent
//! any transactions between the old and new public states. If the user has sent
//! transactions during this period, they must use the sender circuit instead.
//!
//! The update circuit enforces the following constraints:
//! 1. The validity proof for the new public state is correct
//! 2. The block hash of the old public state is included in the new public state's block tree
//! 3. The user's last block number (when they last sent a transaction) is the same or older
//!    than the old public state's block number

use super::error::UpdateError;
use plonky2::{
    field::extension::Extendable,
    hash::hash_types::RichField,
    iop::{
        target::Target,
        witness::{PartialWitness, WitnessWrite},
    },
    plonk::{
        circuit_builder::CircuitBuilder,
        circuit_data::{CircuitConfig, CircuitData, VerifierCircuitData},
        config::{AlgebraicHasher, GenericConfig},
        proof::{ProofWithPublicInputs, ProofWithPublicInputsTarget},
    },
};

use crate::{
    circuits::validity::validity_pis::{
        ValidityPublicInputs, ValidityPublicInputsTarget, VALIDITY_PUBLIC_INPUTS_LEN,
    },
    common::{
        public_state::{PublicState, PublicStateTarget, PUBLIC_STATE_LEN},
        trees::{
            account_tree::{AccountMembershipProof, AccountMembershipProofTarget},
            block_hash_tree::{BlockHashMerkleProof, BlockHashMerkleProofTarget},
        },
    },
    constants::{ACCOUNT_TREE_HEIGHT, BLOCK_HASH_TREE_HEIGHT},
    ethereum_types::{
        u256::{U256Target, U256, U256_LEN},
        u32limb_trait::{U32LimbTargetTrait, U32LimbTrait},
    },
    utils::{dummy::DummyProof, recursively_verifiable::add_proof_target_and_verify_cyclic},
};

pub const UPDATE_PUBLIC_INPUTS_LEN: usize = U256_LEN + PUBLIC_STATE_LEN * 2;

/// Public inputs for the update circuit.
///
/// Contains the user's public key and both the previous and new public states
/// that are being updated between.
#[derive(Debug, Clone)]
pub struct UpdatePublicInputs {
    pub pubkey: U256,
    pub prev_public_state: PublicState,
    pub new_public_state: PublicState,
}

/// Target version of UpdatePublicInputs for use in ZKP circuits.
#[derive(Debug, Clone)]
pub struct UpdatePublicInputsTarget {
    pub pubkey: U256Target,
    pub prev_public_state: PublicStateTarget,
    pub new_public_state: PublicStateTarget,
}

impl UpdatePublicInputs {
    pub fn to_u64_vec(&self) -> Vec<u64> {
        let vec = [
            self.pubkey.to_u64_vec(),
            self.prev_public_state.to_u64_vec(),
            self.new_public_state.to_u64_vec(),
        ]
        .concat();
        assert_eq!(vec.len(), UPDATE_PUBLIC_INPUTS_LEN);
        vec
    }

    pub fn from_u64_slice(input: &[u64]) -> Self {
        assert_eq!(input.len(), UPDATE_PUBLIC_INPUTS_LEN);
        let pubkey = U256::from_u64_slice(&input[0..U256_LEN]).unwrap();
        let prev_public_state =
            PublicState::from_u64_slice(&input[U256_LEN..U256_LEN + PUBLIC_STATE_LEN]);
        let new_public_state = PublicState::from_u64_slice(&input[U256_LEN + PUBLIC_STATE_LEN..]);
        UpdatePublicInputs {
            pubkey,
            prev_public_state,
            new_public_state,
        }
    }
}

impl UpdatePublicInputsTarget {
    pub fn to_vec(&self) -> Vec<Target> {
        let vec = [
            self.pubkey.to_vec(),
            self.prev_public_state.to_vec(),
            self.new_public_state.to_vec(),
        ]
        .concat();
        assert_eq!(vec.len(), UPDATE_PUBLIC_INPUTS_LEN);
        vec
    }

    pub fn from_slice(input: &[Target]) -> Self {
        assert_eq!(input.len(), UPDATE_PUBLIC_INPUTS_LEN);
        let pubkey = U256Target::from_slice(&input[0..U256_LEN]);
        let prev_public_state =
            PublicStateTarget::from_slice(&input[U256_LEN..U256_LEN + PUBLIC_STATE_LEN]);
        let new_public_state = PublicStateTarget::from_slice(&input[U256_LEN + PUBLIC_STATE_LEN..]);
        UpdatePublicInputsTarget {
            pubkey,
            prev_public_state,
            new_public_state,
        }
    }
}

/// Values required for the update circuit.
///
/// This struct contains all the values needed to prove a valid update of a user's public state:
/// - The user's public key
/// - The previous and new public states
/// - A validity proof for the new public state
/// - A merkle proof showing the old block hash is included in the new block tree
/// - An account membership proof to verify the user's last transaction block number
#[derive(Debug, Clone)]
pub struct UpdateValue<
    F: RichField + Extendable<D>,
    C: GenericConfig<D, F = F> + 'static,
    const D: usize,
> where
    <C as GenericConfig<D>>::Hasher: AlgebraicHasher<F>,
{
    pub pubkey: U256,
    pub prev_public_state: PublicState,
    pub new_public_state: PublicState,
    pub validity_proof: ProofWithPublicInputs<F, C, D>,
    pub block_merkle_proof: BlockHashMerkleProof,
    pub account_membership_proof: AccountMembershipProof, // to get last block number
}

impl<F: RichField + Extendable<D>, C: GenericConfig<D, F = F> + 'static, const D: usize>
    UpdateValue<F, C, D>
where
    <C as GenericConfig<D>>::Hasher: AlgebraicHasher<F>,
{
    /// Creates a new UpdateValue by validating all the components needed for a public state update.
    ///
    /// This function performs the following validations:
    /// 1. Verifies the validity proof for the new public state
    /// 2. Verifies the block merkle proof showing the old block hash is included in the new block tree
    /// 3. Verifies the account membership proof to get the user's last transaction block number
    /// 4. Checks that the user's last transaction block number is not newer than the previous public state
    ///
    /// # Arguments
    /// * `validity_vd` - Verifier data for the validity circuit
    /// * `pubkey` - The user's public key
    /// * `validity_proof` - Proof of validity for the new public state
    /// * `prev_public_state` - The previous public state
    /// * `block_merkle_proof` - Proof that the old block hash is included in the new block tree
    /// * `account_membership_proof` - Proof of the user's account in the new state's account tree
    ///
    /// # Returns
    /// A Result containing either the new UpdateValue or an error if any validation fails
    pub fn new(
        validity_vd: &VerifierCircuitData<F, C, D>,
        pubkey: U256,
        validity_proof: &ProofWithPublicInputs<F, C, D>,
        prev_public_state: &PublicState,
        block_merkle_proof: &BlockHashMerkleProof,
        account_membership_proof: &AccountMembershipProof,
    ) -> Result<Self, UpdateError> {
        validity_vd.verify(validity_proof.clone()).map_err(|e| {
            UpdateError::VerificationFailed(format!("Validity proof is invalid: {:?}", e))
        })?;

        let validity_pis = ValidityPublicInputs::from_pis(&validity_proof.public_inputs);

        block_merkle_proof
            .verify(
                &prev_public_state.block_hash,
                prev_public_state.block_number as u64,
                validity_pis.public_state.block_tree_root,
            )
            .map_err(|e| {
                UpdateError::VerificationFailed(format!("Block merkle proof is invalid: {:?}", e))
            })?;

        account_membership_proof
            .verify(pubkey, validity_pis.public_state.account_tree_root)
            .map_err(|e| {
                UpdateError::VerificationFailed(format!(
                    "Account membership proof is invalid: {:?}",
                    e
                ))
            })?;

        let last_block_number = account_membership_proof.get_value() as u32;

        if last_block_number > prev_public_state.block_number {
            return Err(UpdateError::VerificationFailed(format!(
                "Last block number is invalid: last_block_number={}, prev_block_number={}",
                last_block_number, prev_public_state.block_number
            )));
        }

        Ok(Self {
            pubkey,
            prev_public_state: prev_public_state.clone(),
            new_public_state: validity_pis.public_state.clone(),
            validity_proof: validity_proof.clone(),
            block_merkle_proof: block_merkle_proof.clone(),
            account_membership_proof: account_membership_proof.clone(),
        })
    }
}

/// Target version of UpdateValue for use in ZKP circuits.
///
/// This struct contains circuit targets for all components needed to verify a public state update,
/// including the user's public key, previous and new public states, validity proof,
/// block merkle proof, and account membership proof.
#[derive(Debug, Clone)]
pub struct UpdateTarget<const D: usize> {
    pub pubkey: U256Target,
    pub prev_public_state: PublicStateTarget,
    pub new_public_state: PublicStateTarget,
    pub validity_proof: ProofWithPublicInputsTarget<D>,
    pub block_merkle_proof: BlockHashMerkleProofTarget,
    pub account_membership_proof: AccountMembershipProofTarget,
}

impl<const D: usize> UpdateTarget<D> {
    /// Creates a new UpdateTarget with circuit constraints that enforce the update circuit rules.
    ///
    /// This method builds the circuit constraints that verify:
    /// 1. The validity proof for the new public state is correct (via add_proof_target_and_verify_cyclic)
    /// 2. The block hash of the old public state is included in the new public state's block tree
    /// 3. The user's last transaction block number is not newer than the previous public state
    ///
    /// # Arguments
    /// * `validity_vd` - Verifier data for the validity circuit
    /// * `builder` - Circuit builder to add constraints to
    /// * `is_checked` - Whether to add range check constraints for the targets
    ///
    /// # Returns
    /// A new UpdateTarget with all necessary targets and constraints
    pub fn new<F: RichField + Extendable<D>, C: GenericConfig<D, F = F> + 'static>(
        validity_vd: &VerifierCircuitData<F, C, D>,
        builder: &mut CircuitBuilder<F, D>,
        is_checked: bool,
    ) -> Self
    where
        <C as GenericConfig<D>>::Hasher: AlgebraicHasher<F>,
    {
        let pubkey = U256Target::new(builder, is_checked);
        let block_merkle_proof = BlockHashMerkleProofTarget::new(builder, BLOCK_HASH_TREE_HEIGHT);
        let prev_public_state = PublicStateTarget::new(builder, is_checked);
        let validity_proof = add_proof_target_and_verify_cyclic(validity_vd, builder);
        let account_membership_proof =
            AccountMembershipProofTarget::new(builder, ACCOUNT_TREE_HEIGHT, is_checked);
        let validity_pis = ValidityPublicInputsTarget::from_slice(
            &validity_proof.public_inputs[0..VALIDITY_PUBLIC_INPUTS_LEN],
        );
        block_merkle_proof.verify::<F, C, D>(
            builder,
            &prev_public_state.block_hash,
            prev_public_state.block_number,
            validity_pis.public_state.block_tree_root,
        );
        account_membership_proof.verify::<F, C, D>(
            builder,
            pubkey,
            validity_pis.public_state.account_tree_root,
        );
        let last_block_number = account_membership_proof.get_value(builder);
        // assert last_block_number <= prev_public_state.block_number
        let diff = builder.sub(prev_public_state.block_number, last_block_number);
        builder.range_check(diff, 32);
        Self {
            pubkey,
            prev_public_state,
            new_public_state: validity_pis.public_state,
            validity_proof,
            block_merkle_proof,
            account_membership_proof,
        }
    }

    /// Sets the witness values for all targets in this UpdateTarget.
    ///
    /// # Arguments
    /// * `witness` - Witness to set values in
    /// * `value` - UpdateValue containing the values to set
    pub fn set_witness<
        F: RichField + Extendable<D>,
        C: GenericConfig<D, F = F> + 'static,
        W: WitnessWrite<F>,
    >(
        &self,
        witness: &mut W,
        value: &UpdateValue<F, C, D>,
    ) where
        <C as GenericConfig<D>>::Hasher: AlgebraicHasher<F>,
    {
        self.pubkey.set_witness(witness, value.pubkey);
        self.prev_public_state
            .set_witness(witness, &value.prev_public_state);
        self.new_public_state
            .set_witness(witness, &value.new_public_state);
        witness.set_proof_with_pis_target(&self.validity_proof, &value.validity_proof);
        self.block_merkle_proof
            .set_witness(witness, &value.block_merkle_proof);
        self.account_membership_proof
            .set_witness(witness, &value.account_membership_proof);
    }
}

/// The main update circuit for proving valid public state updates.
///
/// This circuit verifies that a user's public state can be updated to a new public state
/// without having sent any transactions in between. It enforces the constraints defined
/// in the UpdateTarget.
pub struct UpdateCircuit<F, C, const D: usize>
where
    F: RichField + Extendable<D>,
    C: GenericConfig<D, F = F>,
{
    pub data: CircuitData<F, C, D>,
    pub target: UpdateTarget<D>,
    pub dummy_proof: DummyProof<F, C, D>,
}

impl<F, C, const D: usize> UpdateCircuit<F, C, D>
where
    F: RichField + Extendable<D>,
    C: GenericConfig<D, F = F> + 'static,
    C::Hasher: AlgebraicHasher<F>,
{
    /// Creates a new UpdateCircuit with the necessary circuit data and targets.
    ///
    /// This method builds the circuit that enforces the update constraints by:
    /// 1. Creating an UpdateTarget with the validity verifier data
    /// 2. Registering the public inputs (pubkey, prev_public_state, new_public_state)
    /// 3. Building the circuit data
    ///
    /// # Arguments
    /// * `validity_vd` - Verifier data for the validity circuit
    ///
    /// # Returns
    /// A new UpdateCircuit ready to generate proofs
    pub fn new(validity_vd: &VerifierCircuitData<F, C, D>) -> Self {
        let mut builder = CircuitBuilder::<F, D>::new(CircuitConfig::default());
        let target = UpdateTarget::new::<F, C>(validity_vd, &mut builder, true);
        let pis = UpdatePublicInputsTarget {
            pubkey: target.pubkey,
            prev_public_state: target.prev_public_state.clone(),
            new_public_state: target.new_public_state.clone(),
        };
        builder.register_public_inputs(&pis.to_vec());
        let data = builder.build();
        let dummy_proof = DummyProof::new(&data.common);
        Self {
            data,
            target,
            dummy_proof,
        }
    }

    /// Generates a proof for the update circuit using the provided UpdateValue.
    ///
    /// This method:
    /// 1. Creates a partial witness from the UpdateValue
    /// 2. Generates a proof using the circuit data
    ///
    /// # Arguments
    /// * `value` - The UpdateValue containing all the values needed for the proof
    ///
    /// # Returns
    /// A Result containing either the generated proof or an error if proof generation fails
    pub fn prove(
        &self,
        value: &UpdateValue<F, C, D>,
    ) -> Result<ProofWithPublicInputs<F, C, D>, UpdateError> {
        let mut pw = PartialWitness::<F>::new();
        self.target.set_witness(&mut pw, value);
        self.data
            .prove(pw)
            .map_err(|e| UpdateError::ProofGenerationError(format!("{:?}", e)))
    }
}

#[cfg(test)]
mod tests {
    use crate::{
        circuits::{
            test_utils::state_manager::ValidityStateManager,
            validity::validity_processor::ValidityProcessor,
        },
        common::{public_state::PublicState, signature_content::key_set::KeySet},
        ethereum_types::address::Address,
    };
    use plonky2::{
        field::goldilocks_field::GoldilocksField, plonk::config::PoseidonGoldilocksConfig,
    };
    use std::sync::Arc;

    use super::UpdateCircuit;

    type F = GoldilocksField;
    type C = PoseidonGoldilocksConfig;
    const D: usize = 2;

    #[test]
    fn test_update_circuit() {
        let mut rng = rand::thread_rng();
        let validity_processor = Arc::new(ValidityProcessor::<F, C, D>::new());
        let mut validity_state_manager =
            ValidityStateManager::new(validity_processor.clone(), Address::default());
        let validity_vd = validity_processor.get_verifier_data();
        let key = KeySet::rand(&mut rng);

        // post empty block
        validity_state_manager.tick(false, &[], 0, 0).unwrap();

        let update_witness = validity_state_manager
            .get_update_witness(key.pubkey, 1, 0, true)
            .unwrap();

        let update_circuit = UpdateCircuit::<F, C, D>::new(&validity_processor.get_verifier_data());
        let proof = update_circuit
            .prove(
                &update_witness
                    .to_value(&validity_vd, key.pubkey, &PublicState::genesis())
                    .unwrap(),
            )
            .unwrap();
        update_circuit.data.verify(proof).unwrap();
    }
}
