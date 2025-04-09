//! Private state transition circuit for token balance updates.
//!
//! This circuit proves the transition of a private state by:
//! 1. Increasing the balance of a specific token (identified by token_index) by a given amount
//! 2. Adding a nullifier to the nullifier tree to prevent double-spending
//!
//! The private state transition is used during token transfers and deposit receipts,
//! updating the recipient's balance while maintaining the integrity of the state.

use plonky2::{
    field::{extension::Extendable, types::Field},
    hash::hash_types::RichField,
    iop::{target::Target, witness::WitnessWrite},
    plonk::{
        circuit_builder::CircuitBuilder,
        config::{AlgebraicHasher, GenericConfig},
    },
};

use super::error::ReceiveTargetsError;

use crate::{
    common::{
        private_state::{PrivateState, PrivateStateTarget},
        salt::{Salt, SaltTarget},
        trees::{
            asset_tree::{AssetLeaf, AssetLeafTarget, AssetMerkleProof, AssetMerkleProofTarget},
            nullifier_tree::{NullifierInsertionProof, NullifierInsertionProofTarget},
        },
    },
    constants::ASSET_TREE_HEIGHT,
    ethereum_types::{
        bytes32::{Bytes32, Bytes32Target},
        u256::{U256Target, U256},
        u32limb_trait::U32LimbTargetTrait as _,
    },
};

// PrivateStateTransitionValue represents a private state transition where a token balance
// is increased and a nullifier is added to the nullifier tree. This is used when receiving
// tokens from transfers or deposits.
#[derive(Debug, Clone)]
pub struct PrivateStateTransitionValue {
    pub token_index: u32,                 // token index of incoming transfer/deposit
    pub amount: U256,                     // token amount of incoming transfer/deposit
    pub nullifier: Bytes32,               // nullifier of corresponding transfer/deposit
    pub new_private_state_salt: Salt,     // new salt of the private state
    pub prev_private_state: PrivateState, // previous private state
    pub nullifier_proof: NullifierInsertionProof, // merkle proof to update nullifier tree
    pub prev_asset_leaf: AssetLeaf,       /* previous asset leaf (balance) of correspoing
                                           * token_index */
    pub asset_merkle_proof: AssetMerkleProof, // merkle proof to update asset tree
    pub new_private_state: PrivateState,      // new private state
}

impl PrivateStateTransitionValue {
    #[allow(clippy::too_many_arguments)]
    /// Creates a new PrivateStateTransitionValue by validating and computing the state transition.
    ///
    /// This function:
    /// 1. Verifies the nullifier can be inserted into the nullifier tree
    /// 2. Verifies the asset merkle proof for the token being updated
    /// 3. Computes the new asset leaf by adding the amount to the previous balance
    /// 4. Constructs the new private state with updated roots and salt
    ///
    /// # Arguments
    /// * `token_index` - Index of the token being updated
    /// * `amount` - Amount to add to the token balance
    /// * `nullifier` - Nullifier to add to the nullifier tree (prevents double-spending)
    /// * `new_salt` - New salt for the private state
    /// * `prev_private_state` - Previous private state
    /// * `nullifier_proof` - Proof for nullifier insertion
    /// * `prev_asset_leaf` - Previous asset leaf (balance) for the token
    /// * `asset_merkle_proof` - Merkle proof for the asset tree
    ///
    /// # Returns
    /// A Result containing either the new PrivateStateTransitionValue or an error
    pub fn new(
        token_index: u32,
        amount: U256,
        nullifier: Bytes32,
        new_salt: Salt,
        prev_private_state: &PrivateState,
        nullifier_proof: &NullifierInsertionProof,
        prev_asset_leaf: &AssetLeaf,
        asset_merkle_proof: &AssetMerkleProof,
    ) -> Result<Self, ReceiveTargetsError> {
        let prev_private_commitment = prev_private_state.commitment();
        let new_nullifier_tree_root = nullifier_proof
            .get_new_root(prev_private_state.nullifier_tree_root, nullifier)
            .map_err(|e| {
                ReceiveTargetsError::VerificationFailed(format!(
                    "Invalid nullifier merkle proof: {}",
                    e
                ))
            })?;

        asset_merkle_proof
            .verify(
                prev_asset_leaf,
                token_index as u64,
                prev_private_state.asset_tree_root,
            )
            .map_err(|e| {
                ReceiveTargetsError::VerificationFailed(format!(
                    "Invalid asset merkle proof: {}",
                    e
                ))
            })?;

        let new_asset_leaf = prev_asset_leaf.add(amount);
        let new_asset_tree_root = asset_merkle_proof.get_root(&new_asset_leaf, token_index as u64);
        let new_private_state = PrivateState {
            asset_tree_root: new_asset_tree_root,
            nullifier_tree_root: new_nullifier_tree_root,
            prev_private_commitment,
            salt: new_salt,
            ..prev_private_state.clone()
        };

        Ok(Self {
            token_index,
            amount,
            nullifier,
            new_private_state_salt: new_salt,
            prev_private_state: prev_private_state.clone(),
            nullifier_proof: nullifier_proof.clone(),
            prev_asset_leaf: *prev_asset_leaf,
            asset_merkle_proof: asset_merkle_proof.clone(),
            new_private_state,
        })
    }
}

/// Target version of PrivateStateTransitionValue for use in ZKP circuits.
///
/// This struct contains circuit targets for all components needed to verify a private state
/// transition, including token updates and nullifier insertions.
#[derive(Debug, Clone)]
pub struct PrivateStateTransitionTarget {
    pub token_index: Target,
    pub amount: U256Target,
    pub nullifier: Bytes32Target,
    pub new_private_state_salt: SaltTarget,
    pub prev_private_state: PrivateStateTarget,
    pub nullifier_proof: NullifierInsertionProofTarget,
    pub prev_asset_leaf: AssetLeafTarget,
    pub asset_merkle_proof: AssetMerkleProofTarget,
    pub new_private_state: PrivateStateTarget,
}

impl PrivateStateTransitionTarget {
    /// Creates a new PrivateStateTransitionTarget with circuit constraints that enforce
    /// the private state transition rules.
    ///
    /// The circuit enforces:
    /// 1. Valid nullifier insertion into the nullifier tree
    /// 2. Valid asset merkle proof for the token being updated
    /// 3. Correct computation of the new asset leaf by adding the amount
    /// 4. Proper construction of the new private state with updated roots
    ///
    /// # Arguments
    /// * `builder` - Circuit builder
    /// * `is_checked` - Whether to add constraints for checking the values
    ///
    /// # Returns
    /// A new PrivateStateTransitionTarget with all necessary targets and constraints
    pub fn new<F: RichField + Extendable<D>, C: GenericConfig<D, F = F> + 'static, const D: usize>(
        builder: &mut CircuitBuilder<F, D>,
        is_checked: bool,
    ) -> Self
    where
        <C as GenericConfig<D>>::Hasher: AlgebraicHasher<F>,
    {
        let token_index = builder.add_virtual_target();
        let amount = U256Target::new(builder, is_checked);
        let nullifier = Bytes32Target::new(builder, is_checked);
        let new_salt = SaltTarget::new(builder);
        let prev_private_state = PrivateStateTarget::new(builder);
        let nullifier_proof = NullifierInsertionProofTarget::new(builder, is_checked);
        let prev_asset_leaf = AssetLeafTarget::new(builder, is_checked);
        let asset_merkle_proof = AssetMerkleProofTarget::new(builder, ASSET_TREE_HEIGHT);

        let prev_private_commitment = prev_private_state.commitment(builder);
        let new_nullifier_tree_root = nullifier_proof.get_new_root::<F, C, D>(
            builder,
            prev_private_state.nullifier_tree_root,
            nullifier,
        );
        asset_merkle_proof.verify::<F, C, D>(
            builder,
            &prev_asset_leaf,
            token_index,
            prev_private_state.asset_tree_root,
        );
        let new_asset_leaf = prev_asset_leaf.add(builder, amount);
        let new_asset_tree_root =
            asset_merkle_proof.get_root::<F, C, D>(builder, &new_asset_leaf, token_index);
        let new_private_state = PrivateStateTarget {
            asset_tree_root: new_asset_tree_root,
            nullifier_tree_root: new_nullifier_tree_root,
            prev_private_commitment,
            salt: new_salt,
            ..prev_private_state
        };
        Self {
            token_index,
            amount,
            nullifier,
            new_private_state_salt: new_salt,
            prev_private_state,
            nullifier_proof,
            prev_asset_leaf,
            asset_merkle_proof,
            new_private_state,
        }
    }

    /// Sets the witness values for all targets in this PrivateStateTransitionTarget.
    ///
    /// # Arguments
    /// * `witness` - Witness to set values in
    /// * `value` - PrivateStateTransitionValue containing the values to set
    pub fn set_witness<W: WitnessWrite<F>, F: Field>(
        &self,
        witness: &mut W,
        value: &PrivateStateTransitionValue,
    ) {
        witness.set_target(self.token_index, F::from_canonical_u32(value.token_index));
        self.amount.set_witness(witness, value.amount);
        self.nullifier.set_witness(witness, value.nullifier);
        self.new_private_state_salt
            .set_witness(witness, value.new_private_state_salt);
        self.prev_private_state
            .set_witness(witness, &value.prev_private_state);
        self.nullifier_proof
            .set_witness(witness, &value.nullifier_proof);
        self.prev_asset_leaf
            .set_witness(witness, value.prev_asset_leaf);
        self.asset_merkle_proof
            .set_witness(witness, &value.asset_merkle_proof);
        self.new_private_state
            .set_witness(witness, &value.new_private_state);
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
    use rand::Rng;

    use crate::{
        circuits::balance::receive::receive_targets::private_state_transition::PrivateStateTransitionTarget,
        common::{
            private_state::PrivateState,
            salt::Salt,
            transfer::Transfer,
            trees::{asset_tree::AssetTree, nullifier_tree::NullifierTree},
        },
        constants::ASSET_TREE_HEIGHT,
        ethereum_types::bytes32::Bytes32,
        utils::poseidon_hash_out::PoseidonHashOut,
    };

    use super::PrivateStateTransitionValue;

    type F = GoldilocksField;
    type C = PoseidonGoldilocksConfig;
    const D: usize = 2;

    #[test]
    fn test_private_state_transition() {
        let mut rng = rand::thread_rng();
        let transfer = Transfer::rand(&mut rng);
        let _pubkey = transfer.recipient.to_pubkey().unwrap();

        let mut asset_tree = AssetTree::new(ASSET_TREE_HEIGHT);
        let mut nullifier_tree = NullifierTree::new();
        let prev_private_state = PrivateState {
            asset_tree_root: asset_tree.get_root(),
            nullifier_tree_root: nullifier_tree.get_root(),
            prev_private_commitment: PoseidonHashOut::default(),
            nonce: rng.gen(),
            salt: Salt::rand(&mut rng),
        };
        let prev_private_commitment = prev_private_state.commitment();

        let prev_asset_leaf = asset_tree.get_leaf(transfer.token_index as u64);
        let asset_merkle_proof = asset_tree.prove(transfer.token_index as u64);
        let new_asset_leaf = prev_asset_leaf.add(transfer.amount);
        asset_tree.update(transfer.token_index as u64, new_asset_leaf);

        let nullifier: Bytes32 = transfer.poseidon_hash().into();
        let nullifier_proof = nullifier_tree.prove_and_insert(nullifier).unwrap();

        let new_salt = Salt::rand(&mut rng);
        let value = PrivateStateTransitionValue::new(
            transfer.token_index,
            transfer.amount,
            nullifier,
            new_salt,
            &prev_private_state,
            &nullifier_proof,
            &prev_asset_leaf,
            &asset_merkle_proof,
        )
        .unwrap();

        let expected_new_private_state = PrivateState {
            asset_tree_root: asset_tree.get_root(),
            nullifier_tree_root: nullifier_tree.get_root(),
            prev_private_commitment,
            nonce: prev_private_state.nonce,
            salt: new_salt,
        };
        assert_eq!(value.new_private_state, expected_new_private_state);

        let mut builder = CircuitBuilder::new(CircuitConfig::default());
        let target = PrivateStateTransitionTarget::new::<F, C, D>(&mut builder, true);
        let data = builder.build::<C>();

        let mut pw = PartialWitness::<F>::new();
        target.set_witness(&mut pw, &value);
        let _ = data.prove(pw).unwrap();
    }
}
