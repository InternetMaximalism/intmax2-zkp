use plonky2::{
    field::{extension::Extendable, types::Field},
    hash::hash_types::RichField,
    iop::{target::Target, witness::WitnessWrite},
    plonk::circuit_builder::CircuitBuilder,
};
use serde::{Deserialize, Serialize};

use crate::{
    constants::ASSET_TREE_HEIGHT,
    utils::poseidon_hash_out::{PoseidonHashOut, PoseidonHashOutTarget},
};

use super::{
    salt::{Salt, SaltTarget},
    trees::{asset_tree::AssetTree, nullifier_tree::NullifierTree},
};

/// The part of the balance proof public input that is not disclosed to others
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PrivateState {
    /// The root of the asset tree
    pub asset_tree_root: PoseidonHashOut,

    /// The root of the nullifier tree
    pub nullifier_tree_root: PoseidonHashOut,

    /// The commitment of the previous private state
    pub prev_private_commitment: PoseidonHashOut,

    /// The nonce of the account which is corresponding to the next tx's nonce
    pub nonce: u32,

    /// The salt which is used to blind this private state
    pub salt: Salt,
}

/// The witness of the private state
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct FullPrivateState {
    pub asset_tree: AssetTree,
    pub nullifier_tree: NullifierTree,
    pub prev_private_commitment: PoseidonHashOut,
    pub nonce: u32,
    pub salt: Salt,
}

impl Default for FullPrivateState {
    fn default() -> Self {
        Self::new()
    }
}

impl FullPrivateState {
    pub fn new() -> Self {
        Self {
            asset_tree: AssetTree::new(ASSET_TREE_HEIGHT),
            nullifier_tree: NullifierTree::new(),
            prev_private_commitment: PoseidonHashOut::default(),
            nonce: 0,
            salt: Salt::default(),
        }
    }

    pub fn to_private_state(&self) -> PrivateState {
        PrivateState {
            asset_tree_root: self.asset_tree.get_root(),
            nullifier_tree_root: self.nullifier_tree.get_root(),
            prev_private_commitment: self.prev_private_commitment,
            nonce: self.nonce,
            salt: self.salt,
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PrivateStateTarget {
    pub asset_tree_root: PoseidonHashOutTarget,
    pub nullifier_tree_root: PoseidonHashOutTarget,
    pub prev_private_commitment: PoseidonHashOutTarget,
    pub nonce: Target,
    pub salt: SaltTarget,
}

impl Default for PrivateState {
    fn default() -> Self {
        Self::new()
    }
}

impl PrivateState {
    pub fn new() -> Self {
        let asset_tree_root = AssetTree::new(ASSET_TREE_HEIGHT).get_root();
        let nullifier_tree_root = NullifierTree::new().get_root();
        let prev_private_commitment = PoseidonHashOut::default();
        Self {
            asset_tree_root,
            nullifier_tree_root,
            prev_private_commitment,
            nonce: 0,
            salt: Salt::default(),
        }
    }

    pub fn to_u64_vec(&self) -> Vec<u64> {
        [
            self.asset_tree_root.to_u64_vec(),
            self.nullifier_tree_root.to_u64_vec(),
            self.prev_private_commitment.to_u64_vec(),
            vec![self.nonce as u64],
            self.salt.to_u64_vec(),
        ]
        .concat()
    }

    pub fn commitment(&self) -> PoseidonHashOut {
        PoseidonHashOut::hash_inputs_u64(&self.to_u64_vec())
    }
}

impl PrivateStateTarget {
    pub fn to_vec(&self) -> Vec<Target> {
        [
            self.asset_tree_root.to_vec(),
            self.nullifier_tree_root.to_vec(),
            self.prev_private_commitment.to_vec(),
            vec![self.nonce],
            self.salt.to_vec(),
        ]
        .concat()
    }

    pub fn commitment<F: RichField + Extendable<D>, const D: usize>(
        &self,
        builder: &mut CircuitBuilder<F, D>,
    ) -> PoseidonHashOutTarget {
        PoseidonHashOutTarget::hash_inputs(builder, &self.to_vec())
    }

    pub fn new<F: RichField + Extendable<D>, const D: usize>(
        builder: &mut CircuitBuilder<F, D>,
    ) -> Self {
        Self {
            asset_tree_root: PoseidonHashOutTarget::new(builder),
            nullifier_tree_root: PoseidonHashOutTarget::new(builder),
            prev_private_commitment: PoseidonHashOutTarget::new(builder),
            nonce: builder.add_virtual_target(),
            salt: SaltTarget::new(builder),
        }
    }

    pub fn set_witness<F: Field, W: WitnessWrite<F>>(&self, witness: &mut W, value: &PrivateState) {
        self.asset_tree_root
            .set_witness(witness, value.asset_tree_root);
        self.nullifier_tree_root
            .set_witness(witness, value.nullifier_tree_root);
        self.prev_private_commitment
            .set_witness(witness, value.prev_private_commitment);
        witness.set_target(self.nonce, F::from_canonical_u32(value.nonce));
        self.salt.set_witness(witness, value.salt);
    }
}
