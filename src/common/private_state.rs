use plonky2::{
    field::{extension::Extendable, types::Field},
    hash::hash_types::RichField,
    iop::{target::Target, witness::WitnessWrite},
    plonk::circuit_builder::CircuitBuilder,
};

use crate::{
    constants::ASSET_TREE_HEIGHT,
    utils::poseidon_hash_out::{PoseidonHashOut, PoseidonHashOutTarget},
};

use super::{
    salt::{Salt, SaltTarget},
    trees::{asset_tree::AssetTree, nullifier_tree::NullifierTree},
};

#[derive(Clone, Debug, PartialEq)]
pub struct PrivateState {
    pub asset_tree_root: PoseidonHashOut,
    pub nullifier_tree_root: PoseidonHashOut,
    pub nonce: u32,
    pub salt: Salt,
}

#[derive(Clone, Debug)]
pub struct PrivateStateTarget {
    pub asset_tree_root: PoseidonHashOutTarget,
    pub nullifier_tree_root: PoseidonHashOutTarget,
    pub nonce: Target,
    pub salt: SaltTarget,
}

impl PrivateState {
    pub fn new() -> Self {
        let asset_tree_root = AssetTree::new(ASSET_TREE_HEIGHT).get_root();
        let nullifier_tree_root = NullifierTree::new().get_root();
        Self {
            asset_tree_root,
            nullifier_tree_root,
            nonce: 0,
            salt: Salt::default(),
        }
    }

    pub fn to_u64_vec(&self) -> Vec<u64> {
        let vec = vec![
            self.asset_tree_root.to_u64_vec(),
            self.nullifier_tree_root.to_u64_vec(),
            vec![self.nonce as u64],
            self.salt.to_u64_vec(),
        ]
        .concat();
        vec
    }

    pub fn commitment(&self) -> PoseidonHashOut {
        PoseidonHashOut::hash_inputs_u64(&self.to_u64_vec())
    }
}

impl PrivateStateTarget {
    pub fn to_vec(&self) -> Vec<Target> {
        let vec = vec![
            self.asset_tree_root.to_vec(),
            self.nullifier_tree_root.to_vec(),
            vec![self.nonce],
            self.salt.to_vec(),
        ]
        .concat();
        vec
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
            nonce: builder.add_virtual_target(),
            salt: SaltTarget::new(builder),
        }
    }

    pub fn set_witness<F: Field, W: WitnessWrite<F>>(&self, witness: &mut W, value: &PrivateState) {
        self.asset_tree_root
            .set_witness(witness, value.asset_tree_root);
        self.nullifier_tree_root
            .set_witness(witness, value.nullifier_tree_root);
        witness.set_target(self.nonce, F::from_canonical_u32(value.nonce));
        self.salt.set_witness(witness, value.salt);
    }
}
