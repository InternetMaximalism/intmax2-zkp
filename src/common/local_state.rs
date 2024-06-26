use plonky2::{
    field::{extension::Extendable, types::Field},
    hash::hash_types::RichField,
    iop::{target::Target, witness::WitnessWrite},
    plonk::circuit_builder::CircuitBuilder,
};

use crate::utils::poseidon_hash_out::{PoseidonHashOut, PoseidonHashOutTarget};

use super::salt::{Salt, SaltTarget};

#[derive(Clone, Debug, Default)]
pub struct PrivateState {
    pub asset_tree_root: PoseidonHashOut,
    pub nullifier_tree_root: PoseidonHashOut,
    pub last_tx_hash: PoseidonHashOut,
    pub nullifier_synced_block_number: u32,
    pub nonce: u32,
    pub salt: Salt,
}

#[derive(Clone, Debug)]
pub struct PrivateStateTarget {
    pub asset_tree_root: PoseidonHashOutTarget,
    pub nullifier_tree_root: PoseidonHashOutTarget,
    pub last_tx_hash: PoseidonHashOutTarget,
    pub nullifier_synced_block_number: Target,
    pub nonce: Target,
    pub salt: SaltTarget,
}

impl PrivateState {
    pub fn to_u64_vec(&self) -> Vec<u64> {
        let vec = vec![
            self.asset_tree_root.to_u64_vec(),
            self.nullifier_tree_root.to_u64_vec(),
            self.last_tx_hash.to_u64_vec(),
            vec![self.nullifier_synced_block_number as u64],
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
            self.last_tx_hash.to_vec(),
            vec![self.nullifier_synced_block_number],
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
            last_tx_hash: PoseidonHashOutTarget::new(builder),
            nullifier_synced_block_number: builder.add_virtual_target(),
            nonce: builder.add_virtual_target(),
            salt: SaltTarget::new(builder),
        }
    }

    pub fn set_witness<F: Field, W: WitnessWrite<F>>(&self, witness: &mut W, value: &PrivateState) {
        self.asset_tree_root
            .set_witness(witness, value.asset_tree_root);
        self.nullifier_tree_root
            .set_witness(witness, value.nullifier_tree_root);
        self.last_tx_hash.set_witness(witness, value.last_tx_hash);
        witness.set_target(
            self.nullifier_synced_block_number,
            F::from_canonical_u32(value.nullifier_synced_block_number),
        );
        witness.set_target(self.nonce, F::from_canonical_u32(value.nonce));
        self.salt.set_witness(witness, value.salt);
    }
}
