use plonky2::{
    field::extension::Extendable,
    hash::hash_types::RichField,
    iop::{
        target::{BoolTarget, Target},
        witness::Witness,
    },
    plonk::circuit_builder::CircuitBuilder,
};

use crate::{
    common::{
        block::Block,
        trees::{account_tree::AccountTree, block_hash_tree::BlockHashTree},
    },
    constants::{ACCOUNT_TREE_HEIGHT, BLOCK_HASH_TREE_HEIGHT},
    ethereum_types::{
        bytes32::{Bytes32, BYTES32_LEN},
        u32limb_trait::{U32LimbTargetTrait as _, U32LimbTrait as _},
    },
    utils::poseidon_hash_out::{PoseidonHashOut, PoseidonHashOutTarget},
};

pub const VALIDITY_PUBLIC_INPUTS_LEN: usize = 3 * 4 + 2 * BYTES32_LEN + 3;

/// Public inputs for the validity circuit
/// - account_tree_root: The root of the account tree. The accounts update has been incorporated up
///   to the previous block.
/// - block_hash_tree_root: The root of the block hash tree that containts the hashes of the blocks
///   up to the previous block.
/// - block_hash: The hash of the current block.
/// - block_number: The number of the current block.
/// - tx_tree_root: The root of the transaction tree in the current block.
/// - sender_tree_root: The root of the sender tree of the current block.
/// - is_registoration_block: A flag indicating whether the current block is a registration block.
/// - is_valid_block: A flag indicating whether the current block is valid, and is not skipped.
#[derive(Debug, Clone)]
pub struct ValidityPublicInputs {
    pub account_tree_root: PoseidonHashOut,
    pub block_hash_tree_root: PoseidonHashOut,
    pub block_hash: Bytes32<u32>,
    pub block_number: u32,
    pub tx_tree_root: Bytes32<u32>,
    pub sender_tree_root: PoseidonHashOut,
    pub is_registoration_block: bool,
    pub is_valid_block: bool,
}

#[derive(Debug, Clone)]
pub struct ValidityPublicInputsTarget {
    pub account_tree_root: PoseidonHashOutTarget,
    pub block_hash_tree_root: PoseidonHashOutTarget,
    pub block_hash: Bytes32<Target>,
    pub tx_tree_root: Bytes32<Target>,
    pub sender_tree_root: PoseidonHashOutTarget,
    pub block_number: Target,
    pub is_registoration_block: BoolTarget,
    pub is_valid_block: BoolTarget,
}

impl ValidityPublicInputs {
    pub fn genesis() -> Self {
        let account_tree = AccountTree::new(ACCOUNT_TREE_HEIGHT);
        let block_hash = Block::genesis().hash();

        // We don't have to construct the tx tree and the sender tree, because they will be skipped.
        let tx_tree_root = Bytes32::<u32>::default();
        let sender_tree_root = PoseidonHashOut::default();

        let block_number = 0;
        let is_registoration_block = false;
        let is_valid_block = false;
        let block_hash_tree = BlockHashTree::new(BLOCK_HASH_TREE_HEIGHT);
        Self {
            account_tree_root: account_tree.0.get_root(),
            block_hash_tree_root: block_hash_tree.get_root(),
            block_hash,
            block_number,
            tx_tree_root,
            sender_tree_root,
            is_registoration_block,
            is_valid_block,
        }
    }

    pub fn to_u64_vec(&self) -> Vec<u64> {
        let vec = self
            .account_tree_root
            .elements
            .into_iter()
            .chain(self.block_hash_tree_root.elements.into_iter())
            .chain(self.block_hash.to_u64_vec())
            .chain(self.tx_tree_root.to_u64_vec())
            .chain(self.sender_tree_root.elements.into_iter())
            .chain(vec![
                self.block_number as u64,
                self.is_registoration_block as u64,
                self.is_valid_block as u64,
            ])
            .collect::<Vec<_>>();
        assert_eq!(vec.len(), VALIDITY_PUBLIC_INPUTS_LEN);
        vec
    }
}

impl ValidityPublicInputsTarget {
    pub fn to_vec(&self) -> Vec<Target> {
        let vec = self
            .account_tree_root
            .elements
            .into_iter()
            .chain(self.block_hash_tree_root.elements.into_iter())
            .chain(self.block_hash.to_vec())
            .chain(self.tx_tree_root.to_vec())
            .chain(self.sender_tree_root.elements.into_iter())
            .chain(vec![
                self.block_number,
                self.is_registoration_block.target,
                self.is_valid_block.target,
            ])
            .collect::<Vec<_>>();
        assert_eq!(vec.len(), VALIDITY_PUBLIC_INPUTS_LEN);
        vec
    }
}

impl ValidityPublicInputsTarget {
    pub fn new<F: RichField + Extendable<D>, const D: usize>(
        builder: &mut CircuitBuilder<F, D>,
        is_checked: bool,
    ) -> Self {
        let is_registoration_block = builder.add_virtual_bool_target_unsafe();
        let is_valid_block = builder.add_virtual_bool_target_unsafe();
        if is_checked {
            builder.assert_bool(is_registoration_block);
            builder.assert_bool(is_valid_block);
        }
        Self {
            account_tree_root: PoseidonHashOutTarget::new(builder),
            block_hash_tree_root: PoseidonHashOutTarget::new(builder),
            block_hash: Bytes32::new(builder, is_checked),
            tx_tree_root: Bytes32::new(builder, is_checked),
            sender_tree_root: PoseidonHashOutTarget::new(builder),
            block_number: builder.add_virtual_target(),
            is_registoration_block,
            is_valid_block,
        }
    }

    pub fn set_witness<F: RichField, W: Witness<F>>(
        &self,
        witness: &mut W,
        value: &ValidityPublicInputs,
    ) {
        self.account_tree_root
            .set_witness(witness, value.account_tree_root);
        self.block_hash_tree_root
            .set_witness(witness, value.block_hash_tree_root);
        self.block_hash.set_witness(witness, value.block_hash);
        self.tx_tree_root.set_witness(witness, value.tx_tree_root);
        self.sender_tree_root
            .set_witness(witness, value.sender_tree_root);
        witness.set_target(self.block_number, F::from_canonical_u32(value.block_number));
        witness.set_bool_target(self.is_registoration_block, value.is_registoration_block);
        witness.set_bool_target(self.is_valid_block, value.is_valid_block);
    }
}
