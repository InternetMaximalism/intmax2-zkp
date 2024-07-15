use plonky2::{
    field::{extension::Extendable, types::Field},
    hash::hash_types::RichField,
    iop::{
        target::{BoolTarget, Target},
        witness::WitnessWrite,
    },
    plonk::circuit_builder::CircuitBuilder,
};

use crate::{
    constants::{BLOCK_HASH_TREE_HEIGHT, DEPOSIT_TREE_HEIGHT},
    ethereum_types::{
        bytes32::{Bytes32, BYTES32_LEN},
        u32limb_trait::{U32LimbTargetTrait as _, U32LimbTrait},
    },
    utils::poseidon_hash_out::{PoseidonHashOut, PoseidonHashOutTarget, POSEIDON_HASH_OUT_LEN},
};

use super::{
    block::Block,
    trees::{account_tree::AccountTree, block_hash_tree::BlockHashTree, deposit_tree::DepositTree},
};

pub const PUBLIC_STATE_LEN: usize = POSEIDON_HASH_OUT_LEN * 3 + BYTES32_LEN * 2 + 1;

// This structure is used in the public input of the validity proof and balance proof.
#[derive(Clone, Debug, PartialEq)]
pub struct PublicState {
    pub block_tree_root: PoseidonHashOut,
    pub prev_account_tree_root: PoseidonHashOut,
    pub account_tree_root: PoseidonHashOut,
    pub deposit_tree_root: Bytes32<u32>,
    pub block_hash: Bytes32<u32>,
    pub block_number: u32,
}

impl PublicState {
    pub fn genesis() -> Self {
        let mut block_tree = BlockHashTree::new(BLOCK_HASH_TREE_HEIGHT);
        block_tree.push(Block::genesis().hash());
        let account_tree = AccountTree::initialize();
        let deposit_tree_root = DepositTree::new(DEPOSIT_TREE_HEIGHT);
        let block_hash = Block::genesis().hash();
        let block_number = 0;
        Self {
            block_tree_root: block_tree.get_root(),
            prev_account_tree_root: PoseidonHashOut::default(),
            account_tree_root: account_tree.get_root(),
            deposit_tree_root: deposit_tree_root.get_root(),
            block_hash,
            block_number,
        }
    }

    pub fn to_u64_vec(&self) -> Vec<u64> {
        let vec = vec![
            self.block_tree_root.to_u64_vec(),
            self.prev_account_tree_root.to_u64_vec(),
            self.account_tree_root.to_u64_vec(),
            self.deposit_tree_root.to_u64_vec(),
            self.block_hash.to_u64_vec(),
            vec![self.block_number as u64],
        ]
        .concat();
        assert_eq!(vec.len(), PUBLIC_STATE_LEN);
        vec
    }

    pub fn from_u64_vec(input: &[u64]) -> Self {
        assert_eq!(input.len(), PUBLIC_STATE_LEN);
        let block_tree_root = PoseidonHashOut::from_u64_vec(&input[0..4]);
        let prev_account_tree_root = PoseidonHashOut::from_u64_vec(&input[4..8]);
        let account_tree_root = PoseidonHashOut::from_u64_vec(&input[8..12]);
        let deposit_tree_root = Bytes32::<u32>::from_u64_vec(&input[12..20]);
        let block_hash = Bytes32::<u32>::from_u64_vec(&input[20..28]);
        let block_number = input[28] as u32;
        Self {
            block_tree_root,
            prev_account_tree_root,
            account_tree_root,
            deposit_tree_root,
            block_hash,
            block_number,
        }
    }
}

#[derive(Clone, Debug)]
pub struct PublicStateTarget {
    pub block_tree_root: PoseidonHashOutTarget,
    pub prev_account_tree_root: PoseidonHashOutTarget,
    pub account_tree_root: PoseidonHashOutTarget,
    pub deposit_tree_root: Bytes32<Target>,
    pub block_hash: Bytes32<Target>,
    pub block_number: Target,
}

impl PublicStateTarget {
    pub fn new<F: RichField + Extendable<D>, const D: usize>(
        builder: &mut CircuitBuilder<F, D>,
        is_checked: bool,
    ) -> Self {
        Self {
            block_tree_root: PoseidonHashOutTarget::new(builder),
            prev_account_tree_root: PoseidonHashOutTarget::new(builder),
            account_tree_root: PoseidonHashOutTarget::new(builder),
            deposit_tree_root: Bytes32::<Target>::new(builder, is_checked),
            block_hash: Bytes32::<Target>::new(builder, is_checked),
            block_number: builder.add_virtual_target(),
        }
    }

    pub fn to_vec(&self) -> Vec<Target> {
        let vec = vec![
            self.block_tree_root.to_vec(),
            self.prev_account_tree_root.to_vec(),
            self.account_tree_root.to_vec(),
            self.deposit_tree_root.limbs(),
            self.block_hash.limbs(),
            vec![self.block_number],
        ]
        .concat();
        assert_eq!(vec.len(), PUBLIC_STATE_LEN);
        vec
    }

    pub fn from_vec(input: &[Target]) -> Self {
        assert_eq!(input.len(), PUBLIC_STATE_LEN);
        let block_tree_root = PoseidonHashOutTarget::from_vec(&input[0..4]);
        let prev_account_tree_root = PoseidonHashOutTarget::from_vec(&input[4..8]);
        let account_tree_root = PoseidonHashOutTarget::from_vec(&input[8..12]);
        let deposit_tree_root = Bytes32::<Target>::from_limbs(&input[12..20]);
        let block_hash = Bytes32::<Target>::from_limbs(&input[20..28]);
        let block_number = input[28];
        Self {
            block_tree_root,
            prev_account_tree_root,
            account_tree_root,
            deposit_tree_root,
            block_hash,
            block_number,
        }
    }

    pub fn constant<F: RichField + Extendable<D>, const D: usize>(
        builder: &mut CircuitBuilder<F, D>,
        value: &PublicState,
    ) -> Self {
        Self {
            block_tree_root: PoseidonHashOutTarget::constant(builder, value.block_tree_root),
            prev_account_tree_root: PoseidonHashOutTarget::constant(
                builder,
                value.prev_account_tree_root,
            ),
            account_tree_root: PoseidonHashOutTarget::constant(builder, value.account_tree_root),
            deposit_tree_root: Bytes32::constant(builder, value.deposit_tree_root),
            block_hash: Bytes32::constant(builder, value.block_hash),
            block_number: builder.constant(F::from_canonical_u32(value.block_number)),
        }
    }

    pub fn connect<F: RichField + Extendable<D>, const D: usize>(
        &self,
        builder: &mut CircuitBuilder<F, D>,
        other: &Self,
    ) {
        self.prev_account_tree_root
            .connect(builder, other.prev_account_tree_root);
        self.account_tree_root
            .connect(builder, other.account_tree_root);
        self.block_tree_root.connect(builder, other.block_tree_root);
        self.deposit_tree_root
            .connect(builder, other.deposit_tree_root);
        self.block_hash.connect(builder, other.block_hash);
        builder.connect(self.block_number, other.block_number);
    }

    pub fn conditional_assert_eq<F: RichField + Extendable<D>, const D: usize>(
        &self,
        builder: &mut CircuitBuilder<F, D>,
        other: &Self,
        condition: BoolTarget,
    ) {
        self.prev_account_tree_root.conditional_assert_eq(
            builder,
            other.prev_account_tree_root,
            condition,
        );
        self.account_tree_root
            .conditional_assert_eq(builder, other.account_tree_root, condition);
        self.block_tree_root
            .conditional_assert_eq(builder, other.block_tree_root, condition);
        self.deposit_tree_root
            .conditional_assert_eq(builder, other.deposit_tree_root, condition);
        self.block_hash
            .conditional_assert_eq(builder, other.block_hash, condition);
        builder.conditional_assert_eq(condition.target, self.block_number, other.block_number);
    }

    pub fn set_witness<F: Field, W: WitnessWrite<F>>(&self, witness: &mut W, value: &PublicState) {
        self.prev_account_tree_root
            .set_witness(witness, value.prev_account_tree_root);
        self.account_tree_root
            .set_witness(witness, value.account_tree_root);
        self.block_tree_root
            .set_witness(witness, value.block_tree_root);
        self.deposit_tree_root
            .set_witness(witness, value.deposit_tree_root);
        self.block_hash.set_witness(witness, value.block_hash);
        witness.set_target(self.block_number, F::from_canonical_u32(value.block_number));
    }
}
