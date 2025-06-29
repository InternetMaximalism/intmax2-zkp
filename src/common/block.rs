use plonky2::{
    field::{extension::Extendable, types::Field},
    hash::hash_types::RichField,
    iop::{target::Target, witness::WitnessWrite},
    plonk::{
        circuit_builder::CircuitBuilder,
        config::{AlgebraicHasher, GenericConfig},
    },
};
use plonky2_keccak::{builder::BuilderKeccak256, utils::solidity_keccak256};
use serde::{Deserialize, Serialize};

use crate::ethereum_types::{
    bytes32::{Bytes32, Bytes32Target},
    u32limb_trait::{U32LimbTargetTrait as _, U32LimbTrait},
    u64::{U64Target, U64},
};

use super::trees::deposit_tree::DepositTree;

/// A block of intmax2.
#[derive(Clone, Default, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Block {
    pub prev_block_hash: Bytes32,   // The hash of the previous block
    pub deposit_tree_root: Bytes32, // The root of the deposit tree
    pub signature_hash: Bytes32,    // The hash of the signature of the block
    pub timestamp: u64,             // The timestamp of the block
    pub block_number: u32,          // The number of the block
}

#[derive(Clone, Debug)]
pub struct BlockTarget {
    pub prev_block_hash: Bytes32Target,
    pub deposit_tree_root: Bytes32Target,
    pub signature_hash: Bytes32Target,
    pub timestamp: U64Target,
    pub block_number: Target,
}

impl Block {
    pub fn genesis() -> Self {
        let deposit_tree_root = DepositTree::initialize().get_root();
        Self {
            prev_block_hash: Bytes32::default(),
            deposit_tree_root,
            signature_hash: Bytes32::default(),
            timestamp: 0,
            block_number: 0,
        }
    }

    pub fn to_u32_vec(&self) -> Vec<u32> {
        [
            self.prev_block_hash.to_u32_vec(),
            self.deposit_tree_root.to_u32_vec(),
            self.signature_hash.to_u32_vec(),
            U64::from(self.timestamp).to_u32_vec(),
            vec![self.block_number],
        ]
        .concat()
    }

    pub fn hash(&self) -> Bytes32 {
        Bytes32::from_u32_slice(&solidity_keccak256(&self.to_u32_vec())).unwrap()
    }
}

impl BlockTarget {
    pub fn new<F: RichField + Extendable<D>, const D: usize>(
        builder: &mut CircuitBuilder<F, D>,
        is_checked: bool,
    ) -> Self {
        let block_number = builder.add_virtual_target();
        if is_checked {
            builder.range_check(block_number, 32);
        }
        Self {
            prev_block_hash: Bytes32Target::new(builder, is_checked),
            deposit_tree_root: Bytes32Target::new(builder, is_checked),
            signature_hash: Bytes32Target::new(builder, is_checked),
            timestamp: U64Target::new(builder, is_checked),
            block_number,
        }
    }

    pub fn to_vec(&self) -> Vec<Target> {
        self.prev_block_hash
            .to_vec()
            .into_iter()
            .chain(self.deposit_tree_root.to_vec())
            .chain(self.signature_hash.to_vec())
            .chain(self.timestamp.to_vec())
            .chain([self.block_number])
            .collect::<Vec<_>>()
    }

    pub fn hash<
        F: RichField + Extendable<D>,
        C: GenericConfig<D, F = F> + 'static,
        const D: usize,
    >(
        &self,
        builder: &mut CircuitBuilder<F, D>,
    ) -> Bytes32Target
    where
        <C as GenericConfig<D>>::Hasher: AlgebraicHasher<F>,
    {
        Bytes32Target::from_slice(&builder.keccak256::<C>(&self.to_vec()))
    }

    pub fn set_witness<W: WitnessWrite<F>, F: Field>(&self, witness: &mut W, value: &Block) {
        self.prev_block_hash
            .set_witness(witness, value.prev_block_hash);
        self.deposit_tree_root
            .set_witness(witness, value.deposit_tree_root);
        self.signature_hash
            .set_witness(witness, value.signature_hash);
        self.timestamp
            .set_witness(witness, U64::from(value.timestamp));
        witness.set_target(self.block_number, F::from_canonical_u32(value.block_number));
    }
}
