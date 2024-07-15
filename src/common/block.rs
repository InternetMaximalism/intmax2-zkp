use plonky2::{
    field::extension::Extendable,
    hash::hash_types::RichField,
    iop::{target::Target, witness::Witness},
    plonk::{
        circuit_builder::CircuitBuilder,
        config::{AlgebraicHasher, GenericConfig},
    },
};
use plonky2_keccak::{builder::BuilderKeccak256, utils::solidity_keccak256};
use serde::{Deserialize, Serialize};

use crate::{
    constants::DEPOSIT_TREE_HEIGHT,
    ethereum_types::{
        bytes32::Bytes32,
        u32limb_trait::{U32LimbTargetTrait as _, U32LimbTrait},
    },
    utils::poseidon_hash_out::{PoseidonHashOut, PoseidonHashOutTarget},
};

use super::trees::deposit_tree::DepositTree;

#[derive(Clone, Default, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Block {
    pub prev_block_hash: Bytes32<u32>,
    pub deposit_tree_root: Bytes32<u32>,
    pub signature_hash: Bytes32<u32>,
    pub block_number: u32,
}

#[derive(Clone, Debug)]
pub struct BlockTarget {
    pub prev_block_hash: Bytes32<Target>,
    pub deposit_tree_root: Bytes32<Target>,
    pub signature_hash: Bytes32<Target>,
    pub block_number: Target,
}

impl Block {
    pub fn genesis() -> Self {
        let deposit_tree_root = DepositTree::new(DEPOSIT_TREE_HEIGHT).get_root();
        Self {
            prev_block_hash: Bytes32::default(),
            deposit_tree_root,
            signature_hash: Bytes32::default(),
            block_number: 0,
        }
    }

    pub fn to_u32_vec(&self) -> Vec<u32> {
        vec![
            self.prev_block_hash.limbs(),
            self.deposit_tree_root.limbs(),
            self.signature_hash.limbs(),
            vec![self.block_number],
        ]
        .concat()
    }

    /// poseidon hash of the block
    pub fn commitment(&self) -> PoseidonHashOut {
        PoseidonHashOut::hash_inputs_u32(&self.to_u32_vec())
    }

    pub fn hash(&self) -> Bytes32<u32> {
        Bytes32::<u32>::from_limbs(&solidity_keccak256(&self.to_u32_vec()))
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
            prev_block_hash: Bytes32::new(builder, is_checked),
            deposit_tree_root: Bytes32::new(builder, is_checked),
            signature_hash: Bytes32::new(builder, is_checked),
            block_number,
        }
    }

    pub fn to_vec(&self) -> Vec<Target> {
        self.prev_block_hash
            .to_vec()
            .into_iter()
            .chain(self.deposit_tree_root.to_vec().into_iter())
            .chain(self.signature_hash.to_vec().into_iter())
            .chain([self.block_number].iter().copied())
            .collect::<Vec<_>>()
    }

    pub fn commitment<F: RichField + Extendable<D>, const D: usize>(
        &self,
        builder: &mut CircuitBuilder<F, D>,
    ) -> PoseidonHashOutTarget {
        PoseidonHashOutTarget::hash_inputs(builder, &self.to_vec())
    }

    pub fn hash<
        F: RichField + Extendable<D>,
        C: GenericConfig<D, F = F> + 'static,
        const D: usize,
    >(
        &self,
        builder: &mut CircuitBuilder<F, D>,
    ) -> Bytes32<Target>
    where
        <C as GenericConfig<D>>::Hasher: AlgebraicHasher<F>,
    {
        Bytes32::<Target>::from_limbs(&builder.keccak256::<C>(&self.to_vec()))
    }

    pub fn set_witness<F: RichField, W: Witness<F>>(&self, witness: &mut W, value: &Block) {
        self.prev_block_hash
            .set_witness(witness, value.prev_block_hash);
        self.deposit_tree_root
            .set_witness(witness, value.deposit_tree_root);
        self.signature_hash
            .set_witness(witness, value.signature_hash);
        witness.set_target(self.block_number, F::from_canonical_u32(value.block_number));
    }
}

#[cfg(test)]
mod tests {
    #[test]
    fn get_genesis_block_hash() {
        let block = super::Block::genesis();
        let hash = block.hash();
        assert_eq!(
            hash.to_string(),
            "913fb9e1f6f1c6d910fd574a5cad8857aa43bfba24e401ada4f56090d4d997a7",
        );
    }
}
