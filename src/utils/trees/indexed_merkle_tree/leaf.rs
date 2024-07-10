use crate::{
    ethereum_types::u32limb_trait::{U32LimbTargetTrait as _, U32LimbTrait as _},
    utils::{
        leafable::LeafableTarget,
        leafable_hasher::PoseidonLeafableHasher,
        poseidon_hash_out::{PoseidonHashOut, PoseidonHashOutTarget},
    },
};
use plonky2::{
    field::{extension::Extendable, types::Field},
    hash::hash_types::RichField,
    iop::{target::Target, witness::WitnessWrite},
    plonk::{
        circuit_builder::CircuitBuilder,
        config::{AlgebraicHasher, GenericConfig},
    },
};

use crate::{ethereum_types::u256::U256, utils::leafable::Leafable};

/// Leaf of the indexed Merkle Tree with U256 as key
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct IndexedMerkleLeaf {
    pub(crate) next_index: usize,
    pub(crate) key: U256<u32>,
    pub(crate) next_key: U256<u32>,
    pub(crate) value: u64, // last block number for accout tree or just zero for nullifier
}

impl IndexedMerkleLeaf {
    pub fn to_u64_vec(&self) -> Vec<u64> {
        let mut res = vec![];
        res.push(self.next_index as u64);
        res.extend_from_slice(&self.key.to_u64_vec());
        res.extend_from_slice(&self.next_key.to_u64_vec());
        res.push(self.value);
        res
    }
}

impl Leafable for IndexedMerkleLeaf {
    type LeafableHasher = PoseidonLeafableHasher;

    fn empty_leaf() -> Self {
        Self::default()
    }

    fn hash(&self) -> PoseidonHashOut {
        PoseidonHashOut::hash_inputs_u64(&self.to_u64_vec())
    }
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct IndexedMerkleLeafTarget {
    pub(crate) next_index: Target,
    pub(crate) key: U256<Target>,
    pub(crate) next_key: U256<Target>,
    pub(crate) value: Target, // last block number for accout tree or just zero for nullifier
}

impl IndexedMerkleLeafTarget {
    pub fn new<F: RichField + Extendable<D>, const D: usize>(
        builder: &mut CircuitBuilder<F, D>,
        is_checked: bool,
    ) -> Self {
        Self {
            next_index: builder.add_virtual_target(),
            key: U256::new(builder, is_checked),
            next_key: U256::new(builder, is_checked),
            value: builder.add_virtual_target(),
        }
    }

    pub fn to_vec(&self) -> Vec<Target> {
        let mut res = vec![];
        res.push(self.next_index);
        res.extend_from_slice(&self.key.limbs());
        res.extend_from_slice(&self.next_key.limbs());
        res.push(self.value);
        res
    }

    pub fn constant<F: RichField + Extendable<D>, const D: usize>(
        builder: &mut CircuitBuilder<F, D>,
        value: &IndexedMerkleLeaf,
    ) -> Self {
        let next_index = builder.constant(F::from_canonical_usize(value.next_index));
        let key = U256::constant(builder, value.key);
        let next_key = U256::constant(builder, value.next_key);
        let value = builder.constant(F::from_canonical_u64(value.value));
        Self {
            next_index,
            key,
            next_key,
            value,
        }
    }

    pub fn set_witness<F: Field, W: WitnessWrite<F>>(
        &self,
        witness: &mut W,
        value: &IndexedMerkleLeaf,
    ) {
        witness.set_target(self.next_index, F::from_canonical_usize(value.next_index));
        self.key.set_witness(witness, value.key);
        self.next_key.set_witness(witness, value.next_key);
        witness.set_target(self.value, F::from_canonical_u64(value.value));
    }
}

impl LeafableTarget for IndexedMerkleLeafTarget {
    type Leaf = IndexedMerkleLeaf;

    fn empty_leaf<F: RichField + Extendable<D>, const D: usize>(
        builder: &mut CircuitBuilder<F, D>,
    ) -> Self {
        let empty_leaf = <Self::Leaf as Leafable>::empty_leaf();
        Self::constant(builder, &empty_leaf)
    }

    fn hash<F: RichField + Extendable<D>, C: GenericConfig<D, F = F> + 'static, const D: usize>(
        &self,
        builder: &mut CircuitBuilder<F, D>,
    ) -> PoseidonHashOutTarget
    where
        <C as GenericConfig<D>>::Hasher: AlgebraicHasher<F>,
    {
        PoseidonHashOutTarget::hash_inputs(builder, &self.to_vec())
    }
}
