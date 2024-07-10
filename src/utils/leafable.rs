use crate::ethereum_types::{
    bytes32::Bytes32,
    u256::U256,
    u32limb_trait::{U32LimbTargetTrait as _, U32LimbTrait},
};
use plonky2::{
    self,
    field::extension::Extendable,
    hash::hash_types::RichField,
    iop::target::Target,
    plonk::{
        circuit_builder::CircuitBuilder,
        config::{AlgebraicHasher, GenericConfig},
    },
};

use super::{
    leafable_hasher::{LeafableHasher, PoseidonLeafableHasher},
    poseidon_hash_out::{PoseidonHashOut, PoseidonHashOutTarget},
};
use core::fmt::Debug;

/// Can be a leaf of Merkle trees.
pub trait Leafable: Clone + Debug {
    type LeafableHasher: LeafableHasher;

    /// Default hash which indicates empty value.
    fn empty_leaf() -> Self;

    /// Hash of its value.
    fn hash(&self) -> <Self::LeafableHasher as LeafableHasher>::HashOut;
}

pub trait LeafableTarget: Clone + Debug {
    type Leaf: Leafable;

    fn empty_leaf<F: RichField + Extendable<D>, const D: usize>(
        builder: &mut CircuitBuilder<F, D>,
    ) -> Self;

    /// Hash target of its value.
    // Generic `C` is used for keccak256
    fn hash<F: RichField + Extendable<D>, C: GenericConfig<D, F = F> + 'static, const D: usize>(
        &self,
        builder: &mut CircuitBuilder<F, D>,
    ) -> <<Self::Leaf as Leafable>::LeafableHasher as LeafableHasher>::HashOutTarget
    where
        <C as GenericConfig<D>>::Hasher: AlgebraicHasher<F>;
}
/*
 * Leafable for PoseidonHashOut
 */
impl Leafable for PoseidonHashOut {
    type LeafableHasher = PoseidonLeafableHasher;

    fn empty_leaf() -> Self {
        Self::default()
    }

    // Output as is in the case of a hash.
    fn hash(&self) -> Self {
        *self
    }
}

impl LeafableTarget for PoseidonHashOutTarget {
    type Leaf = PoseidonHashOut;

    fn empty_leaf<F: RichField + Extendable<D>, const D: usize>(
        builder: &mut CircuitBuilder<F, D>,
    ) -> Self {
        PoseidonHashOutTarget::constant(builder, PoseidonHashOut::default())
    }

    fn hash<F: RichField + Extendable<D>, C: GenericConfig<D, F = F> + 'static, const D: usize>(
        &self,
        _builder: &mut CircuitBuilder<F, D>,
    ) -> PoseidonHashOutTarget
    where
        <C as GenericConfig<D>>::Hasher: AlgebraicHasher<F>,
    {
        *self
    }
}

/*
 * Leafable for Bytes32<u32>
 */
impl Leafable for Bytes32<u32> {
    type LeafableHasher = PoseidonLeafableHasher;

    fn empty_leaf() -> Self {
        Self::default()
    }

    // Output as is in the case of a hash.
    fn hash(&self) -> PoseidonHashOut {
        PoseidonHashOut::hash_inputs_u32(&self.limbs())
    }
}

impl LeafableTarget for Bytes32<Target> {
    type Leaf = Bytes32<u32>;

    fn empty_leaf<F: RichField + Extendable<D>, const D: usize>(
        builder: &mut CircuitBuilder<F, D>,
    ) -> Self {
        Bytes32::<Target>::constant(builder, Bytes32::default())
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
/*
 * Leafable for U256<u32>
 */
impl Leafable for U256<u32> {
    type LeafableHasher = PoseidonLeafableHasher;

    fn empty_leaf() -> Self {
        Self::default()
    }

    // Output as is in the case of a hash.
    fn hash(&self) -> PoseidonHashOut {
        PoseidonHashOut::hash_inputs_u32(&self.limbs())
    }
}

impl LeafableTarget for U256<Target> {
    type Leaf = U256<u32>;

    fn empty_leaf<F: RichField + Extendable<D>, const D: usize>(
        builder: &mut CircuitBuilder<F, D>,
    ) -> Self {
        U256::<Target>::constant(builder, Bytes32::default())
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
