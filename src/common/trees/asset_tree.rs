use crate::utils::trees::merkle_tree_with_leaves::{
    MerkleProofWithLeaves, MerkleProofWithLeavesTarget, MerkleTreeWithLeaves,
};
use plonky2::{
    field::{extension::Extendable, types::Field},
    hash::hash_types::RichField,
    iop::{
        target::{BoolTarget, Target},
        witness::WitnessWrite,
    },
    plonk::{
        circuit_builder::CircuitBuilder,
        config::{AlgebraicHasher, GenericConfig},
    },
};
use rand::Rng;

use crate::{
    ethereum_types::{
        u256::U256,
        u32limb_trait::{U32LimbTargetTrait, U32LimbTrait as _},
    },
    utils::{
        leafable::{Leafable, LeafableTarget},
        poseidon_hash_out::{PoseidonHashOut, PoseidonHashOutTarget},
    },
};

pub type AssetTree = MerkleTreeWithLeaves<AssetLeaf>;
pub type AssetMerkleProof = MerkleProofWithLeaves<AssetLeaf>;
pub type AssetMerkleProofTarget = MerkleProofWithLeavesTarget<AssetLeafTarget>;

#[derive(Clone, Debug, Copy)]
pub struct AssetLeaf {
    pub is_sufficient: bool,
    pub amount: U256<u32>,
}

impl Default for AssetLeaf {
    fn default() -> Self {
        Self {
            is_sufficient: true,
            amount: Default::default(),
        }
    }
}

#[derive(Clone, Debug)]
pub struct AssetLeafTarget {
    pub is_sufficient: BoolTarget,
    pub amount: U256<Target>,
}

impl AssetLeaf {
    pub fn sub(&mut self, amount: U256<u32>) {
        let is_sufficient = (amount <= self.amount) && self.is_sufficient;
        let substract_amount = if is_sufficient { amount } else { self.amount };
        self.is_sufficient = is_sufficient;
        self.amount -= substract_amount;
    }

    pub fn to_u32_vec(&self) -> Vec<u32> {
        let vec = vec![self.is_sufficient as u32]
            .into_iter()
            .chain(self.amount.limbs().into_iter())
            .collect::<Vec<_>>();
        vec
    }

    pub fn rand<R: Rng>(rng: &mut R) -> Self {
        Self {
            is_sufficient: true,
            amount: U256::rand(rng),
        }
    }
}

impl AssetLeafTarget {
    pub fn new<F: RichField + Extendable<D>, const D: usize>(
        builder: &mut CircuitBuilder<F, D>,
        is_checked: bool,
    ) -> Self {
        let is_sufficient = builder.add_virtual_bool_target_unsafe();
        if is_checked {
            builder.assert_bool(is_sufficient);
        }
        Self {
            is_sufficient,
            amount: U256::new(builder, is_checked),
        }
    }

    pub fn sub<F: RichField + Extendable<D>, const D: usize>(
        &mut self,
        builder: &mut CircuitBuilder<F, D>,
        amount: U256<Target>,
    ) {
        let amount_cmp = amount.is_le(builder, &self.amount);
        let is_sufficient = builder.and(self.is_sufficient, amount_cmp);
        let substract_amount = U256::<Target>::select(builder, is_sufficient, amount, self.amount);
        self.is_sufficient = is_sufficient;
        self.amount = self.amount.sub(builder, &substract_amount);
    }

    pub fn constant<F: RichField + Extendable<D>, const D: usize>(
        builder: &mut CircuitBuilder<F, D>,
        value: AssetLeaf,
    ) -> Self {
        Self {
            is_sufficient: builder.constant_bool(value.is_sufficient),
            amount: U256::constant(builder, value.amount),
        }
    }

    pub fn set_witness<F: Field, W: WitnessWrite<F>>(&self, witness: &mut W, value: AssetLeaf) {
        witness.set_bool_target(self.is_sufficient, value.is_sufficient);
        self.amount.set_witness(witness, value.amount);
    }

    pub fn to_vec(&self) -> Vec<Target> {
        let vec = vec![self.is_sufficient.target]
            .into_iter()
            .chain(self.amount.limbs().into_iter())
            .collect::<Vec<_>>();
        vec
    }
}

impl Leafable for AssetLeaf {
    type HashOut = PoseidonHashOut;

    fn empty_leaf() -> Self {
        Self::default()
    }

    fn hash(&self) -> Self::HashOut {
        PoseidonHashOut::hash_inputs_u32(self.to_u32_vec().as_slice())
    }

    fn two_to_one(left: Self::HashOut, right: Self::HashOut) -> Self::HashOut {
        let inputs = left
            .to_u64_vec()
            .into_iter()
            .chain(right.to_u64_vec().into_iter())
            .collect::<Vec<_>>();
        PoseidonHashOut::hash_inputs_u64(inputs.as_slice())
    }
}

impl LeafableTarget for AssetLeafTarget {
    type Leaf = AssetLeaf;
    type HashOutTarget = PoseidonHashOutTarget;

    fn hash_out_target<F: RichField + Extendable<D>, const D: usize>(
        builder: &mut CircuitBuilder<F, D>,
    ) -> Self::HashOutTarget {
        PoseidonHashOutTarget::new(builder)
    }

    fn constant_hash_out_target<F: RichField + Extendable<D>, const D: usize>(
        builder: &mut CircuitBuilder<F, D>,
        value: PoseidonHashOut,
    ) -> Self::HashOutTarget {
        PoseidonHashOutTarget::constant(builder, value)
    }

    fn set_hash_out_target<W: WitnessWrite<F>, F: Field>(
        target: &Self::HashOutTarget,
        witness: &mut W,
        value: PoseidonHashOut,
    ) {
        target.set_witness(witness, value)
    }

    fn empty_leaf<F: RichField + Extendable<D>, const D: usize>(
        builder: &mut CircuitBuilder<F, D>,
    ) -> Self {
        let empty_leaf = <AssetLeaf as Leafable>::empty_leaf();
        AssetLeafTarget::constant(builder, empty_leaf)
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

    fn connect_hash<F: RichField + Extendable<D>, const D: usize>(
        builder: &mut CircuitBuilder<F, D>,
        x: &Self::HashOutTarget,
        y: &Self::HashOutTarget,
    ) {
        x.connect(builder, *y)
    }

    fn two_to_one<
        F: RichField + Extendable<D>,
        C: GenericConfig<D, F = F> + 'static,
        const D: usize,
    >(
        builder: &mut CircuitBuilder<F, D>,
        left: &Self::HashOutTarget,
        right: &Self::HashOutTarget,
    ) -> PoseidonHashOutTarget
    where
        <C as GenericConfig<D>>::Hasher: AlgebraicHasher<F>,
    {
        PoseidonHashOutTarget::two_to_one(builder, *left, *right)
    }

    fn two_to_one_swapped<
        F: RichField + Extendable<D>,
        C: GenericConfig<D, F = F> + 'static,
        const D: usize,
    >(
        builder: &mut CircuitBuilder<F, D>,
        left: &Self::HashOutTarget,
        right: &Self::HashOutTarget,
        swap: BoolTarget,
    ) -> Self::HashOutTarget
    where
        <C as GenericConfig<D>>::Hasher: AlgebraicHasher<F>,
    {
        PoseidonHashOutTarget::two_to_one_swapped(builder, *left, *right, swap)
    }
}
