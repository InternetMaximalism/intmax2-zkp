use crate::utils::{
    leafable_hasher::PoseidonLeafableHasher,
    trees::sparse_merkle_tree::{SparseMerkleProof, SparseMerkleProofTarget, SparseMerkleTree},
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

pub type AssetTree = SparseMerkleTree<AssetLeaf>;
pub type AssetMerkleProof = SparseMerkleProof<AssetLeaf>;
pub type AssetMerkleProofTarget = SparseMerkleProofTarget<AssetLeafTarget>;

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
    type LeafableHasher = PoseidonLeafableHasher;

    fn empty_leaf() -> Self {
        Self::default()
    }

    fn hash(&self) -> PoseidonHashOut {
        PoseidonHashOut::hash_inputs_u32(self.to_u32_vec().as_slice())
    }
}

impl LeafableTarget for AssetLeafTarget {
    type Leaf = AssetLeaf;

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
}
