use crate::{
    ethereum_types::u256::U256Target,
    utils::{
        leafable_hasher::PoseidonLeafableHasher,
        trees::sparse_merkle_tree::{SparseMerkleProof, SparseMerkleProofTarget, SparseMerkleTree},
    },
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
use serde::{Deserialize, Serialize};

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

/// Data stored in the leaf of the asset tree. The index of the leaf corresponds to the token
/// index. The amount represents the balance of the token. `is_insufficient` indicates whether
/// the balance was insufficient when paying. Once a balance shortage occurs, all payments for that
/// token become impossible.
#[derive(Clone, Debug, Default, Copy, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AssetLeaf {
    pub is_insufficient: bool,
    pub amount: U256,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AssetLeafTarget {
    pub is_insufficient: BoolTarget,
    pub amount: U256Target,
}

impl AssetLeaf {
    /// Substracts the given amount from the balance. If the balance is insufficient, the balance
    /// becomes zero and the `is_insufficient` flag is set to true.
    pub fn sub(&self, amount: U256) -> Self {
        let is_insufficient = (self.amount < amount) || self.is_insufficient;
        // If the balance is insufficient, substract the entire balance to prevent
        // underflow.
        let substract_amount = if is_insufficient { self.amount } else { amount };
        let amount = self.amount - substract_amount;
        Self {
            is_insufficient,
            amount,
        }
    }

    /// Adds the given amount to the balance. `is_insufficient` flag is not changed.
    pub fn add(&self, amount: U256) -> Self {
        Self {
            is_insufficient: self.is_insufficient,
            amount: self.amount + amount,
        }
    }

    pub fn to_u32_vec(&self) -> Vec<u32> {
        let vec = vec![self.is_insufficient as u32]
            .into_iter()
            .chain(self.amount.to_u32_vec().into_iter())
            .collect::<Vec<_>>();
        vec
    }

    pub fn rand<R: Rng>(rng: &mut R) -> Self {
        Self {
            is_insufficient: false,
            amount: U256::rand(rng),
        }
    }
}

impl AssetLeafTarget {
    pub fn new<F: RichField + Extendable<D>, const D: usize>(
        builder: &mut CircuitBuilder<F, D>,
        is_checked: bool,
    ) -> Self {
        let is_insufficient = builder.add_virtual_bool_target_unsafe();
        if is_checked {
            builder.assert_bool(is_insufficient);
        }
        Self {
            is_insufficient,
            amount: U256Target::new(builder, is_checked),
        }
    }

    pub fn sub<F: RichField + Extendable<D>, const D: usize>(
        &self,
        builder: &mut CircuitBuilder<F, D>,
        amount: U256Target,
    ) -> Self {
        let amount_cmp = self.amount.is_lt(builder, &amount);
        let is_insufficient = builder.or(amount_cmp, self.is_insufficient);
        // If the balance is insufficient, substract the entire balance to prevent
        // underflow.
        let substract_amount = U256Target::select(builder, is_insufficient, self.amount, amount);
        Self {
            is_insufficient,
            amount: self.amount.sub(builder, &substract_amount),
        }
    }

    pub fn add<F: RichField + Extendable<D>, const D: usize>(
        &self,
        builder: &mut CircuitBuilder<F, D>,
        amount: U256Target,
    ) -> Self {
        Self {
            is_insufficient: self.is_insufficient,
            amount: self.amount.add(builder, &amount),
        }
    }

    pub fn constant<F: RichField + Extendable<D>, const D: usize>(
        builder: &mut CircuitBuilder<F, D>,
        value: AssetLeaf,
    ) -> Self {
        Self {
            is_insufficient: builder.constant_bool(value.is_insufficient),
            amount: U256Target::constant(builder, value.amount),
        }
    }

    pub fn set_witness<F: Field, W: WitnessWrite<F>>(&self, witness: &mut W, value: AssetLeaf) {
        witness.set_bool_target(self.is_insufficient, value.is_insufficient);
        self.amount.set_witness(witness, value.amount);
    }

    pub fn to_vec(&self) -> Vec<Target> {
        let vec = vec![self.is_insufficient.target]
            .into_iter()
            .chain(self.amount.to_vec().into_iter())
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
