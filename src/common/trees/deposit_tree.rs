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
use plonky2_keccak::{builder::BuilderKeccak256 as _, utils::solidity_keccak256};
use rand::Rng;

use crate::{
    ethereum_types::{
        bytes32::Bytes32,
        u256::U256,
        u32limb_trait::{U32LimbTargetTrait as _, U32LimbTrait},
    },
    utils::{
        leafable::{Leafable, LeafableTarget},
        trees::merkle_tree_with_leaves::{
            MerkleProofWithLeaves, MerkleProofWithLeavesTarget, MerkleTreeWithLeaves,
        },
    },
};
pub type DepositTree = MerkleTreeWithLeaves<DepositLeaf>;
pub type DepositMerkleProof = MerkleProofWithLeaves<DepositLeaf>;
pub type DepositMerkleProofTarget = MerkleProofWithLeavesTarget<DepositLeafTarget>;

#[derive(Debug, Clone, Default)]
pub struct DepositLeaf {
    pub pubkey_salt_hash: Bytes32<u32>,
    pub token_index: u32,
    pub amount: U256<u32>,
}

#[derive(Debug, Clone, Default)]
pub struct DepositLeafTarget {
    pub pubkey_salt_hash: Bytes32<Target>,
    pub token_index: Target,
    pub amount: U256<Target>,
}

impl DepositLeaf {
    pub fn to_u32_vec(&self) -> Vec<u32> {
        let vec = vec![
            self.pubkey_salt_hash.limbs(),
            vec![self.token_index],
            self.amount.limbs(),
        ]
        .concat();
        vec
    }

    pub fn rand<R: Rng>(rng: &mut R) -> Self {
        Self {
            pubkey_salt_hash: Bytes32::rand(rng),
            token_index: rng.gen(),
            amount: U256::rand(rng),
        }
    }
}

impl DepositLeafTarget {
    pub fn to_vec(&self) -> Vec<Target> {
        let vec = vec![
            self.pubkey_salt_hash.limbs(),
            vec![self.token_index],
            self.amount.limbs(),
        ]
        .concat();
        vec
    }

    pub fn new<F: RichField + Extendable<D>, const D: usize>(
        builder: &mut CircuitBuilder<F, D>,
        is_checked: bool,
    ) -> Self {
        let pubkey_salt_hash = Bytes32::new(builder, is_checked);
        let token_index = builder.add_virtual_target();
        let amount = U256::new(builder, is_checked);
        Self {
            pubkey_salt_hash,
            token_index,
            amount,
        }
    }

    pub fn constant<F: RichField + Extendable<D>, const D: usize>(
        builder: &mut CircuitBuilder<F, D>,
        value: &DepositLeaf,
    ) -> Self {
        let pubkey_salt_hash = Bytes32::constant(builder, value.pubkey_salt_hash);
        let token_index = builder.constant(F::from_canonical_u32(value.token_index));
        let amount = U256::constant(builder, value.amount);
        Self {
            pubkey_salt_hash,
            token_index,
            amount,
        }
    }

    pub fn set_witness<F: Field, W: WitnessWrite<F>>(&self, witness: &mut W, value: &DepositLeaf) {
        self.pubkey_salt_hash
            .set_witness(witness, value.pubkey_salt_hash);
        witness.set_target(self.token_index, F::from_canonical_u32(value.token_index));
        self.amount.set_witness(witness, value.amount);
    }
}

impl Leafable for DepositLeaf {
    type HashOut = Bytes32<u32>;

    fn empty_leaf() -> Self {
        Self::default()
    }

    fn hash(&self) -> Self::HashOut {
        Bytes32::<u32>::from_limbs(&solidity_keccak256(&self.to_u32_vec()))
    }

    fn two_to_one(left: Self::HashOut, right: Self::HashOut) -> Self::HashOut {
        let inputs = vec![left.limbs(), right.limbs()].concat();
        Bytes32::<u32>::from_limbs(&solidity_keccak256(&inputs))
    }
}

impl LeafableTarget for DepositLeafTarget {
    type Leaf = DepositLeaf;
    type HashOutTarget = Bytes32<Target>;

    fn empty_leaf<F: RichField + Extendable<D>, const D: usize>(
        builder: &mut CircuitBuilder<F, D>,
    ) -> Self {
        Self::constant(builder, &DepositLeaf::default())
    }

    fn hash<F: RichField + Extendable<D>, C: GenericConfig<D, F = F> + 'static, const D: usize>(
        &self,
        builder: &mut CircuitBuilder<F, D>,
    ) -> Self::HashOutTarget
    where
        <C as GenericConfig<D>>::Hasher: AlgebraicHasher<F>,
    {
        let limbs = self.to_vec();
        Bytes32::<Target>::from_limbs(&builder.keccak256::<C>(&limbs))
    }

    fn connect_hash<F: RichField + Extendable<D>, const D: usize>(
        builder: &mut plonky2::plonk::circuit_builder::CircuitBuilder<F, D>,
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
    ) -> Self::HashOutTarget
    where
        <C as GenericConfig<D>>::Hasher: AlgebraicHasher<F>,
    {
        let input = vec![left.limbs(), right.limbs()].concat();
        Bytes32::<Target>::from_limbs(&builder.keccak256::<C>(&input))
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
        let left_swapped = Bytes32::<Target>::select(builder, swap, *right, *left);
        let right_swapped = Bytes32::<Target>::select(builder, swap, *left, *right);
        Self::two_to_one::<F, C, D>(builder, &left_swapped, &right_swapped)
    }

    fn hash_out_target<F: RichField + Extendable<D>, const D: usize>(
        builder: &mut CircuitBuilder<F, D>,
    ) -> Self::HashOutTarget {
        Bytes32::<Target>::new(builder, false)
    }

    fn constant_hash_out_target<F: RichField + Extendable<D>, const D: usize>(
        builder: &mut CircuitBuilder<F, D>,
        value: <Self::Leaf as Leafable>::HashOut,
    ) -> Self::HashOutTarget {
        Bytes32::<Target>::constant(builder, value)
    }

    fn set_hash_out_target<
        W: plonky2::iop::witness::WitnessWrite<F>,
        F: plonky2::field::types::Field,
    >(
        target: &Self::HashOutTarget,
        witness: &mut W,
        value: <Self::Leaf as Leafable>::HashOut,
    ) {
        target.set_witness(witness, value)
    }
}
