use plonky2::{
    field::{extension::Extendable, types::Field},
    hash::hash_types::RichField,
    iop::{target::Target, witness::WitnessWrite},
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
        leafable_hasher::KeccakLeafableHasher,
        poseidon_hash_out::{PoseidonHashOut, PoseidonHashOutTarget},
        trees::merkle_tree_with_leaves::{
            MerkleProofWithLeaves, MerkleProofWithLeavesTarget, MerkleTreeWithLeaves,
        },
    },
};
pub type DepositTree = MerkleTreeWithLeaves<DepositLeaf>;
pub type DepositMerkleProof = MerkleProofWithLeaves<DepositLeaf>;
pub type DepositMerkleProofTarget = MerkleProofWithLeavesTarget<DepositLeafTarget>;

#[derive(Debug, Clone, Default, PartialEq)]
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

    pub fn poseidon_hash(&self) -> PoseidonHashOut {
        PoseidonHashOut::hash_inputs_u32(&self.to_u32_vec())
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

    pub fn poseidon_hash<F: RichField + Extendable<D>, const D: usize>(
        &self,
        builder: &mut CircuitBuilder<F, D>,
    ) -> PoseidonHashOutTarget {
        PoseidonHashOutTarget::hash_inputs(builder, &self.to_vec())
    }

    pub fn set_witness<F: Field, W: WitnessWrite<F>>(&self, witness: &mut W, value: &DepositLeaf) {
        self.pubkey_salt_hash
            .set_witness(witness, value.pubkey_salt_hash);
        witness.set_target(self.token_index, F::from_canonical_u32(value.token_index));
        self.amount.set_witness(witness, value.amount);
    }
}

impl Leafable for DepositLeaf {
    type LeafableHasher = KeccakLeafableHasher;

    fn empty_leaf() -> Self {
        Self::default()
    }

    fn hash(&self) -> Bytes32<u32> {
        Bytes32::<u32>::from_limbs(&solidity_keccak256(&self.to_u32_vec()))
    }
}

impl LeafableTarget for DepositLeafTarget {
    type Leaf = DepositLeaf;

    fn empty_leaf<F: RichField + Extendable<D>, const D: usize>(
        builder: &mut CircuitBuilder<F, D>,
    ) -> Self {
        Self::constant(builder, &DepositLeaf::default())
    }

    fn hash<F: RichField + Extendable<D>, C: GenericConfig<D, F = F> + 'static, const D: usize>(
        &self,
        builder: &mut CircuitBuilder<F, D>,
    ) -> Bytes32<Target>
    where
        <C as GenericConfig<D>>::Hasher: AlgebraicHasher<F>,
    {
        let limbs = self.to_vec();
        Bytes32::<Target>::from_limbs(&builder.keccak256::<C>(&limbs))
    }
}
