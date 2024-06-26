use crate::{
    constants::{NUM_SENDERS_IN_BLOCK, SENDER_TREE_HEIGHT},
    ethereum_types::u128::U128,
    utils::{
        poseidon_hash_out::{PoseidonHashOut, PoseidonHashOutTarget},
        trees::{
            get_root::{get_merkle_root_from_leaves, get_merkle_root_from_leaves_circuit},
            merkle_tree_with_leaves::{MerkleProofWithLeaves, MerkleTreeWithLeaves},
        },
    },
};
use plonky2::{
    field::{extension::Extendable, types::Field},
    hash::hash_types::RichField,
    iop::{
        target::{BoolTarget, Target},
        witness::{Witness, WitnessWrite},
    },
    plonk::{
        circuit_builder::CircuitBuilder,
        config::{AlgebraicHasher, GenericConfig},
    },
};

use crate::{
    ethereum_types::{
        u256::{U256, U256_LEN},
        u32limb_trait::{U32LimbTargetTrait as _, U32LimbTrait as _},
    },
    utils::leafable::{Leafable, LeafableTarget},
};

pub type SenderTree = MerkleTreeWithLeaves<SenderLeaf>;
pub type SenderMerkleProof = MerkleProofWithLeaves<SenderLeaf>;

pub const SENDER_LEAF_LEN: usize = U256_LEN + 1;

#[derive(Default, Clone)]
pub struct SenderLeaf {
    pub sender: U256<u32>,
    pub is_valid: bool,
}

#[derive(Default, Clone)]
pub struct SenderLeafTarget {
    pub sender: U256<Target>,
    pub is_valid: BoolTarget,
}

impl SenderLeaf {
    pub fn to_u32_vec(&self) -> Vec<u32> {
        let vec = self
            .sender
            .limbs()
            .into_iter()
            .chain([self.is_valid as u32].iter().cloned())
            .collect::<Vec<_>>();
        assert_eq!(vec.len(), SENDER_LEAF_LEN);
        vec
    }
}

impl Leafable for SenderLeaf {
    type HashOut = PoseidonHashOut;

    fn empty_leaf() -> Self {
        Self::default()
    }

    fn hash(&self) -> Self::HashOut {
        PoseidonHashOut::hash_inputs_u32(&self.to_u32_vec())
    }

    fn two_to_one(left: Self::HashOut, right: Self::HashOut) -> Self::HashOut {
        let inputs = left
            .to_u64_vec()
            .into_iter()
            .chain(right.to_u64_vec().into_iter())
            .collect::<Vec<_>>();
        PoseidonHashOut::hash_inputs_u64(&inputs)
    }
}

impl SenderLeafTarget {
    pub fn new<F: RichField + Extendable<D>, const D: usize>(
        builder: &mut CircuitBuilder<F, D>,
        is_checked: bool,
    ) -> Self {
        let is_valid = builder.add_virtual_bool_target_unsafe();
        if is_checked {
            builder.assert_bool(is_valid);
        }
        Self {
            sender: U256::<Target>::new(builder, is_checked),
            is_valid,
        }
    }

    pub fn to_vec(&self) -> Vec<Target> {
        let vec = self
            .sender
            .to_vec()
            .into_iter()
            .chain([self.is_valid.target])
            .collect::<Vec<_>>();
        assert_eq!(vec.len(), SENDER_LEAF_LEN);
        vec
    }

    pub fn constant<F: RichField + Extendable<D>, const D: usize>(
        builder: &mut CircuitBuilder<F, D>,
        value: &SenderLeaf,
    ) -> Self {
        Self {
            sender: U256::constant(builder, value.sender),
            is_valid: builder.constant_bool(value.is_valid),
        }
    }

    pub fn set_witness<F: RichField, W: Witness<F>>(&self, witness: &mut W, value: &SenderLeaf) {
        self.sender.set_witness(witness, value.sender);
        witness.set_bool_target(self.is_valid, value.is_valid);
    }
}

impl LeafableTarget for SenderLeafTarget {
    type Leaf = SenderLeaf;
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

pub fn get_sender_leaves(pubkeys: &[U256<u32>], sender_flag: U128<u32>) -> Vec<SenderLeaf> {
    assert_eq!(pubkeys.len(), NUM_SENDERS_IN_BLOCK);
    let sender_bits = sender_flag.to_bits_le();
    let leaves = pubkeys
        .iter()
        .zip(sender_bits.iter())
        .map(|(&sender, &is_valid)| SenderLeaf { sender, is_valid })
        .collect::<Vec<_>>();
    leaves
}
pub fn get_sender_leaves_circuit<F: RichField + Extendable<D>, const D: usize>(
    builder: &mut CircuitBuilder<F, D>,
    pubkeys: &[U256<Target>],
    sender_flag: U128<Target>,
) -> Vec<SenderLeafTarget> {
    assert_eq!(pubkeys.len(), NUM_SENDERS_IN_BLOCK);
    let sender_bits = sender_flag.to_bits_le(builder);
    let leaves = pubkeys
        .iter()
        .zip(sender_bits.iter())
        .map(|(&sender, &is_valid)| SenderLeafTarget { sender, is_valid })
        .collect::<Vec<_>>();
    leaves
}

pub fn get_sender_tree_root(pubkeys: &[U256<u32>], sender_flag: U128<u32>) -> PoseidonHashOut {
    get_merkle_root_from_leaves(SENDER_TREE_HEIGHT, &get_sender_leaves(pubkeys, sender_flag))
}

pub fn get_sender_tree_root_circuit<
    F: RichField + Extendable<D>,
    C: GenericConfig<D, F = F> + 'static,
    const D: usize,
>(
    builder: &mut CircuitBuilder<F, D>,
    pubkeys: &[U256<Target>],
    sender_flag: U128<Target>,
) -> PoseidonHashOutTarget
where
    <C as GenericConfig<D>>::Hasher: AlgebraicHasher<F>,
{
    let leaves = get_sender_leaves_circuit(builder, pubkeys, sender_flag);
    get_merkle_root_from_leaves_circuit::<F, C, D, _>(builder, SENDER_TREE_HEIGHT, &leaves)
}
