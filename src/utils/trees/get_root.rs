use plonky2::{
    field::extension::Extendable,
    hash::hash_types::RichField,
    plonk::{
        circuit_builder::CircuitBuilder,
        config::{AlgebraicHasher, GenericConfig},
    },
};

use crate::utils::{
    leafable::{Leafable, LeafableTarget},
    leafable_hasher::LeafableHasher,
    trees::merkle_tree::{Hasher, HasherFromTarget},
};

use super::{
    error::GetRootFromLeavesError,
    merkle_tree::{HashOut, HashOutTarget},
};

pub fn get_merkle_root_from_leaves<V: Leafable>(
    height: usize,
    leaves: &[V],
) -> Result<HashOut<V>, GetRootFromLeavesError> {
    if leaves.len() > 1 << height {
        return Err(GetRootFromLeavesError::TooManyLeaves(leaves.len()));
    }
    let mut leaves = leaves.to_vec();
    leaves.resize(1 << height, V::empty_leaf());
    get_merkle_root_from_full_leaves(height, &leaves)
}

pub fn get_merkle_root_from_leaves_circuit<
    F: RichField + Extendable<D>,
    C: GenericConfig<D, F = F> + 'static,
    const D: usize,
    VT: LeafableTarget,
>(
    builder: &mut CircuitBuilder<F, D>,
    height: usize,
    leaves: &[VT],
) -> HashOutTarget<VT>
where
    <C as GenericConfig<D>>::Hasher: AlgebraicHasher<F>,
{
    assert!(leaves.len() <= 1 << height, "too many leaves");
    let next_pow_two = leaves.len().next_power_of_two();
    let sub_tree_height = next_pow_two.trailing_zeros() as usize;

    // get sub tree root
    let mut sub_tree_leaves = leaves.to_vec();
    let empty_leaf = VT::empty_leaf(builder);
    sub_tree_leaves.resize(next_pow_two, empty_leaf);
    let sub_tree_root = get_merkle_root_from_full_leaves_circuit::<F, C, D, _>(
        builder,
        sub_tree_height,
        &sub_tree_leaves,
    );

    // calculate hashes
    let mut default_hash = VT::Leaf::empty_leaf().hash();
    for _ in 0..sub_tree_height {
        default_hash = HasherFromTarget::<VT>::two_to_one(default_hash, default_hash);
    }
    let mut root = sub_tree_root;
    for _ in sub_tree_height..height {
        let default_hash_t =
            HasherFromTarget::<VT>::constant_hash_out_target(builder, default_hash);
        root =
            HasherFromTarget::<VT>::two_to_one_target::<F, C, D>(builder, &root, &default_hash_t);
        default_hash = HasherFromTarget::<VT>::two_to_one(default_hash, default_hash);
    }
    root
}

/// Calculate the merkle root from the given leaf and the height of the merkle tree.
/// Returns an error if the number of leaves is not equal to 2^height.
fn get_merkle_root_from_full_leaves<V: Leafable>(
    height: usize,
    leaves: &[V],
) -> Result<HashOut<V>, GetRootFromLeavesError> {
    if leaves.len() != 1 << height {
        return Err(GetRootFromLeavesError::TooManyLeaves(leaves.len()));
    }

    let mut layer = leaves.iter().map(|v| v.hash()).collect::<Vec<_>>();
    if layer.is_empty() {
        return Err(GetRootFromLeavesError::TooManyLeaves(0));
    }

    while layer.len() > 1 {
        if layer.len() % 2 == 1 {
            return Err(GetRootFromLeavesError::NotPowerOfTwo(layer.len()));
        }
        layer = (0..(layer.len() / 2))
            .map(|i| Hasher::<V>::two_to_one(layer[2 * i], layer[2 * i + 1]))
            .collect::<Vec<_>>();
    }
    Ok(layer[0])
}

fn get_merkle_root_from_full_leaves_circuit<
    F: RichField + Extendable<D>,
    C: GenericConfig<D, F = F> + 'static,
    const D: usize,
    VT: LeafableTarget,
>(
    builder: &mut CircuitBuilder<F, D>,
    height: usize,
    leaves: &[VT],
) -> HashOutTarget<VT>
where
    <C as GenericConfig<D>>::Hasher: AlgebraicHasher<F>,
{
    // Note: For circuit building, we still use assertions since errors during circuit building
    // are generally unrecoverable and should be caught during development.
    assert_eq!(
        leaves.len(),
        1 << height,
        "Number of leaves must be 2^height"
    );

    let mut layer = leaves
        .iter()
        .map(|v| v.hash::<F, C, D>(builder))
        .collect::<Vec<_>>();

    assert_ne!(layer.len(), 0, "Layer cannot be empty");

    while layer.len() > 1 {
        assert!(
            layer.len() % 2 == 0,
            "Number of leaves must be a power of 2"
        );

        layer = (0..(layer.len() / 2))
            .map(|i| {
                HasherFromTarget::<VT>::two_to_one_target::<F, C, D>(
                    builder,
                    &layer[2 * i],
                    &layer[2 * i + 1],
                )
            })
            .collect::<Vec<_>>();
    }

    layer[0].clone()
}

#[cfg(test)]
mod tests {
    use plonky2::{
        iop::witness::PartialWitness,
        plonk::{
            circuit_builder::CircuitBuilder,
            circuit_data::CircuitConfig,
            config::{GenericConfig, PoseidonGoldilocksConfig},
        },
    };

    use crate::{
        ethereum_types::{
            bytes32::{Bytes32, Bytes32Target},
            u32limb_trait::{U32LimbTargetTrait, U32LimbTrait},
        },
        utils::{
            leafable::{Leafable, LeafableTarget},
            trees::{
                get_root::{
                    get_merkle_root_from_full_leaves, get_merkle_root_from_full_leaves_circuit,
                    get_merkle_root_from_leaves, get_merkle_root_from_leaves_circuit,
                },
                incremental_merkle_tree::IncrementalMerkleTree,
            },
        },
    };

    const D: usize = 2;
    type C = PoseidonGoldilocksConfig;
    type F = <C as GenericConfig<D>>::F;

    #[test]
    fn test_get_merkle_root_from_full_leaves() {
        let mut rng = rand::thread_rng();
        let height = 5;
        let num_leaves = 6;
        type V = Bytes32;
        let mut tree = IncrementalMerkleTree::<V>::new(height);
        let leaves = (0..num_leaves)
            .map(|_| V::rand(&mut rng))
            .collect::<Vec<_>>();
        for leaf in &leaves {
            tree.push(*leaf);
        }
        let root_expected = tree.get_root();
        let mut padded_leaves = leaves.clone();
        padded_leaves.resize(1 << height, V::empty_leaf());
        let root = get_merkle_root_from_full_leaves(height, &padded_leaves).unwrap();
        assert_eq!(root, root_expected);
    }

    #[test]
    fn test_get_merkle_root_target_from_full_leaves_circuit() {
        type V = Bytes32;
        type VT = Bytes32Target;

        let mut rng = rand::thread_rng();
        let height = 5;
        let leaves = (0..1 << height)
            .map(|_| V::rand(&mut rng))
            .collect::<Vec<_>>();
        let root = get_merkle_root_from_full_leaves(height, &leaves).unwrap();

        let mut builder = CircuitBuilder::<F, D>::new(CircuitConfig::default());
        let mut leaves_t = leaves
            .into_iter()
            .map(|leaf| VT::constant(&mut builder, leaf))
            .collect::<Vec<_>>();
        leaves_t.resize(1 << height, LeafableTarget::empty_leaf(&mut builder));

        let root_t =
            get_merkle_root_from_full_leaves_circuit::<F, C, D, _>(&mut builder, height, &leaves_t);
        let data = builder.build::<C>();

        let mut pw = PartialWitness::<F>::new();
        root_t.set_witness(&mut pw, root);
        data.prove(pw).unwrap();
    }

    #[test]
    fn test_get_merkle_root_target_from_leaves_circuit() {
        type V = Bytes32;
        type VT = Bytes32Target;

        let mut rng = rand::thread_rng();
        let height = 5;
        let num_leaves = 10;
        let leaves = (0..num_leaves)
            .map(|_| V::rand(&mut rng))
            .collect::<Vec<_>>();
        let root = get_merkle_root_from_leaves(height, &leaves).unwrap();

        let mut builder = CircuitBuilder::<F, D>::new(CircuitConfig::default());
        let leaves_t = leaves
            .into_iter()
            .map(|leaf| VT::constant(&mut builder, leaf))
            .collect::<Vec<_>>();
        let root_t =
            get_merkle_root_from_leaves_circuit::<F, C, D, _>(&mut builder, height, &leaves_t);
        let data = builder.build::<C>();

        let mut pw = PartialWitness::<F>::new();
        root_t.set_witness(&mut pw, root);
        data.prove(pw).unwrap();
    }
}
