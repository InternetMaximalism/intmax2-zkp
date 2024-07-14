use plonky2::{
    field::{extension::Extendable, types::Field},
    hash::hash_types::RichField,
    iop::{target::Target, witness::WitnessWrite},
    plonk::{
        circuit_builder::CircuitBuilder,
        config::{AlgebraicHasher, GenericConfig},
    },
};

use crate::{
    common::{
        private_state::{PrivateState, PrivateStateTarget},
        salt::{Salt, SaltTarget},
        trees::{
            asset_tree::{AssetLeaf, AssetLeafTarget, AssetMerkleProof, AssetMerkleProofTarget},
            nullifier_tree::{NullifierInsersionProof, NullifierInsersionProofTarget},
        },
    },
    constants::ASSET_TREE_HEIGHT,
    ethereum_types::{bytes32::Bytes32, u256::U256, u32limb_trait::U32LimbTargetTrait as _},
};

// update private state assuming that the transfer is valid
#[derive(Debug, Clone)]
pub struct PrivateStateTransitionValue {
    pub token_index: u32,
    pub amount: U256<u32>,
    pub nullifier: Bytes32<u32>,
    pub new_salt: Salt,
    pub prev_private_state: PrivateState,
    pub nullifier_proof: NullifierInsersionProof,
    pub prev_asset_leaf: AssetLeaf,
    pub asset_merkle_proof: AssetMerkleProof,
    pub new_private_state: PrivateState,
}

impl PrivateStateTransitionValue {
    pub fn new(
        token_index: u32,
        amount: U256<u32>,
        nullifier: Bytes32<u32>,
        new_salt: Salt,
        prev_private_state: &PrivateState,
        nullifier_proof: &NullifierInsersionProof,
        prev_asset_leaf: &AssetLeaf,
        asset_merkle_proof: &AssetMerkleProof,
    ) -> Self {
        let new_nullifier_tree_root = nullifier_proof
            .get_new_root(prev_private_state.nullifier_tree_root, nullifier)
            .expect("Invalid nullifier proof");
        asset_merkle_proof
            .verify(
                &prev_asset_leaf,
                token_index as usize,
                prev_private_state.asset_tree_root,
            )
            .expect("Invalid asset merkle proof");
        let new_asset_leaf = prev_asset_leaf.add(amount);
        let new_asset_tree_root =
            asset_merkle_proof.get_root(&new_asset_leaf, token_index as usize);
        let new_private_state = PrivateState {
            asset_tree_root: new_asset_tree_root,
            nullifier_tree_root: new_nullifier_tree_root,
            salt: new_salt,
            ..prev_private_state.clone()
        };
        Self {
            token_index,
            amount,
            nullifier,
            new_salt,
            prev_private_state: prev_private_state.clone(),
            nullifier_proof: nullifier_proof.clone(),
            prev_asset_leaf: prev_asset_leaf.clone(),
            asset_merkle_proof: asset_merkle_proof.clone(),
            new_private_state,
        }
    }
}

#[derive(Debug, Clone)]
pub struct PrivateStateTransitionTarget {
    pub token_index: Target,
    pub amount: U256<Target>,
    pub nullifier: Bytes32<Target>,
    pub new_salt: SaltTarget,
    pub prev_private_state: PrivateStateTarget,
    pub nullifier_proof: NullifierInsersionProofTarget,
    pub prev_asset_leaf: AssetLeafTarget,
    pub asset_merkle_proof: AssetMerkleProofTarget,
    pub new_private_state: PrivateStateTarget,
}

impl PrivateStateTransitionTarget {
    pub fn new<F: RichField + Extendable<D>, C: GenericConfig<D, F = F> + 'static, const D: usize>(
        builder: &mut CircuitBuilder<F, D>,
        is_checked: bool,
    ) -> Self
    where
        <C as GenericConfig<D>>::Hasher: AlgebraicHasher<F>,
    {
        let token_index = builder.add_virtual_target();
        let amount = U256::<Target>::new(builder, is_checked);
        let nullifier = Bytes32::<Target>::new(builder, is_checked);
        let new_salt = SaltTarget::new(builder);
        let prev_private_state = PrivateStateTarget::new(builder);
        let nullifier_proof = NullifierInsersionProofTarget::new(builder, is_checked);
        let prev_asset_leaf = AssetLeafTarget::new(builder, is_checked);
        let asset_merkle_proof = AssetMerkleProofTarget::new(builder, ASSET_TREE_HEIGHT);

        let new_nullifier_tree_root = nullifier_proof.get_new_root::<F, C, D>(
            builder,
            prev_private_state.nullifier_tree_root,
            nullifier,
        );
        asset_merkle_proof.verify::<F, C, D>(
            builder,
            &prev_asset_leaf,
            token_index,
            prev_private_state.asset_tree_root,
        );
        let new_asset_leaf = prev_asset_leaf.add(builder, amount);
        let new_asset_tree_root =
            asset_merkle_proof.get_root::<F, C, D>(builder, &new_asset_leaf, token_index);
        let new_private_state = PrivateStateTarget {
            asset_tree_root: new_asset_tree_root,
            nullifier_tree_root: new_nullifier_tree_root,
            salt: new_salt,
            ..prev_private_state
        };
        Self {
            token_index,
            amount,
            nullifier,
            new_salt,
            prev_private_state,
            nullifier_proof,
            prev_asset_leaf,
            asset_merkle_proof,
            new_private_state,
        }
    }

    pub fn set_witness<W: WitnessWrite<F>, F: Field>(
        &self,
        witness: &mut W,
        value: &PrivateStateTransitionValue,
    ) {
        witness.set_target(self.token_index, F::from_canonical_u32(value.token_index));
        self.amount.set_witness(witness, value.amount);
        self.nullifier.set_witness(witness, value.nullifier);
        self.new_salt.set_witness(witness, value.new_salt);
        self.prev_private_state
            .set_witness(witness, &value.prev_private_state);
        self.nullifier_proof
            .set_witness(witness, &value.nullifier_proof);
        self.prev_asset_leaf
            .set_witness(witness, value.prev_asset_leaf);
        self.asset_merkle_proof
            .set_witness(witness, &value.asset_merkle_proof);
        self.new_private_state
            .set_witness(witness, &value.new_private_state);
    }
}

#[cfg(test)]
mod tests {
    use plonky2::{
        field::goldilocks_field::GoldilocksField,
        iop::witness::PartialWitness,
        plonk::{
            circuit_builder::CircuitBuilder, circuit_data::CircuitConfig,
            config::PoseidonGoldilocksConfig,
        },
    };
    use rand::Rng;

    use crate::{
        circuits::balance::receive::receive_targets::private_state_transition::PrivateStateTransitionTarget,
        common::{
            private_state::PrivateState,
            salt::Salt,
            transfer::Transfer,
            trees::{asset_tree::AssetTree, nullifier_tree::NullifierTree},
        },
        constants::ASSET_TREE_HEIGHT,
        ethereum_types::bytes32::Bytes32,
    };

    use super::PrivateStateTransitionValue;

    type F = GoldilocksField;
    type C = PoseidonGoldilocksConfig;
    const D: usize = 2;

    #[test]
    fn private_state_transition() {
        let mut rng = rand::thread_rng();
        let transfer = Transfer::rand(&mut rng);
        let _pubkey = transfer.recipient.to_pubkey().unwrap();

        let mut asset_tree = AssetTree::new(ASSET_TREE_HEIGHT);
        let mut nullifier_tree = NullifierTree::new();
        let prev_private_state = PrivateState {
            asset_tree_root: asset_tree.get_root(),
            nullifier_tree_root: nullifier_tree.get_root(),
            nonce: rng.gen(),
            salt: Salt::rand(&mut rng),
        };

        let prev_asset_leaf = asset_tree.get_leaf(transfer.token_index as usize);
        let asset_merkle_proof = asset_tree.prove(transfer.token_index as usize);
        let new_asset_leaf = prev_asset_leaf.add(transfer.amount);
        asset_tree.update(transfer.token_index as usize, new_asset_leaf);

        let nullifier: Bytes32<u32> = transfer.commitment().into();
        let nullifier_proof = nullifier_tree.prove_and_insert(nullifier).unwrap();

        let new_salt = Salt::rand(&mut rng);
        let value = PrivateStateTransitionValue::new(
            transfer.token_index,
            transfer.amount,
            nullifier,
            new_salt,
            &prev_private_state,
            &nullifier_proof,
            &prev_asset_leaf,
            &asset_merkle_proof,
        );

        let expected_new_private_state = PrivateState {
            asset_tree_root: asset_tree.get_root(),
            nullifier_tree_root: nullifier_tree.get_root(),
            nonce: prev_private_state.nonce,
            salt: new_salt,
        };
        assert_eq!(value.new_private_state, expected_new_private_state);

        let mut builder = CircuitBuilder::new(CircuitConfig::default());
        let target = PrivateStateTransitionTarget::new::<F, C, D>(&mut builder, true);
        let data = builder.build::<C>();

        let mut pw = PartialWitness::<F>::new();
        target.set_witness(&mut pw, &value);
        let _ = data.prove(pw).unwrap();
    }
}
