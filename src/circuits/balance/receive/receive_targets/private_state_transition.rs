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
        transfer::{Transfer, TransferTarget},
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
    pub pubkey: U256<u32>,
    pub transfer: Transfer,
    pub prev_private_state: PrivateState,
    pub nullifier_proof: NullifierInsersionProof,
    pub prev_asset_leaf: AssetLeaf,
    pub asset_merkle_proof: AssetMerkleProof,
    pub new_private_state: PrivateState,
}

impl PrivateStateTransitionValue {
    pub fn new(
        pubkey: U256<u32>,
        transfer: Transfer,
        prev_private_state: PrivateState,
        nullifier_proof: NullifierInsersionProof,
        prev_asset_leaf: AssetLeaf,
        asset_merkle_proof: AssetMerkleProof,
    ) -> Self {
        let recipient = transfer
            .recipient
            .to_pubkey()
            .expect("recipient is not a pubkey");
        assert_eq!(pubkey, recipient);
        let nullifier: Bytes32<u32> = transfer.commitment().into();
        let new_nullifier_tree_root = nullifier_proof
            .get_new_root(prev_private_state.nullifier_tree_root, nullifier)
            .expect("Invalid nullifier proof");
        asset_merkle_proof
            .verify(
                &prev_asset_leaf,
                transfer.token_index as usize,
                prev_private_state.asset_tree_root,
            )
            .expect("Invalid asset merkle proof");
        let new_asset_leaf = prev_asset_leaf.add(transfer.amount);
        let new_asset_tree_root =
            asset_merkle_proof.get_root(&new_asset_leaf, transfer.token_index as usize);
        let new_private_state = PrivateState {
            asset_tree_root: new_asset_tree_root,
            nullifier_tree_root: new_nullifier_tree_root,
            ..prev_private_state
        };
        Self {
            pubkey,
            transfer,
            prev_private_state,
            nullifier_proof,
            prev_asset_leaf,
            asset_merkle_proof,
            new_private_state,
        }
    }
}

#[derive(Debug, Clone)]
pub struct PrivateStateTransitionTarget {
    pub pubkey: U256<Target>,
    pub transfer: TransferTarget,
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
        let pubkey = U256::<Target>::new(builder, is_checked);
        let transfer = TransferTarget::new(builder, is_checked);
        let prev_private_state = PrivateStateTarget::new(builder);
        let nullifier_proof = NullifierInsersionProofTarget::new(builder, is_checked);
        let prev_asset_leaf = AssetLeafTarget::new(builder, is_checked);
        let asset_merkle_proof = AssetMerkleProofTarget::new(builder, ASSET_TREE_HEIGHT);

        let recipient = transfer.recipient.to_pubkey(builder);
        pubkey.connect(builder, recipient);
        let transfer_commitment = transfer.commitment(builder);
        let nullifier: Bytes32<Target> = Bytes32::from_hash_out(builder, transfer_commitment);
        let new_nullifier_tree_root = nullifier_proof.get_new_root::<F, C, D>(
            builder,
            prev_private_state.nullifier_tree_root,
            nullifier,
        );
        asset_merkle_proof.verify::<F, C, D>(
            builder,
            &prev_asset_leaf,
            transfer.token_index,
            prev_private_state.asset_tree_root,
        );
        let new_asset_leaf = prev_asset_leaf.add(builder, transfer.amount);
        let new_asset_tree_root =
            asset_merkle_proof.get_root::<F, C, D>(builder, &new_asset_leaf, transfer.token_index);
        let new_private_state = PrivateStateTarget {
            asset_tree_root: new_asset_tree_root,
            nullifier_tree_root: new_nullifier_tree_root,
            ..prev_private_state
        };
        Self {
            pubkey,
            transfer,
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
        self.pubkey.set_witness(witness, value.pubkey);
        self.transfer.set_witness(witness, value.transfer);
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
        let pubkey = transfer.recipient.to_pubkey().unwrap();

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

        let value = PrivateStateTransitionValue::new(
            pubkey,
            transfer,
            prev_private_state.clone(),
            nullifier_proof.clone(),
            prev_asset_leaf,
            asset_merkle_proof.clone(),
        );

        let expected_new_private_state = PrivateState {
            asset_tree_root: asset_tree.get_root(),
            nullifier_tree_root: nullifier_tree.get_root(),
            nonce: prev_private_state.nonce,
            salt: prev_private_state.salt,
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
