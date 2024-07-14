use crate::{
    common::{
        private_state::PrivateState,
        salt::Salt,
        trees::{
            asset_tree::{AssetLeaf, AssetMerkleProof},
            nullifier_tree::NullifierInsersionProof,
        },
    },
    ethereum_types::{bytes32::Bytes32, u256::U256},
};

#[derive(Debug, Clone)]
pub struct PrivateStateTransitionWitness {
    pub token_index: u32,
    pub amount: U256<u32>,
    pub nullifier: Bytes32<u32>,
    pub new_salt: Salt,
    pub prev_private_state: PrivateState,
    pub nullifier_proof: NullifierInsersionProof,
    pub prev_asset_leaf: AssetLeaf,
    pub asset_merkle_proof: AssetMerkleProof,
}
