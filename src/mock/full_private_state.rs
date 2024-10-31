use crate::common::{
    salt::Salt,
    trees::{asset_tree::AssetTree, nullifier_tree::NullifierTree},
};

/// Full witness of the private state
#[derive(Clone, Debug)]
pub struct FullPrivateState {
    pub asset_tree: AssetTree,
    pub nullifier_tree: NullifierTree,
    pub nonce: u32,
    pub salt: Salt,
}
