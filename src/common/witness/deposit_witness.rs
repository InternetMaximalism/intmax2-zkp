use crate::common::{
    salt::Salt,
    trees::deposit_tree::{DepositLeaf, DepositMerkleProof},
};

#[derive(Clone, Debug)]
pub struct DepositWitness {
    pub deposit_salt: Salt,
    pub deposit_index: usize,
    pub deposit: DepositLeaf,
    pub deposit_merkle_proof: DepositMerkleProof,
}

// without deposit_merkle_proof
#[derive(Clone, Debug)]
pub struct DepositCase {
    pub deposit_salt: Salt,
    pub deposit_index: usize,
    pub deposit: DepositLeaf,
}
