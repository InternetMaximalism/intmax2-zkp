use crate::common::{deposit::Deposit, salt::Salt, trees::deposit_tree::DepositMerkleProof};

#[derive(Clone, Debug)]
pub struct DepositWitness {
    pub deposit_salt: Salt,
    pub deposit_index: usize,
    pub deposit: Deposit,
    pub deposit_merkle_proof: DepositMerkleProof,
}

// without deposit_merkle_proof
#[derive(Clone, Debug)]
pub struct DepositCase {
    pub deposit_salt: Salt,
    pub deposit_index: usize,
    pub deposit: Deposit,
}
