use super::{deposit_witness::DepositWitness, private_witness::PrivateWitness};

#[derive(Clone, Debug)]
pub struct ReceiveDepositWitness {
    pub deposit_witness: DepositWitness,
    pub private_witness: PrivateWitness,
}
