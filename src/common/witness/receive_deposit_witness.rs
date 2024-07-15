use super::{
    deposit_witness::DepositWitness,
    private_state_transition_witness::PrivateStateTransitionWitness,
};

#[derive(Clone, Debug)]
pub struct ReceiveDepositWitness {
    pub deposit_witness: DepositWitness,
    pub private_witness: PrivateStateTransitionWitness,
}
