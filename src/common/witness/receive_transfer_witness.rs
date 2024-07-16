use super::{
    private_state_transition_witness::PrivateStateTransitionWitness,
    transfer_witness::TransferWitness,
};

#[derive(Debug, Clone)]
pub struct ReceiveTransferWitness {
    pub transfer_witness: TransferWitness,
    pub private_witness: PrivateStateTransitionWitness,
}
