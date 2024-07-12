use super::{block_witness::BlockWitness, validity_transition_witness::ValidityTransitionWitness};

#[derive(Debug, Clone)]
pub struct ValidityWitness {
    pub block_witness: BlockWitness,
    pub validity_transition_witness: ValidityTransitionWitness,
}
