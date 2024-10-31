pub mod block_witness;
pub mod deposit_witness;
pub mod full_block;
pub mod private_witness;
pub mod receive_deposit_witness;
pub mod receive_transfer_witness;
// pub mod send_witness; todo: remove file
pub mod spent_witness;
pub mod transfer_witness;
pub mod tx_witness;
pub mod update_witness;
pub mod validity_transition_witness;
pub mod validity_witness;
pub mod withdrawal_witness;

// Compress witness to reduce communication cost of nodes
pub mod compressed;
