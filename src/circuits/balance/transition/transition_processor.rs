use plonky2::{
    field::extension::Extendable, hash::hash_types::RichField, plonk::config::GenericConfig,
};

use crate::circuits::balance::receive::{
    receive_deposit_circuit::ReceiveDepositCircuit,
    receive_transfer_circuit::ReceiveTransferCircuit, update_circuit::UpdateCircuit,
};

pub struct BalanceTransitionProcessor<F, C, const D: usize>
where
    F: RichField + Extendable<D>,
    C: GenericConfig<D, F = F>,
{
    pub receive_transfer_circuit: ReceiveTransferCircuit<F, C, D>,
    pub receive_deposit_circuit: ReceiveDepositCircuit<F, C, D>,
    pub update_circuit: UpdateCircuit<F, C, D>,
}
