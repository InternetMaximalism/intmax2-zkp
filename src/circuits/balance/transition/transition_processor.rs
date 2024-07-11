use plonky2::{
    field::extension::Extendable,
    hash::hash_types::RichField,
    plonk::config::{AlgebraicHasher, GenericConfig},
};

use crate::circuits::{
    balance::{
        receive::{
            receive_deposit_circuit::ReceiveDepositCircuit,
            receive_transfer_circuit::ReceiveTransferCircuit, update_circuit::UpdateCircuit,
        },
        send::sender_processor::SenderProcessor,
    },
    validity::validity_circuit::ValidityCircuit,
};

use super::transition_circuit::BalanceTransitionCircuit;

pub struct BalanceTransitionProcessor<F, C, const D: usize>
where
    F: RichField + Extendable<D>,
    C: GenericConfig<D, F = F>,
{
    pub receive_transfer_circuit: ReceiveTransferCircuit<F, C, D>,
    pub receive_deposit_circuit: ReceiveDepositCircuit<F, C, D>,
    pub update_circuit: UpdateCircuit<F, C, D>,
    pub sender_processor: SenderProcessor<F, C, D>,
    pub balance_transition_circuit: BalanceTransitionCircuit<F, C, D>,
}

impl<F, C, const D: usize> BalanceTransitionProcessor<F, C, D>
where
    F: RichField + Extendable<D>,
    C: GenericConfig<D, F = F> + 'static,
    <C as GenericConfig<D>>::Hasher: AlgebraicHasher<F>,
{
    pub fn new(validity_circuit: &ValidityCircuit<F, C, D>) -> Self {
        let receive_transfer_circuit = ReceiveTransferCircuit::new();
        let receive_deposit_circuit = ReceiveDepositCircuit::new();
        let update_circuit = UpdateCircuit::new(validity_circuit);
        let sender_processor = SenderProcessor::new(validity_circuit);
        let balance_transition_circuit = BalanceTransitionCircuit::new(
            &receive_transfer_circuit,
            &receive_deposit_circuit,
            &update_circuit,
            &sender_processor.sender_circuit,
        );
        Self {
            receive_transfer_circuit,
            receive_deposit_circuit,
            update_circuit,
            sender_processor,
            balance_transition_circuit,
        }
    }

    pub fn prove(&self) {}
}
