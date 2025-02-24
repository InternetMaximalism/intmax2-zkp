use plonky2::{
    field::extension::Extendable,
    hash::hash_types::RichField,
    iop::witness::PartialWitness,
    plonk::{
        circuit_builder::CircuitBuilder,
        circuit_data::{CircuitConfig, CircuitData, CommonCircuitData},
        config::{AlgebraicHasher, GenericConfig},
        proof::ProofWithPublicInputs,
    },
};

use crate::{
    circuits::balance::receive::receive_targets::transfer_inclusion::{
        TransferInclusionTarget, TransferInclusionValue,
    },
    common::withdrawal::{get_withdrawal_nullifier_circuit, WithdrawalTarget},
};

#[derive(Debug)]
pub struct SingleWithdrawalCircuit<F, C, const D: usize>
where
    F: RichField + Extendable<D>,
    C: GenericConfig<D, F = F>,
{
    pub data: CircuitData<F, C, D>,
    transfer_inclusion_target: TransferInclusionTarget<D>,
}

impl<F, C, const D: usize> SingleWithdrawalCircuit<F, C, D>
where
    F: RichField + Extendable<D>,
    C: GenericConfig<D, F = F> + 'static,
    C::Hasher: AlgebraicHasher<F>,
{
    pub fn new(balance_common_data: &CommonCircuitData<F, D>) -> Self {
        let mut builder =
            CircuitBuilder::<F, D>::new(CircuitConfig::standard_recursion_zk_config());
        let transfer_inclusion_target =
            TransferInclusionTarget::new::<F, C>(balance_common_data, &mut builder, true);
        let transfer = transfer_inclusion_target.transfer.clone();
        let nullifier = get_withdrawal_nullifier_circuit(&mut builder, &transfer);
        let recipient = transfer.recipient.to_address(&mut builder);
        let withdrawal = WithdrawalTarget {
            recipient,
            token_index: transfer.token_index,
            amount: transfer.amount,
            nullifier,
            block_hash: transfer_inclusion_target.public_state.block_hash,
            block_number: transfer_inclusion_target.public_state.block_number,
        };
        builder.register_public_inputs(&withdrawal.to_vec());
        let data = builder.build();
        Self {
            data,
            transfer_inclusion_target,
        }
    }

    pub fn prove(
        &self,
        transition_inclusion_value: &TransferInclusionValue<F, C, D>,
    ) -> anyhow::Result<ProofWithPublicInputs<F, C, D>> {
        let mut pw = PartialWitness::<F>::new();
        self.transfer_inclusion_target
            .set_witness(&mut pw, transition_inclusion_value);
        self.data.prove(pw)
    }

    pub fn verify(&self, proof: &ProofWithPublicInputs<F, C, D>) -> anyhow::Result<()> {
        self.data.verify(proof.clone())
    }
}
