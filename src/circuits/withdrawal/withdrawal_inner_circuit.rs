use plonky2::{
    field::extension::Extendable,
    hash::hash_types::RichField,
    iop::{target::Target, witness::PartialWitness},
    plonk::{
        circuit_builder::CircuitBuilder,
        circuit_data::{CircuitConfig, CircuitData},
        config::{AlgebraicHasher, GenericConfig},
        proof::ProofWithPublicInputs,
    },
};

use crate::{
    circuits::balance::{
        balance_circuit::BalanceCircuit,
        receive::receive_targets::transfer_inclusion::{
            TransferInclusionTarget, TransferInclusionValue,
        },
    },
    common::withdrawal::{get_withdrawal_nullifier_circuit, WithdrawalTarget},
    ethereum_types::{bytes32::Bytes32, u32limb_trait::U32LimbTargetTrait},
    utils::recursivable::Recursivable,
};

#[derive(Debug)]
pub struct WithdrawalInnerCircuit<F, C, const D: usize>
where
    F: RichField + Extendable<D>,
    C: GenericConfig<D, F = F>,
{
    data: CircuitData<F, C, D>,
    prev_withdral_hash: Bytes32<Target>,
    transfer_inclusion_target: TransferInclusionTarget<D>,
}

impl<F, C, const D: usize> WithdrawalInnerCircuit<F, C, D>
where
    F: RichField + Extendable<D>,
    C: GenericConfig<D, F = F> + 'static,
    C::Hasher: AlgebraicHasher<F>,
{
    pub fn new(balance_circuit: &BalanceCircuit<F, C, D>) -> Self {
        let mut builder = CircuitBuilder::<F, D>::new(CircuitConfig::default());
        let transfer_inclusion_target = TransferInclusionTarget::new::<F, C>(
            &balance_circuit.get_verifier_data().common,
            &mut builder,
            true,
        );
        let transfer = transfer_inclusion_target.transfer.clone();
        let nullifier = get_withdrawal_nullifier_circuit(&mut builder, &transfer);
        let recipient = transfer.recipient.to_address(&mut builder);
        let prev_withdral_hash = Bytes32::<Target>::new(&mut builder, false); // connect later
        let withdrawal = WithdrawalTarget {
            prev_withdral_hash,
            recipient,
            token_index: transfer.token_index,
            amount: transfer.amount,
            nullifier,
            block_hash: transfer_inclusion_target.public_state.block_hash,
        };
        let withdrawal_hash = withdrawal.hash::<F, C, D>(&mut builder);
        let pis = [prev_withdral_hash.to_vec(), withdrawal_hash.to_vec()].concat();
        builder.register_public_inputs(&pis);
        let data = builder.build();
        Self {
            data,
            prev_withdral_hash,
            transfer_inclusion_target,
        }
    }

    pub fn prove(
        &self,
        prev_withdrawal_hash: Bytes32<u32>,
        transition_inclusion_value: &TransferInclusionValue<F, C, D>,
    ) -> anyhow::Result<ProofWithPublicInputs<F, C, D>> {
        let mut pw = PartialWitness::<F>::new();
        self.prev_withdral_hash
            .set_witness(&mut pw, prev_withdrawal_hash);
        self.transfer_inclusion_target
            .set_witness(&mut pw, transition_inclusion_value);
        self.data.prove(pw)
    }
}

impl<F: RichField + Extendable<D>, C: GenericConfig<D, F = F> + 'static, const D: usize>
    Recursivable<F, C, D> for WithdrawalInnerCircuit<F, C, D>
where
    <C as GenericConfig<D>>::Hasher: AlgebraicHasher<F>,
{
    fn circuit_data(&self) -> &CircuitData<F, C, D> {
        &self.data
    }
}
