use plonky2::{
    field::extension::Extendable,
    hash::hash_types::RichField,
    iop::witness::{PartialWitness, WitnessWrite},
    plonk::{
        circuit_builder::CircuitBuilder,
        circuit_data::{CircuitConfig, CircuitData},
        config::{AlgebraicHasher, GenericConfig},
        proof::{ProofWithPublicInputs, ProofWithPublicInputsTarget},
    },
};

use crate::{
    common::withdrawal::WithdrawalTarget,
    ethereum_types::{
        bytes32::{Bytes32, Bytes32Target},
        u32limb_trait::U32LimbTargetTrait,
    },
    utils::recursively_verifiable::RecursivelyVerifiable,
};

use super::single_withdrawal_circuit::SingleWithdrawalCircuit;

#[derive(Debug)]
pub struct WithdrawalInnerCircuit<F, C, const D: usize>
where
    F: RichField + Extendable<D>,
    C: GenericConfig<D, F = F>,
{
    data: CircuitData<F, C, D>,
    prev_withdral_hash: Bytes32Target,
    single_withdrawal_proof: ProofWithPublicInputsTarget<D>,
}

impl<F, C, const D: usize> WithdrawalInnerCircuit<F, C, D>
where
    F: RichField + Extendable<D>,
    C: GenericConfig<D, F = F> + 'static,
    C::Hasher: AlgebraicHasher<F>,
{
    pub fn new(single_withdrawal_circuit: &SingleWithdrawalCircuit<F, C, D>) -> Self {
        let mut builder = CircuitBuilder::<F, D>::new(CircuitConfig::default());
        let single_withdrawal_proof =
            single_withdrawal_circuit.add_proof_target_and_verify(&mut builder);
        let withdrawal = WithdrawalTarget::from_slice(&single_withdrawal_proof.public_inputs);
        let prev_withdral_hash = Bytes32Target::new(&mut builder, false); // connect later
        let withdrawal_hash =
            withdrawal.hash_with_prev_hash::<F, C, D>(&mut builder, prev_withdral_hash);
        let pis = [prev_withdral_hash.to_vec(), withdrawal_hash.to_vec()].concat();
        builder.register_public_inputs(&pis);
        let data = builder.build();
        Self {
            data,
            prev_withdral_hash,
            single_withdrawal_proof,
        }
    }

    pub fn prove(
        &self,
        prev_withdrawal_hash: Bytes32,
        single_withdrawal_proof: &ProofWithPublicInputs<F, C, D>,
    ) -> anyhow::Result<ProofWithPublicInputs<F, C, D>> {
        let mut pw = PartialWitness::<F>::new();
        self.prev_withdral_hash
            .set_witness(&mut pw, prev_withdrawal_hash);
        pw.set_proof_with_pis_target(&self.single_withdrawal_proof, single_withdrawal_proof);
        self.data.prove(pw)
    }
}

impl<F: RichField + Extendable<D>, C: GenericConfig<D, F = F> + 'static, const D: usize>
    RecursivelyVerifiable<F, C, D> for WithdrawalInnerCircuit<F, C, D>
where
    <C as GenericConfig<D>>::Hasher: AlgebraicHasher<F>,
{
    fn circuit_data(&self) -> &CircuitData<F, C, D> {
        &self.data
    }
}
