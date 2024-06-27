use plonky2::{
    field::extension::Extendable,
    hash::hash_types::RichField,
    iop::target::BoolTarget,
    plonk::{
        circuit_builder::CircuitBuilder,
        circuit_data::CircuitData,
        config::{AlgebraicHasher, GenericConfig},
        proof::ProofWithPublicInputsTarget,
    },
};

use super::dummy::conditionally_verify_proof;

pub trait Recursivable<
    F: RichField + Extendable<D>,
    C: GenericConfig<D, F = F> + 'static,
    const D: usize,
> where
    <C as GenericConfig<D>>::Hasher: AlgebraicHasher<F>,
{
    fn circuit_data(&self) -> &CircuitData<F, C, D>;

    fn add_proof_target_and_verify(
        &self,
        builder: &mut CircuitBuilder<F, D>,
    ) -> ProofWithPublicInputsTarget<D> {
        let data = self.circuit_data();
        let proof = builder.add_virtual_proof_with_pis(&data.common);
        let vd_target = builder.constant_verifier_data(&data.verifier_only);
        builder.verify_proof::<C>(&proof, &vd_target, &data.common);
        proof
    }

    fn add_proof_target_and_conditionally_verify(
        &self,
        builder: &mut CircuitBuilder<F, D>,
        condition: BoolTarget,
    ) -> ProofWithPublicInputsTarget<D> {
        let data = self.circuit_data();
        let proof = builder.add_virtual_proof_with_pis(&data.common);
        let vd = builder.constant_verifier_data(&data.verifier_only);
        conditionally_verify_proof::<F, C, D>(builder, condition, &proof, &vd, &data.common);
        proof
    }
}
