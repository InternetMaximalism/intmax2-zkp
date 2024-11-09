use plonky2::{
    field::extension::Extendable,
    hash::hash_types::RichField,
    iop::target::BoolTarget,
    plonk::{
        circuit_builder::CircuitBuilder,
        circuit_data::VerifierCircuitData,
        config::{AlgebraicHasher, GenericConfig},
        proof::ProofWithPublicInputsTarget,
    },
};

use super::{cyclic::vd_from_pis_slice_target, dummy::conditionally_verify_proof};

pub fn add_proof_target_and_verify<F, C, const D: usize>(
    verifier_data: &VerifierCircuitData<F, C, D>,
    builder: &mut CircuitBuilder<F, D>,
) -> ProofWithPublicInputsTarget<D>
where
    F: RichField + Extendable<D>,
    C: GenericConfig<D, F = F> + 'static,
    <C as GenericConfig<D>>::Hasher: AlgebraicHasher<F>,
{
    let proof = builder.add_virtual_proof_with_pis(&verifier_data.common);
    let vd_target = builder.constant_verifier_data(&verifier_data.verifier_only);
    builder.verify_proof::<C>(&proof, &vd_target, &verifier_data.common);
    proof
}

pub fn add_proof_target_and_conditionally_verify<F, C, const D: usize>(
    verifier_data: &VerifierCircuitData<F, C, D>,
    builder: &mut CircuitBuilder<F, D>,
    condition: BoolTarget,
) -> ProofWithPublicInputsTarget<D>
where
    F: RichField + Extendable<D>,
    C: GenericConfig<D, F = F> + 'static,
    <C as GenericConfig<D>>::Hasher: AlgebraicHasher<F>,
{
    let proof = builder.add_virtual_proof_with_pis(&verifier_data.common);
    let vd = builder.constant_verifier_data(&verifier_data.verifier_only);
    conditionally_verify_proof::<F, C, D>(builder, condition, &proof, &vd, &verifier_data.common);
    proof
}

pub fn add_proof_target_and_verify_cyclic<F, C, const D: usize>(
    verifier_data: &VerifierCircuitData<F, C, D>,
    builder: &mut CircuitBuilder<F, D>,
) -> ProofWithPublicInputsTarget<D>
where
    F: RichField + Extendable<D>,
    C: GenericConfig<D, F = F> + 'static,
    <C as GenericConfig<D>>::Hasher: AlgebraicHasher<F>,
{
    let proof = builder.add_virtual_proof_with_pis(&verifier_data.common);
    let vd_target = builder.constant_verifier_data(&verifier_data.verifier_only);
    let inner_vd_target =
        vd_from_pis_slice_target(&proof.public_inputs, &verifier_data.common.config).unwrap();
    builder.connect_hashes(vd_target.circuit_digest, inner_vd_target.circuit_digest);
    builder.connect_merkle_caps(
        &vd_target.constants_sigmas_cap,
        &inner_vd_target.constants_sigmas_cap,
    );
    builder.verify_proof::<C>(&proof, &vd_target, &verifier_data.common);
    proof
}
