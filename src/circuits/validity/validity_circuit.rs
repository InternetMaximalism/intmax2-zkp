use plonky2::{
    field::extension::Extendable,
    gates::noop::NoopGate,
    hash::hash_types::RichField,
    iop::target::BoolTarget,
    plonk::{
        circuit_builder::CircuitBuilder,
        circuit_data::{CircuitConfig, CircuitData, CommonCircuitData, VerifierCircuitTarget},
        config::{AlgebraicHasher, GenericConfig},
        proof::ProofWithPublicInputsTarget,
    },
};

use crate::{
    circuits::validity::validity_pis::{
        ValidityPublicInputs, ValidityPublicInputsTarget, VALIDITY_PUBLIC_INPUTS_LEN,
    },
    constants::VALIDITY_CIRCUIT_PADDING_DEGREE,
    utils::recursivable::Recursivable as _,
};

use super::transition::wrapper::TransitionWrapperCircuit;

#[derive(Debug)]
pub struct ValidityCircuit<F, C, const D: usize>
where
    F: RichField + Extendable<D>,
    C: GenericConfig<D, F = F>,
{
    pub data: CircuitData<F, C, D>,
    pub is_first_step: BoolTarget,
    pub transition_proof: ProofWithPublicInputsTarget<D>,
    pub prev_proof: ProofWithPublicInputsTarget<D>,
    pub verifier_data_target: VerifierCircuitTarget,
}

impl<F, C, const D: usize> ValidityCircuit<F, C, D>
where
    F: RichField + Extendable<D>,
    C: GenericConfig<D, F = F> + 'static,
    C::Hasher: AlgebraicHasher<F>,
{
    pub fn new(validity_wrap_circuit: &TransitionWrapperCircuit<F, C, D>) -> Self {
        let mut builder = CircuitBuilder::<F, D>::new(CircuitConfig::default());
        let is_first_step = builder.add_virtual_bool_target_safe();
        let is_not_first_step = builder.not(is_first_step);

        let transition_proof = validity_wrap_circuit
            .add_proof_target_and_conditionally_verify(&mut builder, is_not_first_step);
        let prev_pis_ = ValidityPublicInputsTarget::from_vec(
            &transition_proof.public_inputs[0..VALIDITY_PUBLIC_INPUTS_LEN],
        );
        let new_pis = ValidityPublicInputsTarget::from_vec(
            &transition_proof.public_inputs[VALIDITY_PUBLIC_INPUTS_LEN..],
        );
        builder.register_public_inputs(&new_pis.to_vec());

        let mut common_data = common_data_for_validity_circuit::<F, C, D>();
        let verifier_data_target = builder.add_verifier_data_public_inputs();
        common_data.num_public_inputs = builder.num_public_inputs();

        let prev_proof = builder.add_virtual_proof_with_pis(&common_data);
        builder
            .conditionally_verify_cyclic_proof_or_dummy::<C>(
                is_not_first_step,
                &prev_proof,
                &common_data,
            )
            .unwrap();
        let prev_pis = ValidityPublicInputsTarget::from_vec(
            &prev_proof.public_inputs[0..VALIDITY_PUBLIC_INPUTS_LEN],
        );
        prev_pis.connect(&mut builder, &prev_pis_);
        let genesis_pis = ValidityPublicInputs::genesis();
        let genesis_pis_t = ValidityPublicInputsTarget::constant(&mut builder, &genesis_pis);
        prev_pis.conditional_assert_eq(&mut builder, &genesis_pis_t, is_first_step);

        let (data, success) = builder.try_build_with_options::<C>(false);
        debug_assert_eq!(data.common, common_data);
        assert!(success);
        Self {
            data,
            is_first_step,
            transition_proof,
            prev_proof,
            verifier_data_target,
        }
    }
}

// Generates `CommonCircuitData` usable for recursion.
pub fn common_data_for_validity_circuit<
    F: RichField + Extendable<D>,
    C: GenericConfig<D, F = F>,
    const D: usize,
>() -> CommonCircuitData<F, D>
where
    C::Hasher: AlgebraicHasher<F>,
{
    let builder = CircuitBuilder::<F, D>::new(CircuitConfig::default());
    let data = builder.build::<C>();

    let mut builder = CircuitBuilder::<F, D>::new(CircuitConfig::default());
    let proof = builder.add_virtual_proof_with_pis(&data.common);
    let verifier_data = VerifierCircuitTarget {
        constants_sigmas_cap: builder.add_virtual_cap(data.common.config.fri_config.cap_height),
        circuit_digest: builder.add_virtual_hash(),
    };
    builder.verify_proof::<C>(&proof, &verifier_data, &data.common);
    let data = builder.build::<C>();

    let config = CircuitConfig::standard_recursion_config();
    let mut builder = CircuitBuilder::<F, D>::new(config);
    let proof = builder.add_virtual_proof_with_pis(&data.common);
    let verifier_data = VerifierCircuitTarget {
        constants_sigmas_cap: builder.add_virtual_cap(data.common.config.fri_config.cap_height),
        circuit_digest: builder.add_virtual_hash(),
    };
    builder.verify_proof::<C>(&proof, &verifier_data, &data.common);
    while builder.num_gates() < 1 << VALIDITY_CIRCUIT_PADDING_DEGREE {
        builder.add_gate(NoopGate, vec![]);
    }
    builder.build::<C>().common
}

#[cfg(test)]
mod tests {
    #[test]
    fn validity_circuit() {}
}
