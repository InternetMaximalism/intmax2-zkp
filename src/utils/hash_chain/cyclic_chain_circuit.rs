use anyhow::Result;
use hashbrown::HashMap;
use plonky2::{
    field::extension::Extendable,
    gates::noop::NoopGate,
    hash::hash_types::RichField,
    iop::{
        target::BoolTarget,
        witness::{PartialWitness, WitnessWrite as _},
    },
    plonk::{
        circuit_builder::CircuitBuilder,
        circuit_data::{
            CircuitConfig, CircuitData, CommonCircuitData, VerifierCircuitData,
            VerifierCircuitTarget,
        },
        config::{AlgebraicHasher, GenericConfig},
        proof::{ProofWithPublicInputs, ProofWithPublicInputsTarget},
    },
    recursion::dummy_circuit::cyclic_base_proof,
};

use crate::{
    constants::CYCLIC_CIRCUIT_PADDING_DEGREE,
    ethereum_types::{
        bytes32::{Bytes32, Bytes32Target, BYTES32_LEN},
        u32limb_trait::U32LimbTargetTrait,
    },
    utils::{cyclic::vd_vec_len, recursively_verifiable::add_proof_target_and_verify},
};

#[derive(Debug)]
pub struct CyclicChainCircuit<F, C, const D: usize>
where
    F: RichField + Extendable<D>,
    C: GenericConfig<D, F = F>,
{
    pub data: CircuitData<F, C, D>,
    is_first_step: BoolTarget,
    inner_proof: ProofWithPublicInputsTarget<D>,
    prev_proof: ProofWithPublicInputsTarget<D>,
    verifier_data_target: VerifierCircuitTarget,
}

impl<F, C, const D: usize> CyclicChainCircuit<F, C, D>
where
    F: RichField + Extendable<D>,
    C: GenericConfig<D, F = F> + 'static,
    C::Hasher: AlgebraicHasher<F>,
{
    pub fn new(inner_verifier_data: &VerifierCircuitData<F, C, D>) -> Self {
        let mut builder = CircuitBuilder::<F, D>::new(CircuitConfig::default());
        let is_first_step = builder.add_virtual_bool_target_safe();
        let is_not_first_step = builder.not(is_first_step);
        let inner_proof = add_proof_target_and_verify(inner_verifier_data, &mut builder);
        let prev_hash = Bytes32Target::from_slice(&inner_proof.public_inputs[0..BYTES32_LEN]);
        let hash = Bytes32Target::from_slice(&inner_proof.public_inputs[BYTES32_LEN..]);
        builder.register_public_inputs(&hash.to_vec());

        let common_data = common_data_for_circuit::<F, C, D>();
        let verifier_data_target = builder.add_verifier_data_public_inputs();

        let prev_proof = builder.add_virtual_proof_with_pis(&common_data);
        builder
            .conditionally_verify_cyclic_proof_or_dummy::<C>(
                is_not_first_step,
                &prev_proof,
                &common_data,
            )
            .unwrap();
        let prev_pis = Bytes32Target::from_slice(&prev_proof.public_inputs[0..BYTES32_LEN]);
        prev_pis.connect(&mut builder, prev_hash);
        // initial condition
        let zero = Bytes32Target::zero::<F, D, Bytes32>(&mut builder);
        prev_hash.conditional_assert_eq(&mut builder, zero, is_first_step);

        let (data, success) = builder.try_build_with_options::<C>(true);
        assert_eq!(data.common, common_data);
        assert!(success);
        Self {
            data,
            is_first_step,
            inner_proof,
            prev_proof,
            verifier_data_target,
        }
    }

    pub fn prove(
        &self,
        inner_proof: &ProofWithPublicInputs<F, C, D>,
        prev_proof: &Option<ProofWithPublicInputs<F, C, D>>,
    ) -> Result<ProofWithPublicInputs<F, C, D>> {
        let mut pw = PartialWitness::<F>::new();
        pw.set_verifier_data_target(&self.verifier_data_target, &self.data.verifier_only);
        pw.set_proof_with_pis_target(&self.inner_proof, inner_proof);
        if prev_proof.is_none() {
            let dummy_proof =
                cyclic_base_proof(&self.data.common, &self.data.verifier_only, HashMap::new());
            pw.set_bool_target(self.is_first_step, true);
            pw.set_proof_with_pis_target(&self.prev_proof, &dummy_proof);
        } else {
            pw.set_bool_target(self.is_first_step, false);
            pw.set_proof_with_pis_target(&self.prev_proof, prev_proof.as_ref().unwrap());
        }
        self.data.prove(pw)
    }
}

// Generates `CommonCircuitData` for the cyclic circuit
fn common_data_for_circuit<
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

    let mut builder = CircuitBuilder::<F, D>::new(CircuitConfig::default());
    let proof = builder.add_virtual_proof_with_pis(&data.common);
    let verifier_data = VerifierCircuitTarget {
        constants_sigmas_cap: builder.add_virtual_cap(data.common.config.fri_config.cap_height),
        circuit_digest: builder.add_virtual_hash(),
    };
    builder.verify_proof::<C>(&proof, &verifier_data, &data.common);
    while builder.num_gates() < 1 << CYCLIC_CIRCUIT_PADDING_DEGREE {
        builder.add_gate(NoopGate, vec![]);
    }
    let mut common = builder.build::<C>().common;
    common.num_public_inputs = BYTES32_LEN + vd_vec_len(&common.config);
    common
}
