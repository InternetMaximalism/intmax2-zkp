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
        circuit_data::{CircuitConfig, CircuitData, CommonCircuitData, VerifierCircuitTarget},
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
    utils::{
        cyclic::{vd_from_pis_slice_target, vd_vec_len},
        recursivable::Recursivable,
    },
};

use super::withdrawal_inner_circuit::WithdrawalInnerCircuit;

#[derive(Debug)]
pub struct WithdrawalCircuit<F, C, const D: usize>
where
    F: RichField + Extendable<D>,
    C: GenericConfig<D, F = F>,
{
    data: CircuitData<F, C, D>,
    is_first_step: BoolTarget,
    withdrawal_inner_proof: ProofWithPublicInputsTarget<D>,
    prev_proof: ProofWithPublicInputsTarget<D>,
    verifier_data_target: VerifierCircuitTarget,
}

impl<F, C, const D: usize> WithdrawalCircuit<F, C, D>
where
    F: RichField + Extendable<D>,
    C: GenericConfig<D, F = F> + 'static,
    C::Hasher: AlgebraicHasher<F>,
{
    pub fn new(withdrawal_innser_circuit: &WithdrawalInnerCircuit<F, C, D>) -> Self {
        let mut builder = CircuitBuilder::<F, D>::new(CircuitConfig::default());
        let is_first_step = builder.add_virtual_bool_target_safe();
        let is_not_first_step = builder.not(is_first_step);
        let withdrawal_inner_proof =
            withdrawal_innser_circuit.add_proof_target_and_verify(&mut builder);
        let prev_withdrawal_hash =
            Bytes32Target::from_limbs(&withdrawal_inner_proof.public_inputs[0..BYTES32_LEN]);
        let withdrawal_hash =
            Bytes32Target::from_limbs(&withdrawal_inner_proof.public_inputs[BYTES32_LEN..]);
        builder.register_public_inputs(&withdrawal_hash.to_vec());

        let common_data = common_data_for_withdrawal_circuit::<F, C, D>();
        let verifier_data_target = builder.add_verifier_data_public_inputs();

        let prev_proof = builder.add_virtual_proof_with_pis(&common_data);
        builder
            .conditionally_verify_cyclic_proof_or_dummy::<C>(
                is_not_first_step,
                &prev_proof,
                &common_data,
            )
            .unwrap();
        let prev_pis = Bytes32Target::from_limbs(&prev_proof.public_inputs[0..BYTES32_LEN]);
        prev_pis.connect(&mut builder, prev_withdrawal_hash);
        // initial condition
        let zero = Bytes32Target::zero::<F, D, Bytes32>(&mut builder);
        prev_withdrawal_hash.conditional_assert_eq(&mut builder, zero, is_first_step);

        let (data, success) = builder.try_build_with_options::<C>(true);
        assert_eq!(data.common, common_data);
        assert!(success);
        Self {
            data,
            is_first_step,
            withdrawal_inner_proof,
            prev_proof,
            verifier_data_target,
        }
    }

    pub fn prove(
        &self,
        withdrawal_inner_proof: &ProofWithPublicInputs<F, C, D>,
        prev_proof: &Option<ProofWithPublicInputs<F, C, D>>,
    ) -> Result<ProofWithPublicInputs<F, C, D>> {
        let mut pw = PartialWitness::<F>::new();
        pw.set_verifier_data_target(&self.verifier_data_target, &self.data.verifier_only);
        pw.set_proof_with_pis_target(&self.withdrawal_inner_proof, withdrawal_inner_proof);
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

    pub(crate) fn add_proof_target_and_verify(
        &self,
        builder: &mut CircuitBuilder<F, D>,
    ) -> ProofWithPublicInputsTarget<D> {
        let proof = builder.add_virtual_proof_with_pis(&self.data.common);
        let vd_target = builder.constant_verifier_data(&self.data.verifier_only);
        let inner_vd_target =
            vd_from_pis_slice_target(&proof.public_inputs, &self.data.common.config).unwrap();
        builder.connect_hashes(vd_target.circuit_digest, inner_vd_target.circuit_digest);
        builder.connect_merkle_caps(
            &vd_target.constants_sigmas_cap,
            &inner_vd_target.constants_sigmas_cap,
        );
        builder.verify_proof::<C>(&proof, &vd_target, &self.data.common);
        proof
    }
}

// Generates `CommonCircuitData` usable for recursion.
pub fn common_data_for_withdrawal_circuit<
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
