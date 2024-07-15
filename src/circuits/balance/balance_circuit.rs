use anyhow::Result;
use plonky2::{
    field::extension::Extendable,
    gates::noop::NoopGate,
    hash::hash_types::RichField,
    iop::{
        target::{BoolTarget, Target},
        witness::{PartialWitness, WitnessWrite as _},
    },
    plonk::{
        circuit_builder::CircuitBuilder,
        circuit_data::{
            CircuitConfig, CircuitData, CommonCircuitData, VerifierCircuitData,
            VerifierCircuitTarget, VerifierOnlyCircuitData,
        },
        config::{AlgebraicHasher, GenericConfig},
        proof::{ProofWithPublicInputs, ProofWithPublicInputsTarget},
    },
    recursion::{
        cyclic_recursion::check_cyclic_proof_verifier_data, dummy_circuit::cyclic_base_proof,
    },
};

use crate::{
    circuits::{balance::balance_pis::BalancePublicInputsTarget, utils::cyclic::vd_vec_len},
    common::{
        insufficient_flags::{InsufficientFlags, InsufficientFlagsTarget},
        private_state::PrivateState,
        public_state::{PublicState, PublicStateTarget},
    },
    constants::BALANCE_CIRCUIT_PADDING_DEGREE,
    ethereum_types::{u256::U256, u32limb_trait::U32LimbTargetTrait},
    utils::{
        conversion::ToField as _,
        poseidon_hash_out::{PoseidonHashOut, PoseidonHashOutTarget},
        recursivable::Recursivable as _,
    },
};

use super::{
    balance_pis::{BalancePublicInputs, BALANCE_PUBLIC_INPUTS_LEN},
    transition::transition_circuit::BalanceTransitionCircuit,
};

use crate::circuits::utils::cyclic::vd_from_pis_slice_target;

#[derive(Debug)]
pub struct BalanceCircuit<F, C, const D: usize>
where
    F: RichField + Extendable<D>,
    C: GenericConfig<D, F = F>,
{
    data: CircuitData<F, C, D>,
    is_first_step: BoolTarget,
    pubkey: U256<Target>,
    transition_proof: ProofWithPublicInputsTarget<D>,
    prev_proof: ProofWithPublicInputsTarget<D>,
    verifier_data_target: VerifierCircuitTarget,
}

impl<F, C, const D: usize> BalanceCircuit<F, C, D>
where
    F: RichField + Extendable<D>,
    C: GenericConfig<D, F = F> + 'static,
    C::Hasher: AlgebraicHasher<F>,
{
    pub fn new(balance_transition_circuit: &BalanceTransitionCircuit<F, C, D>) -> Self {
        let mut builder = CircuitBuilder::<F, D>::new(CircuitConfig::default());
        let is_first_step = builder.add_virtual_bool_target_safe();
        let is_not_first_step = builder.not(is_first_step);

        let transition_proof = balance_transition_circuit.add_proof_target_and_verify(&mut builder);

        let prev_pis_ = BalancePublicInputsTarget::from_vec(
            &transition_proof.public_inputs[0..BALANCE_PUBLIC_INPUTS_LEN],
        );
        let new_pis = BalancePublicInputsTarget::from_vec(
            &transition_proof.public_inputs
                [BALANCE_PUBLIC_INPUTS_LEN..2 * BALANCE_PUBLIC_INPUTS_LEN],
        );
        let inner_balance_vd = vd_from_pis_slice_target(
            &transition_proof.public_inputs,
            &balance_transition_circuit.data.common.config,
        )
        .expect("Failed to parse inner balance vd");
        builder.register_public_inputs(&new_pis.to_vec());

        let common_data = common_data_for_balance_circuit::<F, C, D>();
        let verifier_data_target = builder.add_verifier_data_public_inputs();
        builder.connect_verifier_data(&inner_balance_vd, &verifier_data_target);

        let prev_proof = builder.add_virtual_proof_with_pis(&common_data);
        builder
            .conditionally_verify_cyclic_proof_or_dummy::<C>(
                is_not_first_step,
                &prev_proof,
                &common_data,
            )
            .unwrap();
        let prev_pis = BalancePublicInputsTarget::from_vec(
            &prev_proof.public_inputs[0..BALANCE_PUBLIC_INPUTS_LEN],
        );
        prev_pis.connect(&mut builder, &prev_pis_);

        let initial_private_commitment =
            PoseidonHashOutTarget::constant(&mut builder, PrivateState::new().commitment());
        let initial_last_tx_hash =
            PoseidonHashOutTarget::constant(&mut builder, PoseidonHashOut::default());
        let intitial_public_state =
            PublicStateTarget::constant(&mut builder, &PublicState::genesis());
        let initial_last_tx_insufficient_flags =
            InsufficientFlagsTarget::constant(&mut builder, InsufficientFlags::default());
        let pubkey = U256::<Target>::new(&mut builder, true);
        let initial_balance_pis = BalancePublicInputsTarget {
            pubkey,
            private_commitment: initial_private_commitment,
            last_tx_hash: initial_last_tx_hash,
            last_tx_insufficient_flags: initial_last_tx_insufficient_flags,
            public_state: intitial_public_state,
        };
        prev_pis.conditional_assert_eq(&mut builder, &initial_balance_pis, is_first_step);

        let (data, success) = builder.try_build_with_options::<C>(true);
        assert_eq!(data.common, common_data);
        assert!(success);
        Self {
            data,
            is_first_step,
            pubkey,
            transition_proof,
            prev_proof,
            verifier_data_target,
        }
    }

    pub fn prove(
        &self,
        pubkey: U256<u32>,
        transition_proof: &ProofWithPublicInputs<F, C, D>,
        prev_proof: &Option<ProofWithPublicInputs<F, C, D>>,
    ) -> Result<ProofWithPublicInputs<F, C, D>> {
        // assertion of public inputs equivalence
        let transition_prev_balance_pis =
            BalancePublicInputs::from_pis(&transition_proof.public_inputs);
        if prev_proof.is_some() {
            let prev_balance_pis =
                BalancePublicInputs::from_pis(&prev_proof.as_ref().unwrap().public_inputs);
            assert_eq!(transition_prev_balance_pis, prev_balance_pis);
        } else {
            let initial_balance_pis = BalancePublicInputs::new(pubkey);
            assert_eq!(transition_prev_balance_pis, initial_balance_pis);
        }

        let mut pw = PartialWitness::<F>::new();
        pw.set_verifier_data_target(&self.verifier_data_target, &self.data.verifier_only);
        pw.set_proof_with_pis_target(&self.transition_proof, transition_proof);
        self.pubkey.set_witness(&mut pw, pubkey);
        if prev_proof.is_none() {
            let dummy_proof = cyclic_base_proof(
                &self.data.common,
                &self.data.verifier_only,
                BalancePublicInputs::new(pubkey)
                    .to_u64_vec()
                    .to_field_vec::<F>()
                    .into_iter()
                    .enumerate()
                    .collect(),
            );
            pw.set_bool_target(self.is_first_step, true);
            pw.set_proof_with_pis_target(&self.prev_proof, &dummy_proof);
        } else {
            pw.set_bool_target(self.is_first_step, false);
            pw.set_proof_with_pis_target(&self.prev_proof, prev_proof.as_ref().unwrap());
        }
        self.data.prove(pw)
    }

    pub fn get_verifier_only_data(&self) -> VerifierOnlyCircuitData<C, D> {
        self.data.verifier_only.clone()
    }

    pub fn get_verifier_data(&self) -> VerifierCircuitData<F, C, D> {
        self.data.verifier_data()
    }

    pub fn verify(&self, proof: &ProofWithPublicInputs<F, C, D>) -> Result<()> {
        check_cyclic_proof_verifier_data(&proof, &self.data.verifier_only, &self.data.common)?;
        self.data.verify(proof.clone())
    }

    pub fn add_proof_target_and_verify(
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
pub fn common_data_for_balance_circuit<
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
    while builder.num_gates() < 1 << BALANCE_CIRCUIT_PADDING_DEGREE {
        builder.add_gate(NoopGate, vec![]);
    }
    let mut common = builder.build::<C>().common;
    common.num_public_inputs = BALANCE_PUBLIC_INPUTS_LEN + vd_vec_len(&common.config);
    common
}
