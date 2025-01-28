use hashbrown::HashMap;
use plonky2::{
    field::{extension::Extendable, types::PrimeField64},
    gates::noop::NoopGate,
    hash::hash_types::RichField,
    iop::{
        target::{BoolTarget, Target},
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
    common::trees::nullifier_tree::NullifierTree,
    constants::CYCLIC_CIRCUIT_PADDING_DEGREE,
    utils::{
        conversion::ToU64,
        cyclic::vd_vec_len,
        poseidon_hash_out::{PoseidonHashOut, PoseidonHashOutTarget, POSEIDON_HASH_OUT_LEN},
    },
};

use super::innocence_inner_target::{InnocenceInnerTarget, InnocenceInnerValue};

pub const INNOCENCE_PUBLIC_INPUTS_LEN: usize = 1 + 3 * POSEIDON_HASH_OUT_LEN;

#[derive(Clone, Debug)]
pub struct InnocencePublicInputs {
    pub use_allow_list: bool,
    pub allow_list_tree_root: PoseidonHashOut,
    pub deny_list_tree_root: PoseidonHashOut,
    pub nullifier_tree_root: PoseidonHashOut,
}

impl InnocencePublicInputs {
    pub fn to_u64_vec(&self) -> Vec<u64> {
        let vec = vec![self.use_allow_list as u64]
            .into_iter()
            .chain(self.allow_list_tree_root.to_u64_vec().into_iter())
            .chain(self.deny_list_tree_root.to_u64_vec().into_iter())
            .chain(self.nullifier_tree_root.to_u64_vec().into_iter())
            .collect::<Vec<_>>();
        assert_eq!(vec.len(), INNOCENCE_PUBLIC_INPUTS_LEN);
        vec
    }

    pub fn from_u64_slice(slice: &[u64]) -> Self {
        assert_eq!(slice.len(), INNOCENCE_PUBLIC_INPUTS_LEN);
        let use_allow_list = slice[0] != 0;
        let allow_list_tree_root =
            PoseidonHashOut::from_u64_slice(&slice[1..1 + POSEIDON_HASH_OUT_LEN]);
        let deny_list_tree_root = PoseidonHashOut::from_u64_slice(
            &slice[1 + POSEIDON_HASH_OUT_LEN..1 + 2 * POSEIDON_HASH_OUT_LEN],
        );
        let nullifier_tree_root = PoseidonHashOut::from_u64_slice(
            &slice[1 + 2 * POSEIDON_HASH_OUT_LEN..1 + 3 * POSEIDON_HASH_OUT_LEN],
        );
        Self {
            use_allow_list,
            allow_list_tree_root,
            deny_list_tree_root,
            nullifier_tree_root,
        }
    }

    pub fn from_pis<F: PrimeField64>(pis: &[F]) -> Self {
        Self::from_u64_slice(&pis[0..INNOCENCE_PUBLIC_INPUTS_LEN].to_u64_vec())
    }
}

#[derive(Clone, Debug)]
pub struct InnocencePublicInputsTarget {
    pub use_allow_list: BoolTarget,
    pub allow_list_tree_root: PoseidonHashOutTarget,
    pub deny_list_tree_root: PoseidonHashOutTarget,
    pub nullifier_tree_root: PoseidonHashOutTarget,
}

impl InnocencePublicInputsTarget {
    pub fn to_vec(&self) -> Vec<Target> {
        let vec = vec![self.use_allow_list.target]
            .into_iter()
            .chain(self.allow_list_tree_root.to_vec().into_iter())
            .chain(self.deny_list_tree_root.to_vec().into_iter())
            .chain(self.nullifier_tree_root.to_vec().into_iter())
            .collect::<Vec<_>>();
        assert_eq!(vec.len(), INNOCENCE_PUBLIC_INPUTS_LEN);
        vec
    }

    pub fn from_slice(slice: &[Target]) -> Self {
        assert_eq!(slice.len(), INNOCENCE_PUBLIC_INPUTS_LEN);
        let use_allow_list = BoolTarget::new_unsafe(slice[0]);
        let allow_list_tree_root =
            PoseidonHashOutTarget::from_slice(&slice[1..1 + POSEIDON_HASH_OUT_LEN]);
        let deny_list_tree_root = PoseidonHashOutTarget::from_slice(
            &slice[1 + POSEIDON_HASH_OUT_LEN..1 + 2 * POSEIDON_HASH_OUT_LEN],
        );
        let nullifier_tree_root = PoseidonHashOutTarget::from_slice(
            &slice[1 + 2 * POSEIDON_HASH_OUT_LEN..1 + 3 * POSEIDON_HASH_OUT_LEN],
        );
        Self {
            use_allow_list,
            allow_list_tree_root,
            deny_list_tree_root,
            nullifier_tree_root,
        }
    }

    pub fn from_pis(pis: &[Target]) -> Self {
        Self::from_slice(&pis[0..INNOCENCE_PUBLIC_INPUTS_LEN])
    }
}

pub struct InnocenceCircuit<F, C, const D: usize>
where
    F: RichField + Extendable<D>,
    C: GenericConfig<D, F = F>,
{
    is_first_step: BoolTarget,
    inner_target: InnocenceInnerTarget,
    prev_proof: ProofWithPublicInputsTarget<D>,
    verifier_data_target: VerifierCircuitTarget,
    data: CircuitData<F, C, D>,
}

impl<F, C, const D: usize> InnocenceCircuit<F, C, D>
where
    F: RichField + Extendable<D>,
    C: GenericConfig<D, F = F> + 'static,
    C::Hasher: AlgebraicHasher<F>,
{
    pub fn new() -> Self {
        let mut builder = CircuitBuilder::<F, D>::new(CircuitConfig::default());
        let is_first_step = builder.add_virtual_bool_target_safe();
        let is_not_first_step = builder.not(is_first_step);
        let inner_target = InnocenceInnerTarget::new::<F, C, D>(&mut builder, true);
        let pis = InnocencePublicInputsTarget {
            use_allow_list: inner_target.use_allow_list,
            allow_list_tree_root: inner_target.allow_list_tree_root,
            deny_list_tree_root: inner_target.deny_list_tree_root,
            nullifier_tree_root: inner_target.new_nullifier_tree_root,
        };
        builder.register_public_inputs(&pis.to_vec());

        let common_data = common_data_for_innocence_circuit::<F, C, D>();
        let verifier_data_target = builder.add_verifier_data_public_inputs();

        let prev_proof = builder.add_virtual_proof_with_pis(&common_data);
        builder
            .conditionally_verify_cyclic_proof_or_dummy::<C>(
                is_not_first_step,
                &prev_proof,
                &common_data,
            )
            .unwrap();
        let prev_pis = InnocencePublicInputsTarget::from_pis(&prev_proof.public_inputs);

        // connect
        builder.connect(
            prev_pis.use_allow_list.target,
            inner_target.use_allow_list.target,
        );
        prev_pis
            .allow_list_tree_root
            .connect(&mut builder, inner_target.allow_list_tree_root);
        prev_pis
            .deny_list_tree_root
            .connect(&mut builder, inner_target.deny_list_tree_root);
        prev_pis
            .nullifier_tree_root
            .connect(&mut builder, inner_target.prev_nullifier_tree_root);

        let initial_nullifier_tree_root = NullifierTree::new().get_root();
        let initial_nullifier_tree_root_target =
            PoseidonHashOutTarget::constant(&mut builder, initial_nullifier_tree_root);
        prev_pis.nullifier_tree_root.conditional_assert_eq(
            &mut builder,
            initial_nullifier_tree_root_target,
            is_first_step,
        );

        let (data, success) = builder.try_build_with_options::<C>(true);
        assert_eq!(data.common, common_data);
        assert!(success);

        Self {
            is_first_step,
            inner_target,
            prev_proof,
            verifier_data_target,
            data,
        }
    }

    pub fn prove(
        &self,
        inner_value: &InnocenceInnerValue,
        prev_proof: &Option<ProofWithPublicInputs<F, C, D>>,
    ) -> anyhow::Result<ProofWithPublicInputs<F, C, D>> {
        let mut pw = PartialWitness::<F>::new();
        pw.set_verifier_data_target(&self.verifier_data_target, &self.data.verifier_only);
        self.inner_target.set_witness(&mut pw, inner_value);
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

fn common_data_for_innocence_circuit<
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
    common.num_public_inputs = INNOCENCE_PUBLIC_INPUTS_LEN + vd_vec_len(&common.config);
    common
}
