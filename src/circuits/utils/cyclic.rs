use anyhow::{ensure, Result};
use plonky2::{
    field::extension::Extendable,
    hash::{
        hash_types::{HashOut, HashOutTarget, MerkleCapTarget, RichField},
        merkle_tree::MerkleCap,
    },
    iop::target::{BoolTarget, Target},
    plonk::{
        circuit_builder::CircuitBuilder,
        circuit_data::{CircuitConfig, VerifierCircuitTarget, VerifierOnlyCircuitData},
        config::{AlgebraicHasher, GenericConfig, GenericHashOut as _},
    },
};

pub(crate) fn vd_vec_len(config: &CircuitConfig) -> usize {
    4 + 4 * config.fri_config.num_cap_elements()
}

pub(crate) fn vd_to_vec<
    F: RichField + Extendable<D>,
    C: GenericConfig<D, F = F>,
    const D: usize,
>(
    config: &CircuitConfig,
    vd: &VerifierOnlyCircuitData<C, D>,
) -> Vec<F> {
    let mut vec = vec![];
    vec.extend_from_slice(&vd.circuit_digest.to_vec());
    for i in 0..config.fri_config.num_cap_elements() {
        vec.extend_from_slice(&vd.constants_sigmas_cap.0[i].to_vec());
    }
    vec
}

pub(crate) fn vd_to_vec_target(config: &CircuitConfig, vd: &VerifierCircuitTarget) -> Vec<Target> {
    let mut vec = vec![];
    vec.extend_from_slice(&vd.circuit_digest.elements);
    for i in 0..config.fri_config.num_cap_elements() {
        vec.extend_from_slice(&vd.constants_sigmas_cap.0[i].elements);
    }
    vec
}

pub(crate) fn vd_from_pis_slice<
    F: RichField + Extendable<D>,
    C: GenericConfig<D, F = F>,
    const D: usize,
>(
    slice: &[F],
    config: &CircuitConfig,
) -> Result<VerifierOnlyCircuitData<C, D>>
where
    <C as GenericConfig<D>>::Hasher: AlgebraicHasher<F>,
{
    let cap_len = config.fri_config.num_cap_elements();
    let len = slice.len();
    ensure!(len >= 4 + 4 * cap_len, "Not enough public inputs");
    let constants_sigmas_cap = MerkleCap(
        (0..cap_len)
            .map(|i| HashOut {
                elements: core::array::from_fn(|j| slice[len - 4 * (cap_len - i) + j]),
            })
            .collect(),
    );
    let circuit_digest = HashOut {
        elements: core::array::from_fn(|i| slice[len - 4 - 4 * cap_len + i]),
    };
    Ok(VerifierOnlyCircuitData {
        circuit_digest,
        constants_sigmas_cap,
    })
}

pub(crate) fn vd_from_pis_slice_target(
    slice: &[Target],
    config: &CircuitConfig,
) -> Result<VerifierCircuitTarget> {
    let cap_len = config.fri_config.num_cap_elements();
    let len = slice.len();
    ensure!(len >= 4 + 4 * cap_len, "Not enough public inputs");
    let constants_sigmas_cap = MerkleCapTarget(
        (0..cap_len)
            .map(|i| HashOutTarget {
                elements: core::array::from_fn(|j| slice[len - 4 * (cap_len - i) + j]),
            })
            .collect(),
    );
    let circuit_digest = HashOutTarget {
        elements: core::array::from_fn(|i| slice[len - 4 - 4 * cap_len + i]),
    };
    Ok(VerifierCircuitTarget {
        circuit_digest,
        constants_sigmas_cap,
    })
}

pub(crate) fn conditionally_connect_vd<F: RichField + Extendable<D>, const D: usize>(
    builder: &mut CircuitBuilder<F, D>,
    condition: BoolTarget,
    vk0: &VerifierCircuitTarget,
    vk1: &VerifierCircuitTarget,
) {
    let selected_vd = builder.select_verifier_data(condition, vk0, vk1);
    builder.connect_verifier_data(&selected_vd, vk1);
}
