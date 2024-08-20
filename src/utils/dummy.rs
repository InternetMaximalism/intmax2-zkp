use plonky2::{
    field::extension::Extendable,
    gates::noop::NoopGate,
    hash::hash_types::RichField,
    iop::target::BoolTarget,
    plonk::{
        circuit_builder::CircuitBuilder,
        circuit_data::{CircuitData, CommonCircuitData, VerifierCircuitTarget},
        config::{AlgebraicHasher, GenericConfig},
        proof::{ProofWithPublicInputs, ProofWithPublicInputsTarget},
    },
    recursion::dummy_circuit::{dummy_circuit, dummy_proof},
};

#[derive(Debug, Clone)]
pub struct DummyProof<F, C, const D: usize>
where
    F: RichField + Extendable<D>,
    C: GenericConfig<D, F = F>,
{
    pub proof: ProofWithPublicInputs<F, C, D>,
}

impl<F, C, const D: usize> DummyProof<F, C, D>
where
    F: RichField + Extendable<D>,
    C: GenericConfig<D, F = F> + 'static,
    <C as GenericConfig<D>>::Hasher: AlgebraicHasher<F>,
{
    pub(crate) fn new(common: &CommonCircuitData<F, D>) -> Self {
        let data = dummy_circuit::<F, C, D>(&common);
        let proof = dummy_proof(&data, vec![].into_iter().enumerate().collect()).unwrap();
        Self { proof }
    }

    pub(crate) fn new_with_hiding_degree(
        common: &CommonCircuitData<F, D>,
        hiding_degree: usize,
    ) -> Self {
        let data = dummy_circuit_with_hiding_degree::<F, C, D>(&common, hiding_degree);
        let proof = dummy_proof(&data, vec![].into_iter().enumerate().collect()).unwrap();
        Self { proof }
    }
}

/// Generate a circuit matching a given `CommonCircuitData`.
pub fn dummy_circuit_with_hiding_degree<
    F: RichField + Extendable<D>,
    C: GenericConfig<D, F = F>,
    const D: usize,
>(
    common_data: &CommonCircuitData<F, D>,
    hiding_degree: usize,
) -> CircuitData<F, C, D> {
    let config = common_data.config.clone();

    // Number of `NoopGate`s to add to get a circuit of size `degree` in the end.
    // Need to account for public input hashing, a `PublicInputGate` and a `ConstantGate`.
    let degree = common_data.degree();

    let mut builder = CircuitBuilder::<F, D>::new(config.clone());

    let num_noop_gate = degree - common_data.num_public_inputs.div_ceil(8) - hiding_degree - 2;
    for _ in 0..num_noop_gate {
        builder.add_gate(NoopGate, vec![]);
    }

    for gate in &common_data.gates {
        builder.add_gate_to_gate_set(gate.clone());
    }
    for _ in 0..common_data.num_public_inputs {
        builder.add_virtual_public_input();
    }

    let circuit = builder.build::<C>();
    assert_eq!(&circuit.common, common_data);
    circuit
}

/// Conditionally verify a proof
/// Unlike `builder.conditionally_verify_proof`, when the condition is false,
/// you need to set the dummy proof.
pub(crate) fn conditionally_verify_proof<
    F: RichField + Extendable<D>,
    C: GenericConfig<D, F = F> + 'static,
    const D: usize,
>(
    builder: &mut CircuitBuilder<F, D>,
    condition: BoolTarget,
    proof_with_pis: &ProofWithPublicInputsTarget<D>,
    inner_verifier_data: &VerifierCircuitTarget,
    inner_common_data: &CommonCircuitData<F, D>,
) where
    C::Hasher: AlgebraicHasher<F>,
{
    let dummy_circuit = dummy_circuit::<F, C, D>(inner_common_data);
    let dummy_verifier_data_target = builder.constant_verifier_data(&dummy_circuit.verifier_only);
    let selected_verifier_data =
        builder.select_verifier_data(condition, inner_verifier_data, &dummy_verifier_data_target);
    builder.verify_proof::<C>(&proof_with_pis, &selected_verifier_data, inner_common_data);
}
