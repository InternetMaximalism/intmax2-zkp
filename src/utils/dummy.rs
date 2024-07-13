use plonky2::{
    field::extension::Extendable,
    hash::hash_types::RichField,
    iop::target::BoolTarget,
    plonk::{
        circuit_builder::CircuitBuilder,
        circuit_data::{CommonCircuitData, VerifierCircuitTarget, VerifierOnlyCircuitData},
        config::{AlgebraicHasher, GenericConfig},
        proof::{ProofWithPublicInputs, ProofWithPublicInputsTarget},
    },
    recursion::dummy_circuit::{cyclic_base_proof, dummy_circuit, dummy_proof},
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
    pub fn new(common: &CommonCircuitData<F, D>) -> Self {
        let data = dummy_circuit::<F, C, D>(&common);
        let proof = dummy_proof(&data, vec![].into_iter().enumerate().collect()).unwrap();
        Self { proof }
    }

    pub fn new_cyclic(
        common: &CommonCircuitData<F, D>,
        verifier_data: &VerifierOnlyCircuitData<C, D>,
    ) -> Self {
        let proof = cyclic_base_proof(
            &common,
            &verifier_data,
            vec![].into_iter().enumerate().collect(),
        );
        Self { proof }
    }
}

/// Conditionally verify a proof
/// Unlike `builder.conditionally_verify_proof`, when the condition is false,
/// you need to set the dummy proof.
pub fn conditionally_verify_proof<
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
