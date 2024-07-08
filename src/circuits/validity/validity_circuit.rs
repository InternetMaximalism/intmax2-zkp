use anyhow::Result;
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
    circuits::validity::validity_pis::{
        ValidityPublicInputs, ValidityPublicInputsTarget, VALIDITY_PUBLIC_INPUTS_LEN,
    },
    constants::VALIDITY_CIRCUIT_PADDING_DEGREE,
    utils::recursivable::Recursivable as _,
};

#[cfg(not(feature = "dummy_validity_proof"))]
use super::transition::wrapper::TransitionWrapperCircuit;

#[cfg(feature = "dummy_validity_proof")]
use crate::circuits::validity::transition::dummy_wrapper::DummyTransitionWrapperCircuit;

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
    pub fn new(
        #[cfg(not(feature = "dummy_validity_proof"))]
        validity_wrap_circuit: &TransitionWrapperCircuit<F, C, D>,
        #[cfg(feature = "dummy_validity_proof")]
        dummy_validity_wrap_circuit: &DummyTransitionWrapperCircuit<F, C, D>,
    ) -> Self {
        let mut builder = CircuitBuilder::<F, D>::new(CircuitConfig::default());
        let is_first_step = builder.add_virtual_bool_target_safe();
        let is_not_first_step = builder.not(is_first_step);

        #[cfg(not(feature = "dummy_validity_proof"))]
        let transition_proof = validity_wrap_circuit.add_proof_target_and_verify(&mut builder);
        #[cfg(feature = "dummy_validity_proof")]
        let transition_proof =
            dummy_validity_wrap_circuit.add_proof_target_and_verify(&mut builder);

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

        let (data, success) = builder.try_build_with_options::<C>(true);
        assert_eq!(data.common, common_data);
        assert!(success);
        Self {
            data,
            is_first_step,
            transition_proof,
            prev_proof,
            verifier_data_target,
        }
    }

    pub fn prove(
        &self,
        transition_proof: &ProofWithPublicInputs<F, C, D>,
        prev_proof: &Option<ProofWithPublicInputs<F, C, D>>,
    ) -> Result<ProofWithPublicInputs<F, C, D>> {
        let mut pw = PartialWitness::<F>::new();
        pw.set_verifier_data_target(&self.verifier_data_target, &self.data.verifier_only);
        pw.set_proof_with_pis_target(&self.transition_proof, transition_proof);
        if prev_proof.is_none() {
            let dummy_proof = cyclic_base_proof(
                &self.data.common,
                &self.data.verifier_only,
                ValidityPublicInputs::genesis()
                    .to_u64_vec()
                    .into_iter()
                    .map(F::from_canonical_u64)
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

    let mut builder = CircuitBuilder::<F, D>::new(CircuitConfig::default());
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
    type F = GoldilocksField;
    type C = PoseidonGoldilocksConfig;
    const D: usize = 2;
    use crate::{
        common::{signature::key_set::KeySet, tx::Tx},
        constants::NUM_SENDERS_IN_BLOCK,
        mock::{
            block_builder::{MockBlockBuilder, TxResuest},
            db::MockDB,
        },
    };
    use plonky2::{
        field::goldilocks_field::GoldilocksField, plonk::config::PoseidonGoldilocksConfig,
    };
    use rand::Rng;

    use super::ValidityCircuit;

    #[cfg(not(feature = "dummy_validity_proof"))]
    #[test]
    fn validity_circuit() {
        use crate::circuits::validity::transition::wrapper::TransitionWrapperCircuit;
        let mut rng = rand::thread_rng();
        let mut mock_db = MockDB::new();
        let block_builder = MockBlockBuilder;

        let transition_processor = TransitionProcessor::<F, C, D>::new();
        let txs = (0..NUM_SENDERS_IN_BLOCK)
            .map(|_| {
                let sender = KeySet::rand(&mut rng);
                TxResuest {
                    tx: Tx::rand(&mut rng),
                    sender,
                    will_return_signature: rng.gen_bool(0.5),
                }
            })
            .collect::<Vec<_>>();
        let block_info = block_builder.generate_block(&mut mock_db, true, txs);
        let block_witness = block_info.block_witness.clone();
        let transition_witness = block_builder.generate_transition_witness(&mut mock_db);
        let prev_block_witness = mock_db.get_last_block_witness();
        block_builder.update(&mut mock_db, &block_info); // this is not needed in this test
                                                         // but we add here to demonstrate that the block is updated after the transition

        let transition_proof = transition_processor
            .prove(&block_witness, &prev_block_witness, &transition_witness)
            .unwrap();

        let validity_circuit =
            ValidityCircuit::<F, C, D>::new(&transition_processor.transition_wrapper_circuit);
        validity_circuit.prove(&transition_proof, &None).unwrap();
    }

    #[cfg(feature = "dummy_validity_proof")]
    #[test]
    fn dummy_validity_circuit() {
        use crate::circuits::validity::transition::dummy_wrapper::DummyTransitionWrapperCircuit;

        let mut rng = rand::thread_rng();
        let mut mock_db = MockDB::new();
        let block_builder = MockBlockBuilder;

        let txs = (0..NUM_SENDERS_IN_BLOCK)
            .map(|_| {
                let sender = KeySet::rand(&mut rng);
                TxResuest {
                    tx: Tx::rand(&mut rng),
                    sender,
                    will_return_signature: rng.gen_bool(0.5),
                }
            })
            .collect::<Vec<_>>();
        let block_info = block_builder.generate_block(&mut mock_db, true, txs);
        let block_witness = block_info.block_witness.clone();
        let prev_block_witness = mock_db.get_last_block_witness();
        block_builder.update(&mut mock_db, &block_info); // this is not needed in this test
                                                         // but we add here to demonstrate that the block is updated after the transition

        let prev_pis = prev_block_witness.to_validity_pis();
        let new_pis = block_witness.to_validity_pis();
        let dummy_transition_wrapper = DummyTransitionWrapperCircuit::<F, C, D>::new();
        let transition_proof = dummy_transition_wrapper.prove(&prev_pis, &new_pis).unwrap();

        let validity_circuit = ValidityCircuit::<F, C, D>::new(&dummy_transition_wrapper);
        validity_circuit.prove(&transition_proof, &None).unwrap();
    }
}
