use std::marker::PhantomData;

use plonky2::{
    field::extension::Extendable,
    gates::{noop::NoopGate, random_access::RandomAccessGate},
    hash::hash_types::RichField,
    iop::{
        target::{BoolTarget, Target},
        witness::{PartialWitness, WitnessWrite},
    },
    plonk::{
        circuit_builder::CircuitBuilder,
        circuit_data::{CircuitConfig, CircuitData, CommonCircuitData, VerifierCircuitTarget},
        config::{AlgebraicHasher, GenericConfig},
        proof::{ProofWithPublicInputs, ProofWithPublicInputsTarget},
    },
    recursion::cyclic_recursion::check_cyclic_proof_verifier_data,
};
use plonky2_keccak::builder::BuilderKeccak256 as _;

use crate::{
    ethereum_types::{
        bytes32::{Bytes32, BYTES32_LEN},
        u32limb_trait::U32LimbTargetTrait as _,
    },
    utils::dummy::DummyProof,
};

use super::dynamic_leafable::DynamicLeafableCircuit;

pub struct DynamicTreeCircuit<F, C, const D: usize, InnerCircuit>
where
    F: RichField + Extendable<D>,
    C: GenericConfig<D, F = F> + 'static,
    C::Hasher: AlgebraicHasher<F>,
    InnerCircuit: DynamicLeafableCircuit<F, C, D>,
{
    pub data: CircuitData<F, C, D>,
    pub is_not_first_step: BoolTarget,
    pub leaf_proof: ProofWithPublicInputsTarget<D>,
    pub prev_left_proof: ProofWithPublicInputsTarget<D>,
    pub prev_right_proof: ProofWithPublicInputsTarget<D>,
    pub dummy_leaf: DummyProof<F, C, D>,
    pub dummy_node: DummyProof<F, C, D>,
    pub vd: VerifierCircuitTarget,
    _phantom: PhantomData<InnerCircuit>,
}

impl<F, C, const D: usize, InnerCircuit> DynamicTreeCircuit<F, C, D, InnerCircuit>
where
    F: RichField + Extendable<D>,
    C: GenericConfig<D, F = F> + 'static,
    C::Hasher: AlgebraicHasher<F>,
    InnerCircuit: DynamicLeafableCircuit<F, C, D>,
{
    pub fn new(inner_circuit: &InnerCircuit, common_data: &mut CommonCircuitData<F, D>) -> Self {
        let mut builder = CircuitBuilder::<F, D>::new(CircuitConfig::default());
        let cur_hash = Bytes32::<Target>::new(&mut builder, false);
        builder.register_public_inputs(&cur_hash.to_vec());

        let vd = builder.add_verifier_data_public_inputs();
        common_data.num_public_inputs = builder.num_public_inputs();

        let is_not_first_step = builder.add_virtual_bool_target_safe(); // whether this circuit uses recursive proof or not
        let is_first_step = builder.not(is_not_first_step);
        let leaf_proof =
            inner_circuit.add_proof_target_and_conditionally_verify(&mut builder, is_first_step);
        let prev_left_proof = builder.add_virtual_proof_with_pis(&common_data);
        let prev_right_proof = builder.add_virtual_proof_with_pis(&common_data);

        builder
            .conditionally_verify_cyclic_proof_or_dummy::<C>(
                is_not_first_step,
                &prev_left_proof,
                &common_data,
            )
            .unwrap();
        builder
            .conditionally_verify_cyclic_proof_or_dummy::<C>(
                is_not_first_step,
                &prev_right_proof,
                &common_data,
            )
            .unwrap();

        // in the case of leaf
        let leaf_hash = Bytes32::<Target>::from_limbs(&leaf_proof.public_inputs);

        // in the case of non-leaf
        let left_hash =
            Bytes32::<Target>::from_limbs(&prev_left_proof.public_inputs[0..BYTES32_LEN]);
        let right_hash =
            Bytes32::<Target>::from_limbs(&prev_right_proof.public_inputs[0..BYTES32_LEN]);
        let node_hash = Bytes32::<Target>::from_limbs(
            &builder.keccak256::<C>(&vec![left_hash.to_vec(), right_hash.to_vec()].concat()),
        );

        let next_hash = Bytes32::select(&mut builder, is_first_step, leaf_hash, node_hash);
        cur_hash.connect(&mut builder, next_hash);

        let (data, success) = builder.try_build_with_options(true);
        assert_eq!(&data.common, common_data);
        assert!(success);
        let dummy_leaf = inner_circuit.dummy_leaf();
        let dummy_node = DummyProof::<F, C, D>::new_cyclic(&data.common, &data.verifier_only);

        Self {
            data,
            is_not_first_step,
            leaf_proof,
            prev_left_proof,
            prev_right_proof,
            dummy_leaf,
            dummy_node,
            vd,
            _phantom: PhantomData,
        }
    }

    pub fn prove(
        &self,
        leaf_proof: Option<ProofWithPublicInputs<F, C, D>>,
        left_and_right_proof: Option<(
            ProofWithPublicInputs<F, C, D>,
            ProofWithPublicInputs<F, C, D>,
        )>,
    ) -> anyhow::Result<ProofWithPublicInputs<F, C, D>> {
        let mut pw = PartialWitness::new();
        pw.set_verifier_data_target(&self.vd, &self.data.verifier_only);
        if leaf_proof.is_some() {
            assert!(left_and_right_proof.is_none());
            pw.set_bool_target(self.is_not_first_step, false);
            pw.set_proof_with_pis_target(&self.leaf_proof, &leaf_proof.unwrap());
            pw.set_proof_with_pis_target(&self.prev_left_proof, &self.dummy_node.proof);
            pw.set_proof_with_pis_target(&self.prev_right_proof, &self.dummy_node.proof);
        } else {
            assert!(left_and_right_proof.is_some());
            pw.set_bool_target(self.is_not_first_step, true);
            let (left_proof, right_proof) = left_and_right_proof.unwrap();
            pw.set_proof_with_pis_target(&self.leaf_proof, &self.dummy_leaf.proof);
            pw.set_proof_with_pis_target(&self.prev_left_proof, &left_proof);
            pw.set_proof_with_pis_target(&self.prev_right_proof, &right_proof);
        }
        self.data.prove(pw)
    }

    pub fn verify(&self, proof_with_pis: ProofWithPublicInputs<F, C, D>) -> anyhow::Result<()> {
        check_cyclic_proof_verifier_data(
            &proof_with_pis,
            &self.data.verifier_only,
            &self.data.common,
        )?;
        self.data.verify(proof_with_pis)
    }
}

pub fn common_data_for_dynamic_tree_circuit<
    F: RichField + Extendable<D>,
    C: GenericConfig<D, F = F>,
    const D: usize,
>() -> CommonCircuitData<F, D>
where
    C::Hasher: AlgebraicHasher<F>,
{
    let config = CircuitConfig::standard_recursion_config();
    let builder = CircuitBuilder::<F, D>::new(config);
    let data = builder.build::<C>();

    let config = CircuitConfig::standard_recursion_config();
    let mut builder = CircuitBuilder::<F, D>::new(config);
    let proof = builder.add_virtual_proof_with_pis(&data.common);
    let verifier_data = VerifierCircuitTarget {
        constants_sigmas_cap: builder.add_virtual_cap(data.common.config.fri_config.cap_height),
        circuit_digest: builder.add_virtual_hash(),
    };
    builder.verify_proof::<C>(&proof, &verifier_data, &data.common);
    let data = builder.build::<C>();
    let config = CircuitConfig::standard_recursion_config();
    let mut builder = CircuitBuilder::<F, D>::new(config.clone());
    let proof = builder.add_virtual_proof_with_pis(&data.common);
    let verifier_data = VerifierCircuitTarget {
        constants_sigmas_cap: builder.add_virtual_cap(data.common.config.fri_config.cap_height),
        circuit_digest: builder.add_virtual_hash(),
    };
    builder.verify_proof::<C>(&proof, &verifier_data, &data.common);

    let random_access_gate = RandomAccessGate::<F, D>::new_from_config(&config, 1);
    builder.add_gate(random_access_gate, vec![]);
    while builder.num_gates() < 1 << 15 {
        builder.add_gate(NoopGate, vec![]);
    }
    builder.build::<C>().common
}

#[cfg(test)]
mod tests {
    use plonky2::{
        field::extension::Extendable,
        hash::hash_types::RichField,
        iop::{
            target::Target,
            witness::{PartialWitness, WitnessWrite},
        },
        plonk::{
            circuit_builder::CircuitBuilder,
            circuit_data::{CircuitConfig, CircuitData},
            config::{AlgebraicHasher, GenericConfig, PoseidonGoldilocksConfig},
            proof::ProofWithPublicInputs,
        },
    };

    use crate::{
        ethereum_types::{bytes32::Bytes32, u32limb_trait::U32LimbTargetTrait as _},
        utils::{
            dummy::DummyProof, poseidon_hash_out::PoseidonHashOutTarget,
            recursivable::Recursivable,
            trees::dynamic_tree::dynamic_leafable::DynamicLeafableCircuit,
        },
    };
    use plonky2::field::types::Field;

    use super::DynamicTreeCircuit;

    const D: usize = 2;
    type C = PoseidonGoldilocksConfig;
    type F = <C as GenericConfig<D>>::F;

    pub struct Acircuit<F, C, const D: usize>
    where
        F: RichField + Extendable<D>,
        C: GenericConfig<D, F = F>,
    {
        pub data: CircuitData<F, C, D>,
        pub target: Target,
    }

    impl<F, C, const D: usize> Acircuit<F, C, D>
    where
        F: RichField + Extendable<D>,
        C: GenericConfig<D, F = F> + 'static,
        C::Hasher: AlgebraicHasher<F>,
    {
        pub fn new() -> Self {
            let mut builder = CircuitBuilder::<F, D>::new(CircuitConfig::default());
            let target = builder.add_virtual_target();
            let hash_out = PoseidonHashOutTarget::hash_inputs(&mut builder, &[target]);
            let hash = Bytes32::from_hash_out(&mut builder, hash_out);
            builder.register_public_inputs(&hash.to_vec());
            let data = builder.build::<C>();
            Self { data, target }
        }

        pub fn prove(&self, input: F) -> ProofWithPublicInputs<F, C, D> {
            let mut pw = PartialWitness::new();
            pw.set_target(self.target, input);
            self.data.prove(pw).unwrap()
        }
    }

    impl<F, C, const D: usize> Recursivable<F, C, D> for Acircuit<F, C, D>
    where
        F: RichField + Extendable<D>,
        C: GenericConfig<D, F = F> + 'static,
        C::Hasher: AlgebraicHasher<F>,
    {
        fn circuit_data(&self) -> &CircuitData<F, C, D> {
            &self.data
        }
    }

    impl<F, C, const D: usize> DynamicLeafableCircuit<F, C, D> for Acircuit<F, C, D>
    where
        F: RichField + Extendable<D>,
        C: GenericConfig<D, F = F> + 'static,
        C::Hasher: AlgebraicHasher<F>,
    {
        fn dummy_leaf(&self) -> DummyProof<F, C, D> {
            DummyProof::new_cyclic(&self.data.common, &self.data.verifier_only)
        }
    }

    #[test]
    fn test_dynamic_tree_circuit() {
        let a_circuit = Acircuit::<F, C, D>::new();
        let mut common_data = super::common_data_for_dynamic_tree_circuit::<F, C, D>();
        let dynamic_tree_circuit =
            DynamicTreeCircuit::<F, C, D, _>::new(&a_circuit, &mut common_data);
        let leaf_proof0 = a_circuit.prove(F::ZERO);
        let leaf_proof1 = a_circuit.prove(F::ZERO);

        let left_proof = dynamic_tree_circuit.prove(Some(leaf_proof0), None).unwrap();
        let right_proof = dynamic_tree_circuit.prove(Some(leaf_proof1), None).unwrap();

        let root_proof = dynamic_tree_circuit
            .prove(None, Some((left_proof, right_proof)))
            .unwrap();
        dynamic_tree_circuit.verify(root_proof).unwrap();
    }
}
