use plonky2::{
    field::extension::Extendable,
    hash::hash_types::RichField,
    iop::witness::{PartialWitness, WitnessWrite},
    plonk::{
        circuit_builder::CircuitBuilder,
        circuit_data::{CircuitConfig, CircuitData, VerifierCircuitData},
        config::{AlgebraicHasher, GenericConfig},
        proof::{ProofWithPublicInputs, ProofWithPublicInputsTarget},
    },
};

use crate::{
    ethereum_types::{
        bytes32::{Bytes32, Bytes32Target},
        u32limb_trait::U32LimbTargetTrait,
    },
    utils::recursively_verifiable::add_proof_target_and_verify,
};

use super::hash_with_prev_hash_circuit;

#[derive(Debug)]
pub struct HashInnerCircuit<F, C, const D: usize>
where
    F: RichField + Extendable<D>,
    C: GenericConfig<D, F = F>,
{
    pub data: CircuitData<F, C, D>,
    prev_hash: Bytes32Target,
    single_proof: ProofWithPublicInputsTarget<D>,
}

impl<F, C, const D: usize> HashInnerCircuit<F, C, D>
where
    F: RichField + Extendable<D>,
    C: GenericConfig<D, F = F> + 'static,
    C::Hasher: AlgebraicHasher<F>,
{
    pub fn new(single_vd: &VerifierCircuitData<F, C, D>) -> Self {
        let mut builder = CircuitBuilder::<F, D>::new(CircuitConfig::default());
        let single_proof = add_proof_target_and_verify(single_vd, &mut builder);
        let content = &single_proof.public_inputs.to_vec();
        let prev_hash = Bytes32Target::new(&mut builder, false); // connect later
        let hash = hash_with_prev_hash_circuit::<F, C, D>(&mut builder, content, prev_hash);
        let pis = [prev_hash.to_vec(), hash.to_vec()].concat();
        builder.register_public_inputs(&pis);
        let data = builder.build();
        Self {
            data,
            prev_hash,
            single_proof,
        }
    }

    pub fn prove(
        &self,
        prev_hash: Bytes32,
        single_proof: &ProofWithPublicInputs<F, C, D>,
    ) -> super::error::Result<ProofWithPublicInputs<F, C, D>> {
        let mut pw = PartialWitness::<F>::new();
        self.prev_hash.set_witness(&mut pw, prev_hash);
        pw.set_proof_with_pis_target(&self.single_proof, single_proof);
        self.data.prove(pw).map_err(|e| super::error::HashChainError::InnerProofError(e.to_string()))
    }
}
