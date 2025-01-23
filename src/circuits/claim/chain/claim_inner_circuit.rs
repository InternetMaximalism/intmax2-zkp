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
    common::claim::ClaimTarget,
    ethereum_types::{
        bytes32::{Bytes32, Bytes32Target},
        u32limb_trait::U32LimbTargetTrait,
    },
    utils::recursively_verifiable::add_proof_target_and_verify,
};

#[derive(Debug)]
pub struct ClaimInnerCircuit<F, C, const D: usize>
where
    F: RichField + Extendable<D>,
    C: GenericConfig<D, F = F>,
{
    pub data: CircuitData<F, C, D>,
    prev_claim_hash: Bytes32Target,
    single_claim_proof: ProofWithPublicInputsTarget<D>,
}

impl<F, C, const D: usize> ClaimInnerCircuit<F, C, D>
where
    F: RichField + Extendable<D>,
    C: GenericConfig<D, F = F> + 'static,
    C::Hasher: AlgebraicHasher<F>,
{
    pub fn new(single_claim_vd: &VerifierCircuitData<F, C, D>) -> Self {
        let mut builder = CircuitBuilder::<F, D>::new(CircuitConfig::default());
        let single_claim_proof = add_proof_target_and_verify(single_claim_vd, &mut builder);
        let claim = ClaimTarget::from_slice(&single_claim_proof.public_inputs);
        let prev_claim_hash = Bytes32Target::new(&mut builder, false); // connect later
        let claim_hash = claim.hash_with_prev_hash::<F, C, D>(&mut builder, prev_claim_hash);
        let pis = [prev_claim_hash.to_vec(), claim_hash.to_vec()].concat();
        builder.register_public_inputs(&pis);
        let data = builder.build();
        Self {
            data,
            prev_claim_hash,
            single_claim_proof,
        }
    }

    pub fn prove(
        &self,
        prev_claim_hash: Bytes32,
        single_claim_proof: &ProofWithPublicInputs<F, C, D>,
    ) -> anyhow::Result<ProofWithPublicInputs<F, C, D>> {
        let mut pw = PartialWitness::<F>::new();
        self.prev_claim_hash.set_witness(&mut pw, prev_claim_hash);
        pw.set_proof_with_pis_target(&self.single_claim_proof, single_claim_proof);
        self.data.prove(pw)
    }
}
