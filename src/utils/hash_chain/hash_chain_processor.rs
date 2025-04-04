use super::{
    chain_end_circuit::ChainEndCircuit, cyclic_chain_circuit::CyclicChainCircuit,
    error::{HashChainError, Result},
    hash_inner_circuit::HashInnerCircuit,
};
use plonky2::{
    field::extension::Extendable,
    hash::hash_types::RichField,
    plonk::{
        circuit_data::VerifierCircuitData,
        config::{AlgebraicHasher, GenericConfig},
        proof::ProofWithPublicInputs,
    },
};

use crate::{
    ethereum_types::{
        address::Address,
        bytes32::{Bytes32, BYTES32_LEN},
        u32limb_trait::U32LimbTrait as _,
    },
    utils::conversion::ToU64,
};


pub struct HashChainProcessor<F, C, const D: usize>
where
    F: RichField + Extendable<D>,
    C: GenericConfig<D, F = F>,
{
    pub inner_circuit: HashInnerCircuit<F, C, D>,
    pub cyclic_circuit: CyclicChainCircuit<F, C, D>,
    pub chain_end_circuit: ChainEndCircuit<F, C, D>,
}

impl<F, C, const D: usize> HashChainProcessor<F, C, D>
where
    F: RichField + Extendable<D>,
    C: GenericConfig<D, F = F> + 'static,
    C::Hasher: AlgebraicHasher<F>,
{
    pub fn new(single_vd: &VerifierCircuitData<F, C, D>) -> Self {
        let inner_circuit = HashInnerCircuit::new(single_vd);
        let cyclic_circuit = CyclicChainCircuit::new(&inner_circuit.data.verifier_data());
        let chain_end_circuit = ChainEndCircuit::new(&cyclic_circuit.data.verifier_data());
        Self {
            inner_circuit,
            cyclic_circuit,
            chain_end_circuit,
        }
    }

    // Prove a chain, given a single proof and the previous cyclic proof.
    pub fn prove_chain(
        &self,
        single_proof: &ProofWithPublicInputs<F, C, D>,
        prev_proof: &Option<ProofWithPublicInputs<F, C, D>>,
    ) -> Result<ProofWithPublicInputs<F, C, D>> {
        let prev_hash = if prev_proof.is_some() {
            Bytes32::from_u64_slice(
                &prev_proof.as_ref().unwrap().public_inputs[0..BYTES32_LEN].to_u64_vec(),
            ).expect("Converting from u64 slice should never fail")
        } else {
            Bytes32::default()
        };
        let inner_proof = self
            .inner_circuit
            .prove(prev_hash, single_proof)
            .map_err(|e| HashChainError::InnerProofError(e.to_string()))?;
        let cyclic_proof = self
            .cyclic_circuit
            .prove(&inner_proof, prev_proof)
            .map_err(|e| HashChainError::CyclicProofError(e.to_string()))?;
        Ok(cyclic_proof)
    }

    pub fn prove_end(
        &self,
        cyclic_proof: &ProofWithPublicInputs<F, C, D>,
        aggregator: Address,
    ) -> Result<ProofWithPublicInputs<F, C, D>> {
        let end_proof = self.chain_end_circuit.prove(cyclic_proof, aggregator)
            .map_err(|e| HashChainError::ChainEndProofError(e.to_string()))?;
        Ok(end_proof)
    }
}
