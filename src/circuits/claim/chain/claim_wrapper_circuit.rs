use plonky2::{
    field::extension::Extendable,
    hash::hash_types::RichField,
    iop::{
        target::Target,
        witness::{PartialWitness, WitnessWrite as _},
    },
    plonk::{
        circuit_builder::CircuitBuilder,
        circuit_data::{CircuitConfig, CircuitData, VerifierCircuitData},
        config::{AlgebraicHasher, GenericConfig},
        proof::{ProofWithPublicInputs, ProofWithPublicInputsTarget},
    },
};
use plonky2_keccak::{builder::BuilderKeccak256 as _, utils::solidity_keccak256};
use serde::{Deserialize, Serialize};

use crate::{
    ethereum_types::{
        address::{Address, AddressTarget},
        bytes32::{Bytes32, Bytes32Target, BYTES32_LEN},
        u32limb_trait::{U32LimbTargetTrait as _, U32LimbTrait},
    },
    utils::recursively_verifiable::add_proof_target_and_verify_cyclic,
};

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ClaimProofPublicInputs {
    pub last_claim_hash: Bytes32,
    pub claim_aggregator: Address,
}

impl ClaimProofPublicInputs {
    pub fn to_u32_vec(&self) -> Vec<u32> {
        [
            self.last_claim_hash.to_u32_vec(),
            self.claim_aggregator.to_u32_vec(),
        ]
        .concat()
    }

    pub fn hash(&self) -> Bytes32 {
        Bytes32::from_u32_slice(&solidity_keccak256(&self.to_u32_vec()))
    }
}

#[derive(Debug, Clone)]
struct ClaimProofPublicInputsTarget {
    last_claim_hash: Bytes32Target,
    claim_aggregator: AddressTarget,
}

impl ClaimProofPublicInputsTarget {
    fn to_vec(&self) -> Vec<Target> {
        [
            self.last_claim_hash.to_vec(),
            self.claim_aggregator.to_vec(),
        ]
        .concat()
    }

    fn hash<F: RichField + Extendable<D>, C: GenericConfig<D, F = F> + 'static, const D: usize>(
        &self,
        builder: &mut CircuitBuilder<F, D>,
    ) -> Bytes32Target
    where
        <C as GenericConfig<D>>::Hasher: AlgebraicHasher<F>,
    {
        Bytes32Target::from_slice(&builder.keccak256::<C>(&self.to_vec()))
    }
}

#[derive(Debug)]
pub struct ClaimWrapperCircuit<F, C, const D: usize>
where
    F: RichField + Extendable<D>,
    C: GenericConfig<D, F = F>,
{
    pub data: CircuitData<F, C, D>,
    claim_proof: ProofWithPublicInputsTarget<D>,
    claim_aggregator: AddressTarget, // Who makes the claim proof and receive the reward
}

impl<F, C, const D: usize> ClaimWrapperCircuit<F, C, D>
where
    F: RichField + Extendable<D>,
    C: GenericConfig<D, F = F> + 'static,
    C::Hasher: AlgebraicHasher<F>,
{
    pub fn new(claim_verifier_data: &VerifierCircuitData<F, C, D>) -> Self {
        let mut builder = CircuitBuilder::<F, D>::new(CircuitConfig::default());
        let claim_proof = add_proof_target_and_verify_cyclic(claim_verifier_data, &mut builder);
        let last_claim_hash = Bytes32Target::from_slice(&claim_proof.public_inputs[0..BYTES32_LEN]);
        let claim_aggregator = AddressTarget::new(&mut builder, true);
        let pis = ClaimProofPublicInputsTarget {
            last_claim_hash,
            claim_aggregator,
        };
        let pis_hash = pis.hash::<F, C, D>(&mut builder);
        builder.register_public_inputs(&pis_hash.to_vec());
        let data = builder.build();
        Self {
            data,
            claim_proof,
            claim_aggregator,
        }
    }

    pub fn prove(
        &self,
        claim_proof: &ProofWithPublicInputs<F, C, D>,
        claim_aggregator: Address,
    ) -> anyhow::Result<ProofWithPublicInputs<F, C, D>> {
        let mut pw = PartialWitness::<F>::new();
        pw.set_proof_with_pis_target(&self.claim_proof, claim_proof);
        self.claim_aggregator.set_witness(&mut pw, claim_aggregator);
        self.data.prove(pw)
    }
}
