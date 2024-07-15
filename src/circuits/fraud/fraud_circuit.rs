use anyhow::Result;
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
        config::{AlgebraicHasher, GenericConfig},
        proof::{ProofWithPublicInputs, ProofWithPublicInputsTarget},
    },
};
use plonky2_keccak::{builder::BuilderKeccak256 as _, utils::solidity_keccak256};

use crate::{
    circuits::validity::{
        validity_circuit::ValidityCircuit, validity_pis::ValidityPublicInputsTarget,
    },
    ethereum_types::{
        address::{Address, ADDRESS_LEN},
        bytes32::{Bytes32, BYTES32_LEN},
        u32limb_trait::{U32LimbTargetTrait as _, U32LimbTrait},
    },
    utils::recursivable::Recursivable,
};

pub const FRAUD_PROOF_PUBLIC_INPUTS_LEN: usize = BYTES32_LEN + 1 + ADDRESS_LEN;

#[derive(Clone, Debug)]
pub struct FraudProofPublicInputs {
    pub block_hash: Bytes32<u32>,
    pub block_number: u32,
    pub challenger: Address<u32>,
}

impl FraudProofPublicInputs {
    pub fn to_u32_vec(&self) -> Vec<u32> {
        let vec = vec![
            self.block_hash.limbs(),
            vec![self.block_number],
            self.challenger.limbs(),
        ]
        .concat();
        assert_eq!(vec.len(), FRAUD_PROOF_PUBLIC_INPUTS_LEN);
        vec
    }

    pub fn hash(&self) -> Bytes32<u32> {
        Bytes32::<u32>::from_limbs(&solidity_keccak256(&self.to_u32_vec()))
    }
}

#[derive(Clone, Debug)]
pub struct FraudProofPublicInputsTarget {
    pub block_hash: Bytes32<Target>,
    pub block_number: Target,
    pub challenger: Address<Target>,
}

impl FraudProofPublicInputsTarget {
    pub fn to_vec(&self) -> Vec<Target> {
        let vec = vec![
            self.block_hash.to_vec(),
            vec![self.block_number],
            self.challenger.to_vec(),
        ]
        .concat();
        assert_eq!(vec.len(), FRAUD_PROOF_PUBLIC_INPUTS_LEN);
        vec
    }

    pub fn hash<
        F: RichField + Extendable<D>,
        C: GenericConfig<D, F = F> + 'static,
        const D: usize,
    >(
        &self,
        builder: &mut CircuitBuilder<F, D>,
    ) -> Bytes32<Target>
    where
        <C as GenericConfig<D>>::Hasher: AlgebraicHasher<F>,
    {
        Bytes32::<Target>::from_limbs(&builder.keccak256::<C>(&self.to_vec()))
    }
}

pub struct FraudCircuit<F: RichField + Extendable<D>, C: GenericConfig<D, F = F>, const D: usize> {
    pub validity_proof: ProofWithPublicInputsTarget<D>,
    pub challenger: Address<Target>,
    pub data: CircuitData<F, C, D>,
}

impl<F: RichField + Extendable<D>, C: GenericConfig<D, F = F> + 'static, const D: usize>
    FraudCircuit<F, C, D>
where
    <C as GenericConfig<D>>::Hasher: AlgebraicHasher<F>,
{
    pub fn new(validity_circuit: &ValidityCircuit<F, C, D>) -> Self {
        let mut builder = CircuitBuilder::<F, D>::new(CircuitConfig::default());
        let validity_proof = validity_circuit.add_proof_target_and_verify(&mut builder);
        let validity_pis = ValidityPublicInputsTarget::from_pis(&validity_proof.public_inputs);
        let challenger = Address::<Target>::new(&mut builder, true);
        builder.assert_zero(validity_pis.is_valid_block.target);
        let pis = FraudProofPublicInputsTarget {
            block_hash: validity_pis.public_state.block_hash,
            block_number: validity_pis.public_state.block_number,
            challenger,
        };
        let pis_hash = pis.hash::<F, C, D>(&mut builder);
        builder.register_public_inputs(&pis_hash.to_vec());
        let data = builder.build();
        Self {
            validity_proof,
            challenger,
            data,
        }
    }

    pub fn prove(
        &self,
        challenger: Address<u32>,
        validity_proof: &ProofWithPublicInputs<F, C, D>,
    ) -> Result<ProofWithPublicInputs<F, C, D>> {
        let mut pw = PartialWitness::<F>::new();
        pw.set_proof_with_pis_target(&self.validity_proof, validity_proof);
        self.challenger.set_witness(&mut pw, challenger);
        self.data.prove(pw)
    }
}

impl<F: RichField + Extendable<D>, C: GenericConfig<D, F = F> + 'static, const D: usize>
    Recursivable<F, C, D> for FraudCircuit<F, C, D>
where
    <C as GenericConfig<D>>::Hasher: AlgebraicHasher<F>,
{
    fn circuit_data(&self) -> &CircuitData<F, C, D> {
        &self.data
    }
}
