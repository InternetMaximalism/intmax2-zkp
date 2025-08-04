use plonky2::{
    field::{extension::Extendable, types::PrimeField64},
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
        address::{Address, AddressTarget, ADDRESS_LEN},
        bytes32::{Bytes32, Bytes32Target, BYTES32_LEN},
        u32limb_trait::{U32LimbTargetTrait as _, U32LimbTrait},
    },
    utils::{conversion::ToU64 as _, recursively_verifiable::add_proof_target_and_verify_cyclic},
};

use super::error::HashChainError;

/// masked bits for use gnark circuit
pub const MASKED_BITS: usize = 3;
const CHAIN_END_PROOF_PUBLIC_INPUTS_LEN: usize = BYTES32_LEN + ADDRESS_LEN;

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ChainEndProofPublicInputs {
    pub last_hash: Bytes32,
    pub aggregator: Address,
}

impl ChainEndProofPublicInputs {
    pub fn to_u32_vec(&self) -> Vec<u32> {
        let vec = [self.last_hash.to_u32_vec(), self.aggregator.to_u32_vec()].concat();
        assert_eq!(vec.len(), CHAIN_END_PROOF_PUBLIC_INPUTS_LEN);
        vec
    }

    pub fn from_u32_slice(slice: &[u32]) -> Result<Self, HashChainError> {
        if slice.len() != CHAIN_END_PROOF_PUBLIC_INPUTS_LEN {
            return Err(HashChainError::InvalidData(format!(
                "Invalid input length for ChainEndProofPublicInputs: expected {}, got {}",
                CHAIN_END_PROOF_PUBLIC_INPUTS_LEN,
                slice.len()
            )));
        }
        let last_hash = Bytes32::from_u32_slice(&slice[0..BYTES32_LEN]).unwrap();
        let aggregator = Address::from_u32_slice(&slice[BYTES32_LEN..]).unwrap();
        Ok(Self {
            last_hash,
            aggregator,
        })
    }

    pub fn from_u64_slice(slice: &[u64]) -> Result<Self, HashChainError> {
        if slice.len() != CHAIN_END_PROOF_PUBLIC_INPUTS_LEN {
            return Err(HashChainError::InvalidData(format!(
                "Invalid input length for ChainEndProofPublicInputs: expected {}, got {}",
                CHAIN_END_PROOF_PUBLIC_INPUTS_LEN,
                slice.len()
            )));
        }
        let inputs = slice
            .iter()
            .map(|&x| {
                assert!(x <= u32::MAX as u64);
                x as u32
            })
            .collect::<Vec<u32>>();
        Self::from_u32_slice(&inputs)
    }

    pub fn from_pis<F: PrimeField64>(pis: &[F]) -> Result<Self, HashChainError> {
        Self::from_u64_slice(&pis.to_u64_vec())
    }

    pub fn hash(&self) -> Bytes32 {
        Bytes32::from_u32_slice(&solidity_keccak256(&self.to_u32_vec())).unwrap()
    }
}

#[derive(Debug, Clone)]
struct ChainEndProofPublicInputsTarget {
    last_hash: Bytes32Target,
    aggregator: AddressTarget,
}

impl ChainEndProofPublicInputsTarget {
    fn to_vec(&self) -> Vec<Target> {
        [self.last_hash.to_vec(), self.aggregator.to_vec()].concat()
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
pub struct ChainEndCircuit<F, C, const D: usize>
where
    F: RichField + Extendable<D>,
    C: GenericConfig<D, F = F>,
{
    pub data: CircuitData<F, C, D>,
    proof: ProofWithPublicInputsTarget<D>,
    aggregator: AddressTarget, // Who makes the aggregated proof and receive the reward
}

impl<F, C, const D: usize> ChainEndCircuit<F, C, D>
where
    F: RichField + Extendable<D>,
    C: GenericConfig<D, F = F> + 'static,
    C::Hasher: AlgebraicHasher<F>,
{
    pub fn new(verifier_data: &VerifierCircuitData<F, C, D>) -> Self {
        let mut builder = CircuitBuilder::<F, D>::new(CircuitConfig::default());
        let proof = add_proof_target_and_verify_cyclic(verifier_data, &mut builder);
        let last_hash = Bytes32Target::from_slice(&proof.public_inputs[0..BYTES32_LEN]);
        let aggregator = AddressTarget::new(&mut builder, true);
        let pis = ChainEndProofPublicInputsTarget {
            last_hash,
            aggregator,
        };
        let pis_hash = pis.hash::<F, C, D>(&mut builder);
        let masked_pis_hash = mask_high_bits_circuit(&mut builder, pis_hash, MASKED_BITS);
        builder.register_public_inputs(&masked_pis_hash.to_vec());
        let data = builder.build();
        Self {
            data,
            proof,
            aggregator,
        }
    }

    pub fn prove(
        &self,
        proof: &ProofWithPublicInputs<F, C, D>,
        aggregator: Address,
    ) -> super::error::Result<ProofWithPublicInputs<F, C, D>> {
        let mut pw = PartialWitness::<F>::new();
        pw.set_proof_with_pis_target(&self.proof, proof);
        self.aggregator.set_witness(&mut pw, aggregator);
        self.data.prove(pw).map_err(|e| {
            crate::utils::error::UtilsError::from(super::error::HashChainError::ChainEndProofError(
                e.to_string(),
            ))
        })
    }
}

pub fn mask_high_bits(input: Bytes32, num_bits: usize) -> Bytes32 {
    let mut limbs = input.to_u32_vec();
    let masked_highest_limb = limbs[0] & ((1 << (32 - num_bits)) - 1);
    limbs[0] = masked_highest_limb;
    Bytes32::from_u32_slice(&limbs).unwrap()
}

pub fn mask_high_bits_circuit<F: RichField + Extendable<D>, const D: usize>(
    builder: &mut CircuitBuilder<F, D>,
    input: Bytes32Target,
    num_bits: usize,
) -> Bytes32Target {
    let mut limbs = input.to_vec();
    let highest_limb_bits_le = builder.split_le(limbs[0], 32);
    let highest_limb = builder.le_sum(highest_limb_bits_le[0..32 - num_bits].into_iter());
    limbs[0] = highest_limb;
    Bytes32Target::from_slice(&limbs)
}

#[cfg(test)]
mod tests {
    use plonky2::{
        field::goldilocks_field::GoldilocksField, plonk::config::PoseidonGoldilocksConfig,
    };

    use super::*;

    type F = GoldilocksField;
    type C = PoseidonGoldilocksConfig;
    const D: usize = 2;

    #[test]
    fn test_mask_high_bits() {
        let mut rng = rand::thread_rng();
        let input = Bytes32::rand(&mut rng);

        let num_bits = 3;
        let expected = mask_high_bits(input, num_bits);

        let mut builder = CircuitBuilder::<F, D>::new(CircuitConfig::default());
        let input_target = Bytes32Target::constant(&mut builder, input);
        let masked_target = mask_high_bits_circuit(&mut builder, input_target, num_bits);
        let expected_target = Bytes32Target::constant(&mut builder, expected);
        masked_target.connect(&mut builder, expected_target);

        let data = builder.build::<C>();
        let pw = PartialWitness::new();
        let proof = data.prove(pw).unwrap();
        data.verify(proof).unwrap();
    }
}
