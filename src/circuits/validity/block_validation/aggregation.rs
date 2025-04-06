//! Circuit that verifies the weighted aggregation of public keys matches the aggregate public key
//! in the signature.
//!
//! This circuit ensures that the weighted aggregation of public keys bound by a pubkey commitment
//! equals the aggregate public key bound by a signature commitment. The weights are derived from
//! hashing each public key with the pubkey hash.
//!
//! The circuit takes as input:
//! - A set of public keys
//! - A signature content containing an aggregate public key
//! - Commitments to both the public keys and the signature
//!
//! It verifies that:
//! 1. The weighted sum of the public keys equals the aggregate public key in the signature
//! 2. The commitments correctly bind the public keys and signature
//!
//! IMPORTANT: This circuit assumes that format validation has already been performed on the
//! pubkeys and signature content. If the format validation is not passed, the proof generation
//! will fail. Format validation ensures that:
//! - Pubkeys are in the correct range and properly ordered
//! - Pubkeys are recoverable from their x-coordinates
//! - The signature content has a valid format
//! - The message point is correctly derived from the block sign payload

use plonky2::{
    field::extension::Extendable,
    gates::constant::ConstantGate,
    hash::hash_types::RichField,
    iop::{
        target::{BoolTarget, Target},
        witness::{PartialWitness, Witness},
    },
    plonk::{
        circuit_builder::CircuitBuilder,
        circuit_data::{CircuitConfig, CircuitData},
        config::{AlgebraicHasher, GenericConfig},
        proof::ProofWithPublicInputs,
    },
};

use super::error::BlockValidationError;

use crate::{
    circuits::validity::block_validation::utils::get_pubkey_commitment_circuit,
    common::signature_content::{SignatureContent, SignatureContentTarget},
    constants::NUM_SENDERS_IN_BLOCK,
    ethereum_types::{
        u256::{U256Target, U256},
        u32limb_trait::U32LimbTargetTrait,
    },
    utils::{
        dummy::DummyProof,
        poseidon_hash_out::{PoseidonHashOut, PoseidonHashOutTarget, POSEIDON_HASH_OUT_LEN},
    },
};

use super::utils::get_pubkey_commitment;

pub const AGGREGATION_PUBLIC_INPUTS_LEN: usize = 2 * POSEIDON_HASH_OUT_LEN + 1;

/// Public inputs for the aggregation circuit.
#[derive(Clone, Debug)]
pub struct AggregationPublicInputs {
    /// Commitment to the set of public keys
    pub pubkey_commitment: PoseidonHashOut,

    /// Commitment to the signature content
    pub signature_commitment: PoseidonHashOut,

    /// Flag indicating whether the aggregation is valid
    pub is_valid: bool,
}

/// Target version of AggregationPublicInputs for use in the circuit.
#[derive(Clone, Debug)]
pub struct AggregationPublicInputsTarget {
    /// Target for the commitment to the set of public keys
    pub pubkey_commitment: PoseidonHashOutTarget,

    /// Target for the commitment to the signature content
    pub signature_commitment: PoseidonHashOutTarget,

    /// Target for the validity flag
    pub is_valid: BoolTarget,
}

impl AggregationPublicInputs {
    pub fn from_u64_slice(input: &[u64]) -> Result<Self, BlockValidationError> {
        if input.len() != AGGREGATION_PUBLIC_INPUTS_LEN {
            return Err(BlockValidationError::AggregationInputLengthMismatch {
                expected: AGGREGATION_PUBLIC_INPUTS_LEN,
                actual: input.len(),
            });
        }
        let pubkey_commitment = PoseidonHashOut::from_u64_slice(&input[0..4]);
        let signature_commitment = PoseidonHashOut::from_u64_slice(&input[4..8]);
        let is_valid = input[8] == 1;
        Ok(Self {
            pubkey_commitment,
            signature_commitment,
            is_valid,
        })
    }
}

impl AggregationPublicInputsTarget {
    pub fn to_vec(&self) -> Vec<Target> {
        let vec = self
            .pubkey_commitment
            .elements
            .into_iter()
            .chain(self.signature_commitment.elements)
            .chain([self.is_valid.target])
            .collect::<Vec<_>>();
        assert_eq!(vec.len(), AGGREGATION_PUBLIC_INPUTS_LEN);
        vec
    }

    pub fn from_slice(input: &[Target]) -> Result<Self, BlockValidationError> {
        if input.len() != AGGREGATION_PUBLIC_INPUTS_LEN {
            return Err(BlockValidationError::AggregationInputLengthMismatch {
                expected: AGGREGATION_PUBLIC_INPUTS_LEN,
                actual: input.len(),
            });
        }

        let pubkey_commitment = PoseidonHashOutTarget::from_slice(&input[0..4]);
        let signature_commitment = PoseidonHashOutTarget::from_slice(&input[4..8]);
        let is_valid = BoolTarget::new_unsafe(input[8]);

        Ok(Self {
            pubkey_commitment,
            signature_commitment,
            is_valid,
        })
    }
}

/// Values used in the aggregation circuit.
pub struct AggregationValue {
    pub pubkeys: Vec<U256>,
    pub signature: SignatureContent,
    pub pubkey_commitment: PoseidonHashOut,
    pub signature_commitment: PoseidonHashOut,
    pub is_valid: bool,
}

/// Target version of AggregationValue for use in the circuit.
#[derive(Debug, Clone)]
pub struct AggregationTarget {
    /// Targets for the set of public keys
    pub pubkeys: Vec<U256Target>,

    /// Target for the signature content
    pub signature: SignatureContentTarget,

    /// Target for the commitment to the set of public keys
    pub pubkey_commitment: PoseidonHashOutTarget,

    /// Target for the commitment to the signature content
    pub signature_commitment: PoseidonHashOutTarget,

    /// Target for the validity flag
    pub is_valid: BoolTarget,
}

impl AggregationValue {
    pub fn new(pubkeys: Vec<U256>, signature: SignatureContent) -> Self {
        let pubkey_commitment = get_pubkey_commitment(&pubkeys);
        let signature_commitment = signature.commitment();
        let is_valid = signature.verify_aggregation(&pubkeys);
        Self {
            pubkeys,
            signature,
            pubkey_commitment,
            signature_commitment,
            is_valid,
        }
    }
}

impl AggregationTarget {
    pub fn new<F: RichField + Extendable<D>, C: GenericConfig<D, F = F> + 'static, const D: usize>(
        builder: &mut CircuitBuilder<F, D>,
    ) -> Self
    where
        <C as GenericConfig<D>>::Hasher: AlgebraicHasher<F>,
    {
        let pubkeys = (0..NUM_SENDERS_IN_BLOCK)
            .map(|_| U256Target::new(builder, true))
            .collect::<Vec<_>>();

        let pubkey_commitment = get_pubkey_commitment_circuit(builder, &pubkeys);
        let signature = SignatureContentTarget::new(builder, true);
        let signature_commitment = signature.commitment(builder);
        let is_valid = signature.verify_aggregation::<F, C, D>(builder, &pubkeys);
        Self {
            pubkeys,
            signature,
            pubkey_commitment,
            signature_commitment,
            is_valid,
        }
    }

    pub fn set_witness<F: RichField, W: Witness<F>>(
        &self,
        witness: &mut W,
        value: &AggregationValue,
    ) {
        for (pubkey_t, pubkey) in self.pubkeys.iter().zip(value.pubkeys.iter()) {
            pubkey_t.set_witness(witness, *pubkey);
        }
        self.signature.set_witness(witness, &value.signature);
        self.pubkey_commitment
            .set_witness(witness, value.pubkey_commitment);
        self.signature_commitment
            .set_witness(witness, value.signature_commitment);
        witness.set_bool_target(self.is_valid, value.is_valid);
    }
}

/// Circuit that verifies the weighted aggregation of public keys matches the aggregate public key.
#[derive(Debug)]
pub struct AggregationCircuit<F, C, const D: usize>
where
    F: RichField + Extendable<D>,
    C: GenericConfig<D, F = F>,
{
    pub data: CircuitData<F, C, D>,
    pub target: AggregationTarget,
    /// Dummy proof for recursive verification
    pub dummy_proof: DummyProof<F, C, D>,
}

impl<F, C, const D: usize> Default for AggregationCircuit<F, C, D>
where
    F: RichField + Extendable<D>,
    C: GenericConfig<D, F = F> + 'static,
    C::Hasher: AlgebraicHasher<F>,
{
    fn default() -> Self {
        Self::new()
    }
}

impl<F, C, const D: usize> AggregationCircuit<F, C, D>
where
    F: RichField + Extendable<D>,
    C: GenericConfig<D, F = F> + 'static,
    C::Hasher: AlgebraicHasher<F>,
{
    pub fn new() -> Self {
        let config = CircuitConfig::default();
        let mut builder = CircuitBuilder::<F, D>::new(config.clone());

        // Create targets for the aggregation values
        let target = AggregationTarget::new::<F, C, D>(&mut builder);

        // Register public inputs
        let pis = AggregationPublicInputsTarget {
            signature_commitment: target.signature_commitment,
            pubkey_commitment: target.pubkey_commitment,
            is_valid: target.is_valid,
        };
        builder.register_public_inputs(&pis.to_vec());

        // Add a ConstantGate to create a dummy proof
        builder.add_gate(ConstantGate::new(config.num_constants), vec![]);

        // Build the circuit
        let data = builder.build();
        let dummy_proof = DummyProof::new(&data.common);

        Self {
            data,
            target,
            dummy_proof,
        }
    }

    pub fn prove(
        &self,
        value: &AggregationValue,
    ) -> Result<ProofWithPublicInputs<F, C, D>, BlockValidationError> {
        let mut pw = PartialWitness::<F>::new();
        self.target.set_witness(&mut pw, value);
        self.data
            .prove(pw)
            .map_err(|e| BlockValidationError::Plonky2Error(e.to_string()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::common::signature_content::SignatureContent;
    use plonky2::{
        field::goldilocks_field::GoldilocksField, plonk::config::PoseidonGoldilocksConfig,
    };

    type F = GoldilocksField;
    const D: usize = 2;
    type C = PoseidonGoldilocksConfig;

    /// Tests the aggregation circuit with valid inputs.
    #[test]
    fn test_aggregation_circuit_valid() {
        // Generate random key set and signature
        let rng = &mut rand::thread_rng();
        let (keyset, signature) = SignatureContent::rand(rng);
        let pubkeys = keyset
            .iter()
            .map(|keyset| keyset.pubkey)
            .collect::<Vec<_>>();

        // Verify format and aggregation validity
        assert!(
            signature.is_valid_format(&pubkeys),
            "Signature format should be valid"
        );
        assert!(
            signature.verify_aggregation(&pubkeys),
            "Signature aggregation should be valid"
        );

        // Create and prove the aggregation circuit
        let aggregation_circuit = AggregationCircuit::<F, C, D>::new();
        let aggregation_value = AggregationValue::new(pubkeys, signature);
        let proof = aggregation_circuit
            .prove(&aggregation_value)
            .expect("Failed to prove aggregation circuit");

        // Verify the proof
        aggregation_circuit
            .data
            .verify(proof)
            .expect("Failed to verify aggregation circuit proof");
    }

    /// Tests the public inputs conversion functions.
    #[test]
    fn test_aggregation_public_inputs_conversion() {
        // Create random public inputs
        let rng = &mut rand::thread_rng();
        let pubkey_commitment = PoseidonHashOut::rand(rng);
        let signature_commitment = PoseidonHashOut::rand(rng);
        let is_valid = true;

        // Create public inputs
        let inputs = AggregationPublicInputs {
            pubkey_commitment,
            signature_commitment,
            is_valid,
        };

        // Convert to u64 slice
        let u64_vec = [
            pubkey_commitment.to_u64_vec(),
            signature_commitment.to_u64_vec(),
            vec![if is_valid { 1 } else { 0 }],
        ]
        .concat();

        // Convert back to AggregationPublicInputs
        let recovered = AggregationPublicInputs::from_u64_slice(&u64_vec)
            .expect("Failed to convert from u64 slice");

        // Verify equality
        assert_eq!(
            recovered.pubkey_commitment, inputs.pubkey_commitment,
            "Pubkey commitment should match after conversion"
        );
        assert_eq!(
            recovered.signature_commitment, inputs.signature_commitment,
            "Signature commitment should match after conversion"
        );
        assert_eq!(
            recovered.is_valid, inputs.is_valid,
            "Validity flag should match after conversion"
        );
    }
}
