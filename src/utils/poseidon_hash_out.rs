use crate::{
    ethereum_types::{
        bytes32::Bytes32Target,
        u32limb_trait::{U32LimbTargetTrait as _, U32LimbTrait as _},
    },
    utils::error::PoseidonHashOutError,
};
use core::fmt::Display;
use plonky2::{
    field::{
        extension::Extendable,
        goldilocks_field::GoldilocksField,
        types::{Field, PrimeField64},
    },
    hash::{
        hash_types::{HashOut, RichField, NUM_HASH_OUT_ELTS},
        hashing::PlonkyPermutation as _,
        poseidon::PoseidonHash,
    },
    iop::{
        target::{BoolTarget, Target},
        witness::WitnessWrite,
    },
    plonk::{
        circuit_builder::CircuitBuilder,
        config::{AlgebraicHasher, Hasher},
    },
};
use rand::Rng;
use serde::{Deserialize, Serialize};

use crate::ethereum_types::bytes32::Bytes32;

use super::conversion::{ToField, ToU64};

pub const POSEIDON_HASH_OUT_LEN: usize = 4;

/// A struct equivalent to plonky2's `HashOut`, but implemented with u64 fixed instead of
/// generics. This is convenient for implementing serialize and leafable.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Hash)]
pub struct PoseidonHashOut {
    pub elements: [u64; 4],
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PoseidonHashOutTarget {
    pub elements: [Target; 4],
}

impl PoseidonHashOut {
    pub fn to_u64_vec(&self) -> Vec<u64> {
        self.elements.to_vec()
    }

    pub fn from_u64_slice(input: &[u64]) -> Result<Self, PoseidonHashOutError> {
        if input.len() != POSEIDON_HASH_OUT_LEN {
            return Err(PoseidonHashOutError::InvalidHashValue(format!(
                "Invalid input length: expected {}, got {}",
                POSEIDON_HASH_OUT_LEN,
                input.len()
            )));
        }
        Ok(Self {
            elements: input.try_into().unwrap(),
        })
    }

    pub fn hash_inputs_u64(inputs: &[u64]) -> Self {
        PoseidonHash::hash_no_pad(&inputs.to_field_vec::<GoldilocksField>()).into()
    }

    pub fn hash_inputs_u32(inputs: &[u32]) -> Self {
        let inputs = inputs
            .iter()
            .map(|&x| GoldilocksField::from_canonical_u32(x))
            .collect::<Vec<_>>();
        PoseidonHash::hash_no_pad(&inputs).into()
    }

    pub fn rand<R: Rng>(rng: &mut R) -> Self {
        let elements = (0..4)
            .map(|_| rng.gen_range(0..GoldilocksField::NEG_ONE.0))
            .collect::<Vec<_>>();
        Self {
            elements: elements.try_into().unwrap(),
        }
    }
}

impl PoseidonHashOutTarget {
    pub fn to_vec(&self) -> Vec<Target> {
        self.elements.to_vec()
    }

    pub fn from_slice(input: &[Target]) -> Self {
        assert_eq!(input.len(), POSEIDON_HASH_OUT_LEN);
        Self {
            elements: input.try_into().unwrap(),
        }
    }

    pub fn new<F: RichField + Extendable<D>, const D: usize>(
        builder: &mut CircuitBuilder<F, D>,
    ) -> Self {
        let elements = (0..4)
            .map(|_| builder.add_virtual_target())
            .collect::<Vec<_>>();
        Self {
            elements: elements.try_into().unwrap(),
        }
    }

    pub fn constant<F: RichField + Extendable<D>, const D: usize>(
        builder: &mut CircuitBuilder<F, D>,
        value: PoseidonHashOut,
    ) -> Self {
        let elements = value
            .elements
            .map(|e| builder.constant(F::from_canonical_u64(e)));
        Self { elements }
    }

    pub fn hash_inputs<F: RichField + Extendable<D>, const D: usize>(
        builder: &mut CircuitBuilder<F, D>,
        inputs: &[Target],
    ) -> Self {
        let hash_out = builder.hash_n_to_hash_no_pad::<PoseidonHash>(inputs.to_vec());
        Self {
            elements: hash_out.elements,
        }
    }

    pub fn connect<F: RichField + Extendable<D>, const D: usize>(
        &self,
        builder: &mut CircuitBuilder<F, D>,
        other: Self,
    ) {
        for (a, b) in self.elements.iter().zip(other.elements.iter()) {
            builder.connect(*a, *b);
        }
    }

    pub fn conditional_assert_eq<F: RichField + Extendable<D>, const D: usize>(
        &self,
        builder: &mut CircuitBuilder<F, D>,
        other: Self,
        condition: BoolTarget,
    ) {
        for (a, b) in self.elements.iter().zip(other.elements.iter()) {
            builder.conditional_assert_eq(condition.target, *a, *b);
        }
    }

    pub fn select<F: RichField + Extendable<D>, const D: usize>(
        builder: &mut CircuitBuilder<F, D>,
        condition: BoolTarget,
        x: Self,
        y: Self,
    ) -> Self {
        let elements = x
            .elements
            .iter()
            .zip(y.elements.iter())
            .map(|(x, y)| builder.select(condition, *x, *y))
            .collect::<Vec<_>>();
        Self {
            elements: elements.try_into().unwrap(),
        }
    }

    pub fn two_to_one<F: RichField + Extendable<D>, const D: usize>(
        builder: &mut CircuitBuilder<F, D>,
        left: Self,
        right: Self,
    ) -> Self {
        let inputs = left
            .elements
            .into_iter()
            .chain(right.elements)
            .collect::<Vec<_>>();
        PoseidonHashOutTarget::hash_inputs(builder, &inputs)
    }

    pub fn two_to_one_swapped<F: RichField + Extendable<D>, const D: usize>(
        builder: &mut CircuitBuilder<F, D>,
        left: Self,
        right: Self,
        swap: BoolTarget,
    ) -> Self {
        let zero = builder.zero();
        let mut perm_inputs = <PoseidonHash as AlgebraicHasher<F>>::AlgebraicPermutation::default();
        perm_inputs.set_from_slice(&left.elements, 0);
        perm_inputs.set_from_slice(&right.elements, NUM_HASH_OUT_ELTS);
        perm_inputs.set_from_iter(std::iter::repeat(zero), 2 * NUM_HASH_OUT_ELTS);
        let perm_outs = PoseidonHash::permute_swapped(perm_inputs, swap, builder);
        let hash_outs = perm_outs.squeeze()[0..NUM_HASH_OUT_ELTS]
            .try_into()
            .unwrap();
        Self {
            elements: hash_outs,
        }
    }

    pub fn set_witness<F: Field, W: WitnessWrite<F>>(
        &self,
        witness: &mut W,
        value: PoseidonHashOut,
    ) {
        for (target, value) in self.elements.iter().zip(value.elements.iter()) {
            witness.set_target(*target, F::from_canonical_u64(*value));
        }
    }
}

/*
 * From traits for PoseidonHashOut.
 */
impl<F: PrimeField64> From<HashOut<F>> for PoseidonHashOut {
    fn from(value: HashOut<F>) -> Self {
        let elements: [u64; 4] = value.elements.iter().to_u64_vec().try_into().unwrap();
        Self { elements }
    }
}

impl From<PoseidonHashOut> for Bytes32 {
    /// Convert HashOut to Bytes32.
    fn from(value: PoseidonHashOut) -> Self {
        let limbs = value
            .elements
            .iter()
            .flat_map(|&e| {
                let low = e as u32;
                let high = (e >> 32) as u32;
                [high, low]
            })
            .collect::<Vec<_>>();
        Self::from_u32_slice(&limbs).expect("Converting from u32 slice should never fail")
    }
}

impl Bytes32 {
    pub fn reduce_to_hash_out(&self) -> PoseidonHashOut {
        let elements = self
            .to_u32_vec()
            .chunks(2)
            .map(|chunk| {
                let low = chunk[1];
                let high = chunk[0];
                ((high as u64) << 32) + (low as u64)
            })
            .collect::<Vec<_>>();
        PoseidonHashOut {
            elements: elements.try_into().unwrap(),
        }
    }
}

impl TryFrom<Bytes32> for PoseidonHashOut {
    type Error = PoseidonHashOutError;
    // Convert Bytes32 to HashOut.
    /// Bytes32 has a larger representation space than HashOut, so this might fail.
    fn try_from(value: Bytes32) -> Result<Self, Self::Error> {
        let hash_out = value.reduce_to_hash_out();
        let recovered: Bytes32 = hash_out.into();
        if value != recovered {
            return Err(PoseidonHashOutError::RecoveryFailed);
        }
        Ok(hash_out)
    }
}

impl Bytes32Target {
    // Convert HashOutTarget to Bytes32Target. This conversion is deterministic.
    pub fn from_hash_out<F: RichField + Extendable<D>, const D: usize>(
        builder: &mut CircuitBuilder<F, D>,
        input: PoseidonHashOutTarget,
    ) -> Self {
        let limbs = input
            .elements
            .iter()
            .flat_map(|e| {
                let (low, high) = safe_split_lo_and_hi(builder, *e);
                [high, low]
            })
            .collect::<Vec<_>>();
        Self::from_slice(&limbs)
    }

    pub fn reduce_to_hash_out<F: RichField + Extendable<D>, const D: usize>(
        &self,
        builder: &mut CircuitBuilder<F, D>,
    ) -> PoseidonHashOutTarget {
        let mut result = vec![];
        for chunk in self.to_vec().chunks(2) {
            let low = chunk[1];
            let high = chunk[0];
            result.push(builder.mul_const_add(F::from_canonical_u64(1 << 32), high, low));
        }
        PoseidonHashOutTarget {
            elements: result.try_into().unwrap(),
        }
    }

    pub fn to_hash_out<F: RichField + Extendable<D>, const D: usize>(
        &self,
        builder: &mut CircuitBuilder<F, D>,
    ) -> PoseidonHashOutTarget {
        let hash_out = self.reduce_to_hash_out(builder);
        let recovered = Bytes32Target::from_hash_out(builder, hash_out);
        self.connect(builder, recovered);
        hash_out
    }
}

// Split the goldilocks field target uniquely into hi and lo parts. x = hi*2^32 + lo
fn safe_split_lo_and_hi<F: RichField + Extendable<D>, const D: usize>(
    builder: &mut CircuitBuilder<F, D>,
    x: Target,
) -> (Target, Target) {
    let (lo, hi) = builder.split_low_high(x, 32, 64);
    // lo and hi are constrained to be 32 bits and x = hi*2^32 + lo mod p
    // However, when x < 2^32, there are two possible decompositions:
    // 1) hi = 0, lo = x
    // 2) hi = 2^32 - 1, lo = x + 1
    // By adding the constraint that lo must be 0 when hi = 2^32 - 1, we can eliminate the latter
    // case. This constraint still allows any value of x to be decomposed, because
    // hi = 2^32 - 1, lo = 0 gives hi*2^32 + lo = p - 1, which is the maximum value in the field.
    let hi_max = builder.constant(F::from_canonical_u64((1 << 32) - 1));
    let is_hi_max = builder.is_equal(hi, hi_max);
    let t = builder.mul(is_hi_max.target, lo);
    builder.assert_zero(t);
    (lo, hi)
}

impl Serialize for PoseidonHashOut {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(&self.to_string())
    }
}

impl<'de> Deserialize<'de> for PoseidonHashOut {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let bytes32 = Bytes32::deserialize(deserializer)?;
        bytes32.try_into().map_err(serde::de::Error::custom)
    }
}

impl Display for PoseidonHashOut {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let bytes32: Bytes32 = (*self).into();
        write!(f, "{}", bytes32)
    }
}

#[cfg(test)]
mod tests {
    use plonky2::{
        iop::witness::PartialWitness,
        plonk::{circuit_data::CircuitConfig, config::PoseidonGoldilocksConfig},
    };
    use rand::thread_rng;

    use super::*;

    type F = GoldilocksField;
    const D: usize = 2;
    type C = PoseidonGoldilocksConfig;

    #[test]
    fn test_poseidon_hash_out_safe_split_lo_and_hi() {
        let x = F::NEG_ONE;

        let mut builder = CircuitBuilder::<F, D>::new(CircuitConfig::default());
        let x = builder.constant(x);
        let (lo, _hi) = safe_split_lo_and_hi(&mut builder, x);
        builder.assert_zero(lo);

        let circuit = builder.build::<C>();
        let _proof = circuit.prove(PartialWitness::new()).unwrap();
    }

    #[test]
    fn test_poseidon_hash_out_hash_inputs_u64() {
        let inputs = vec![1u64, 2u64, 3u64];
        let hash = PoseidonHashOut::hash_inputs_u64(&inputs);

        // Verify that hashing the same inputs produces the same output
        let hash2 = PoseidonHashOut::hash_inputs_u64(&inputs);
        assert_eq!(hash, hash2);

        // Verify that different inputs produce different outputs
        let different_inputs = vec![1u64, 2u64, 4u64];
        let different_hash = PoseidonHashOut::hash_inputs_u64(&different_inputs);
        assert_ne!(hash, different_hash);
    }

    #[test]
    fn test_poseidon_hash_out_hash_inputs_u32() {
        let inputs = vec![1u32, 2u32, 3u32];
        let hash = PoseidonHashOut::hash_inputs_u32(&inputs);

        // Verify that hashing the same inputs produces the same output
        let hash2 = PoseidonHashOut::hash_inputs_u32(&inputs);
        assert_eq!(hash, hash2);

        // Verify that different inputs produce different outputs
        let different_inputs = vec![1u32, 2u32, 4u32];
        let different_hash = PoseidonHashOut::hash_inputs_u32(&different_inputs);
        assert_ne!(hash, different_hash);
    }

    #[test]
    fn test_poseidon_hash_out_rand() {
        let mut rng = thread_rng();
        let hash1 = PoseidonHashOut::rand(&mut rng);
        let hash2 = PoseidonHashOut::rand(&mut rng);

        // Two random hashes should be different
        assert_ne!(hash1, hash2);

        // Elements should be within the valid range for GoldilocksField
        for element in hash1.elements.iter() {
            assert!(*element < GoldilocksField::NEG_ONE.0);
        }
    }

    #[test]
    fn test_poseidon_hash_out_to_u64_vec() {
        let elements = [1u64, 2u64, 3u64, 4u64];
        let hash = PoseidonHashOut { elements };
        let vec = hash.to_u64_vec();

        assert_eq!(vec, elements.to_vec());
    }

    #[test]
    fn test_poseidon_hash_out_from_u64_slice() {
        let elements = [1u64, 2u64, 3u64, 4u64];
        let hash = PoseidonHashOut::from_u64_slice(&elements).unwrap();

        assert_eq!(hash.elements, elements);
    }

    #[test]
    fn test_poseidon_hash_out_from_u64_slice_invalid_length() {
        let elements = [1u64, 2u64, 3u64];
        let result = PoseidonHashOut::from_u64_slice(&elements);
        assert!(result.is_err());
    }

    #[test]
    fn test_poseidon_hash_out_bytes32_conversion() {
        let mut rng = thread_rng();
        let original = PoseidonHashOut::rand(&mut rng);

        // Convert to Bytes32 and back
        let bytes32: Bytes32 = original.into();
        let recovered: PoseidonHashOut = bytes32.try_into().unwrap();

        // Should get the original value back
        assert_eq!(original, recovered);
    }

    #[test]
    fn test_poseidon_hash_out_bytes32_reduce() {
        let mut rng = thread_rng();
        let original = PoseidonHashOut::rand(&mut rng);

        // Convert to Bytes32
        let bytes32: Bytes32 = original.into();

        // Use reduce_to_hash_out
        let reduced = bytes32.reduce_to_hash_out();

        // Should get the original value back
        assert_eq!(original, reduced);
    }

    #[test]
    fn test_poseidon_hash_out_serialization() {
        let mut rng = thread_rng();
        let original = PoseidonHashOut::rand(&mut rng);

        // Serialize to string
        let serialized = serde_json::to_string(&original).unwrap();

        // Deserialize back
        let deserialized: PoseidonHashOut = serde_json::from_str(&serialized).unwrap();

        // Should get the original value back
        assert_eq!(original, deserialized);
    }

    #[test]
    fn test_poseidon_hash_out_target_circuit_operations() {
        let mut builder = CircuitBuilder::<F, D>::new(CircuitConfig::default());

        // Create two hash targets
        let hash_target1 = PoseidonHashOutTarget::new(&mut builder);
        let hash_target2 = PoseidonHashOutTarget::new(&mut builder);

        // Test two_to_one
        let combined = PoseidonHashOutTarget::two_to_one(&mut builder, hash_target1, hash_target2);

        // Test conditional_assert_eq
        let condition = builder.add_virtual_bool_target_safe();
        combined.conditional_assert_eq(&mut builder, hash_target1, condition);

        // Test select
        let _selected =
            PoseidonHashOutTarget::select(&mut builder, condition, hash_target1, hash_target2);

        // Create witness values
        let mut pw = PartialWitness::new();
        let hash_value1 = PoseidonHashOut::rand(&mut thread_rng());
        let hash_value2 = PoseidonHashOut::rand(&mut thread_rng());

        // Set witness values
        hash_target1.set_witness(&mut pw, hash_value1);
        hash_target2.set_witness(&mut pw, hash_value2);
        pw.set_bool_target(condition, false);

        // Build and prove the circuit
        let circuit = builder.build::<C>();
        let _proof = circuit.prove(pw).unwrap();
    }

    #[test]
    fn test_poseidon_hash_out_target_hash_inputs() {
        let mut builder = CircuitBuilder::<F, D>::new(CircuitConfig::default());

        // Create input targets
        let input1 = builder.add_virtual_target();
        let input2 = builder.add_virtual_target();
        let inputs = vec![input1, input2];

        // Hash the inputs
        let _hash_target = PoseidonHashOutTarget::hash_inputs(&mut builder, &inputs);

        // Create witness values
        let mut pw = PartialWitness::new();
        pw.set_target(input1, F::from_canonical_u64(1));
        pw.set_target(input2, F::from_canonical_u64(2));

        // Build and prove the circuit
        let circuit = builder.build::<C>();
        let _proof = circuit.prove(pw).unwrap();
    }

    #[test]
    fn test_poseidon_hash_out_target_bytes32_conversion() {
        let mut builder = CircuitBuilder::<F, D>::new(CircuitConfig::default());

        // Create a hash target
        let hash_target = PoseidonHashOutTarget::new(&mut builder);

        // Convert to Bytes32Target and back
        let bytes32_target = Bytes32Target::from_hash_out(&mut builder, hash_target);
        let recovered_hash_target = bytes32_target.to_hash_out(&mut builder);

        // Connect the original and recovered hash targets
        hash_target.connect(&mut builder, recovered_hash_target);

        // Create witness values
        let mut pw = PartialWitness::new();
        let hash_value = PoseidonHashOut::rand(&mut thread_rng());

        // Set witness values
        hash_target.set_witness(&mut pw, hash_value);

        // Build and prove the circuit
        let circuit = builder.build::<C>();
        let _proof = circuit.prove(pw).unwrap();
    }
}
