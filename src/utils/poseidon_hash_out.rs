use crate::ethereum_types::u32limb_trait::{U32LimbTargetTrait as _, U32LimbTrait as _};
use anyhow::ensure;
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
#[derive(Debug, Clone, Copy, Default, PartialEq)]
pub struct PoseidonHashOut {
    pub elements: [u64; 4],
}

#[derive(Debug, Clone, Copy)]
pub struct PoseidonHashOutTarget {
    pub elements: [Target; 4],
}

impl PoseidonHashOut {
    pub fn to_u64_vec(&self) -> Vec<u64> {
        self.elements.to_vec()
    }

    pub fn from_u64_vec(input: &[u64]) -> Self {
        assert_eq!(input.len(), POSEIDON_HASH_OUT_LEN);
        Self {
            elements: input.try_into().unwrap(),
        }
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

    pub fn from_vec(input: &[Target]) -> Self {
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
            .chain(right.elements.into_iter())
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

impl From<PoseidonHashOut> for Bytes32<u32> {
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
        Self::from_limbs(&limbs)
    }
}

impl Bytes32<u32> {
    pub fn reduce_to_hash_out(&self) -> PoseidonHashOut {
        let elements = self
            .limbs()
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

impl TryFrom<Bytes32<u32>> for PoseidonHashOut {
    type Error = anyhow::Error;
    // Convert Bytes32 to HashOut.
    /// Bytes32 has a larger representation space than HashOut, so this might fail.
    fn try_from(value: Bytes32<u32>) -> Result<Self, Self::Error> {
        let hash_out = value.reduce_to_hash_out();
        let recovered: Bytes32<u32> = hash_out.into();
        ensure!(value == recovered, "Failed to recover HashOut from Bytes32");
        Ok(hash_out)
    }
}

impl Bytes32<Target> {
    pub fn from_hash_out<F: RichField + Extendable<D>, const D: usize>(
        builder: &mut CircuitBuilder<F, D>,
        input: PoseidonHashOutTarget,
    ) -> Self {
        let limbs = input
            .elements
            .iter()
            .flat_map(|e| {
                let (low, high) = builder.split_low_high(*e, 32, 32);
                [high, low]
            })
            .collect::<Vec<_>>();
        Self::from_limbs(&limbs)
    }

    pub fn reduce_to_hash_out<F: RichField + Extendable<D>, const D: usize>(
        &self,
        builder: &mut CircuitBuilder<F, D>,
    ) -> PoseidonHashOutTarget {
        let mut result = vec![];
        for chunk in self.limbs().chunks(2) {
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
        let recovered = Bytes32::<Target>::from_hash_out(builder, hash_out);
        self.connect(builder, recovered);
        hash_out
    }
}

impl Serialize for PoseidonHashOut {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        let bytes32: Bytes32<u32> = (*self).into();
        bytes32.serialize(serializer)
    }
}

impl<'de> Deserialize<'de> for PoseidonHashOut {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let bytes32 = Bytes32::<u32>::deserialize(deserializer)?;
        bytes32.try_into().map_err(serde::de::Error::custom)
    }
}

impl Display for PoseidonHashOut {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let bytes32: Bytes32<u32> = (*self).into();
        write!(f, "{}", bytes32)
    }
}
