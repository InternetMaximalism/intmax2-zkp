use plonky2::{
    field::extension::Extendable, hash::hash_types::RichField, iop::target::Target,
    plonk::circuit_builder::CircuitBuilder,
};
use serde::{Deserialize, Serialize};

use super::u32limb_trait::{U32LimbTargetTrait, U32LimbTrait};

pub const U64_LEN: usize = 2;

// A structure representing the u64 type in Ethereum.
// `T` is either `u32` or `U32Target`.
// The value is stored in big endian format.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Default, Hash)]
pub struct U64<T: Clone + Copy> {
    limbs: [T; U64_LEN],
}

impl From<u64> for U64<u32> {
    fn from(value: u64) -> Self {
        let lo = value as u32;
        let hi = (value >> 32) as u32;
        Self { limbs: [hi, lo] }
    }
}

impl From<U64<u32>> for u64 {
    fn from(value: U64<u32>) -> Self {
        let hi = value.limbs[0] as u64;
        let lo = value.limbs[1] as u64;
        (hi << 32) | lo
    }
}

impl std::fmt::Display for U64<u32> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", u64::from(*self))
    }
}

impl Serialize for U64<u32> {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(&u64::from(*self).to_string())
    }
}

impl<'de> Deserialize<'de> for U64<u32> {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let s = String::deserialize(deserializer)?;
        let s_u64: u64 = s.parse().unwrap();
        Ok(Self::from(s_u64))
    }
}

impl U32LimbTrait<U64_LEN> for U64<u32> {
    fn limbs(&self) -> Vec<u32> {
        self.limbs.to_vec()
    }

    fn from_limbs(limbs: &[u32]) -> Self {
        Self {
            limbs: limbs.try_into().unwrap(),
        }
    }
}

impl U32LimbTargetTrait<U64_LEN> for U64<Target> {
    fn limbs(&self) -> Vec<Target> {
        self.limbs.to_vec()
    }

    fn from_limbs(limbs: &[Target]) -> Self {
        Self {
            limbs: limbs.try_into().unwrap(),
        }
    }
}

impl U64<Target> {
    pub fn from_u64<F: RichField + Extendable<D>, const D: usize>(
        builder: &mut CircuitBuilder<F, D>,
        value: Target,
    ) -> Self {
        let (lo, hi) = builder.split_low_high(value, 32, 64);
        Self { limbs: [hi, lo] }
    }

    pub fn to_u64<F: RichField + Extendable<D>, const D: usize>(
        &self,
        builder: &mut CircuitBuilder<F, D>,
    ) -> Target {
        let lo = self.limbs[1];
        let hi = self.limbs[0];
        builder.mul_const_add(F::from_canonical_u64(1 << 32), hi, lo)
    }
}
