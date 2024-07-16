use anyhow::ensure;
use num::{BigUint, Num as _, Zero as _};
use plonky2::iop::target::Target;
use serde::{Deserialize, Serialize};

use super::u32limb_trait::{U32LimbTargetTrait, U32LimbTrait};

pub const U128_LEN: usize = 4;

// A structure representing the ui128 type in Ethereum.
// `T` is either `u32` or `U32Target`.
// The value is stored in big endian format.
#[derive(Clone, Copy, PartialEq, Default, Hash)]
pub struct U128 {
    limbs: [u32; U128_LEN],
}

#[derive(Clone, Copy, Debug)]
pub struct U128Target {
    limbs: [Target; U128_LEN],
}

impl core::fmt::Debug for U128 {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let b: BigUint = (*self).into();
        let s = b.to_str_radix(10);
        write!(f, "{}", s)
    }
}

impl core::fmt::Display for U128 {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        core::fmt::Debug::fmt(&self, f)
    }
}

impl Serialize for U128 {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(&self.to_string())
    }
}

impl<'de> Deserialize<'de> for U128 {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let s = String::deserialize(deserializer)?;
        let b = BigUint::from_str_radix(&s, 10).map_err(serde::de::Error::custom)?;
        let u: U128 = b.try_into().unwrap();
        Ok(u)
    }
}

impl TryFrom<BigUint> for U128 {
    type Error = anyhow::Error;
    fn try_from(value: BigUint) -> anyhow::Result<Self> {
        let mut digits = value.to_u32_digits();
        ensure!(digits.len() <= U128_LEN, "value is too large");
        digits.resize(U128_LEN, 0);
        digits.reverse(); // little endian to big endian
        Ok(Self {
            limbs: digits.try_into().unwrap(),
        })
    }
}

impl From<U128> for BigUint {
    fn from(value: U128) -> Self {
        let mut sum = BigUint::zero();
        for (i, digit) in value.limbs.iter().rev().enumerate() {
            sum += BigUint::from(*digit) << (32 * i);
        }
        sum
    }
}

impl U32LimbTrait<U128_LEN> for U128 {
    fn limbs(&self) -> Vec<u32> {
        self.limbs.to_vec()
    }

    fn from_limbs(limbs: &[u32]) -> Self {
        Self {
            limbs: limbs.try_into().unwrap(),
        }
    }
}

impl U32LimbTargetTrait<U128_LEN> for U128Target {
    fn limbs(&self) -> Vec<Target> {
        self.limbs.to_vec()
    }

    fn from_limbs(limbs: &[Target]) -> Self {
        Self {
            limbs: limbs.try_into().unwrap(),
        }
    }
}
