use std::str::FromStr;

use anyhow::ensure;
use num::{BigUint, Zero as _};
use plonky2::iop::target::Target;
use serde::{Deserialize, Serialize};

use super::u32limb_trait::{U32LimbTargetTrait, U32LimbTrait};

pub const BYTES16_LEN: usize = 4;

// A structure representing the byte16 type in Ethereum.
// The value is stored in big endian format.
#[derive(Clone, Copy, PartialEq, Default, Hash)]
pub struct Bytes16 {
    limbs: [u32; BYTES16_LEN],
}

#[derive(Clone, Copy, Debug)]
pub struct Bytes16Target {
    limbs: [Target; BYTES16_LEN],
}

impl core::fmt::Debug for Bytes16 {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.to_hex())
    }
}

impl core::fmt::Display for Bytes16 {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        core::fmt::Debug::fmt(&self, f)
    }
}

impl FromStr for Bytes16 {
    type Err = anyhow::Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Self::from_hex(s).map_err(|e| anyhow::anyhow!("Failed to parse Bytes16: {}", e))
    }
}

impl Serialize for Bytes16 {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(&self.to_string())
    }
}

impl<'de> Deserialize<'de> for Bytes16 {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let s = String::deserialize(deserializer)?;
        let value = Self::from_hex(&s).map_err(serde::de::Error::custom)?;
        Ok(value)
    }
}

impl TryFrom<BigUint> for Bytes16 {
    type Error = anyhow::Error;
    fn try_from(value: BigUint) -> anyhow::Result<Self> {
        let mut digits = value.to_u32_digits();
        ensure!(digits.len() <= BYTES16_LEN, "value is too large");
        digits.resize(BYTES16_LEN, 0);
        digits.reverse(); // little endian to big endian
        Ok(Self {
            limbs: digits.try_into().unwrap(),
        })
    }
}

impl From<Bytes16> for BigUint {
    fn from(value: Bytes16) -> Self {
        let mut sum = BigUint::zero();
        for (i, digit) in value.limbs.iter().rev().enumerate() {
            sum += BigUint::from(*digit) << (32 * i);
        }
        sum
    }
}

impl U32LimbTrait<BYTES16_LEN> for Bytes16 {
    fn to_u32_vec(&self) -> Vec<u32> {
        self.limbs.to_vec()
    }

    fn from_u32_slice(limbs: &[u32]) -> super::u32limb_trait::Result<Self> {
        if limbs.len() != BYTES16_LEN {
            return Err(super::u32limb_trait::U32LimbError::InvalidLength(limbs.len()));
        }
        Ok(Self {
            limbs: limbs.try_into().map_err(|_| super::u32limb_trait::U32LimbError::InvalidLength(limbs.len()))?,
        })
    }
}

impl U32LimbTargetTrait<BYTES16_LEN> for Bytes16Target {
    fn to_vec(&self) -> Vec<Target> {
        self.limbs.to_vec()
    }

    fn from_slice(limbs: &[Target]) -> Self {
        assert_eq!(limbs.len(), BYTES16_LEN, "Invalid length for Bytes16Target");
        Self {
            limbs: limbs.try_into().unwrap(),
        }
    }
}
