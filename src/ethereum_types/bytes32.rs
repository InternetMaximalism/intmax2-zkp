use std::{fmt::Debug, str::FromStr};

use plonky2::iop::target::Target;
use serde::{Deserialize, Serialize};

use super::{
    u256::{U256, U256_LEN},
    u32limb_trait::{U32LimbTargetTrait, U32LimbTrait},
};

pub const BYTES32_LEN: usize = U256_LEN;

// A structure representing the bytes32 type in Ethereum.
// The value is stored in big endian format.
#[derive(Clone, Copy, PartialEq, Eq, Default, Hash)]
pub struct Bytes32 {
    limbs: [u32; BYTES32_LEN],
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Bytes32Target {
    limbs: [Target; BYTES32_LEN],
}

impl core::fmt::Debug for Bytes32 {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.to_hex())
    }
}

impl core::fmt::Display for Bytes32 {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        core::fmt::Debug::fmt(&self, f)
    }
}

impl FromStr for Bytes32 {
    type Err = anyhow::Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Self::from_hex(s).map_err(|e| anyhow::anyhow!("Failed to parse Bytes32: {}", e))
    }
}

impl Serialize for Bytes32 {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(&self.to_string())
    }
}

impl<'de> Deserialize<'de> for Bytes32 {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let s = String::deserialize(deserializer)?;
        let value = Self::from_hex(&s).map_err(serde::de::Error::custom)?;
        Ok(value)
    }
}

impl From<U256> for Bytes32 {
    fn from(value: U256) -> Self {
        Bytes32::from_u32_slice(&value.to_u32_vec()).expect("Converting from U256 to Bytes32 should never fail")
    }
}

impl From<Bytes32> for U256 {
    fn from(value: Bytes32) -> Self {
        U256::from_u32_slice(&value.to_u32_vec()).expect("Converting from Bytes32 to U256 should never fail")
    }
}

impl U32LimbTrait<BYTES32_LEN> for Bytes32 {
    fn to_u32_vec(&self) -> Vec<u32> {
        self.limbs.to_vec()
    }

    fn from_u32_slice(limbs: &[u32]) -> super::u32limb_trait::Result<Self> {
        if limbs.len() != BYTES32_LEN {
            return Err(super::u32limb_trait::U32LimbError::InvalidLength(limbs.len()));
        }
        Ok(Self {
            limbs: limbs.try_into().map_err(|_| super::u32limb_trait::U32LimbError::InvalidLength(limbs.len()))?,
        })
    }
}

impl U32LimbTargetTrait<BYTES32_LEN> for Bytes32Target {
    fn to_vec(&self) -> Vec<Target> {
        self.limbs.to_vec()
    }

    fn from_slice(limbs: &[Target]) -> Self {
        assert_eq!(limbs.len(), BYTES32_LEN, "Invalid length for Bytes32Target");
        Self {
            limbs: limbs.try_into().unwrap(),
        }
    }
}
