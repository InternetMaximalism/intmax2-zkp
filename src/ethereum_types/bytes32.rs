use std::fmt::Debug;

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

#[derive(Clone, Copy, Debug)]
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
        Bytes32::from_slice(&value.limbs())
    }
}

impl From<Bytes32> for U256 {
    fn from(value: Bytes32) -> Self {
        U256::from_slice(&value.limbs())
    }
}

impl U32LimbTrait<BYTES32_LEN> for Bytes32 {
    fn limbs(&self) -> Vec<u32> {
        self.limbs.to_vec()
    }

    fn from_slice(limbs: &[u32]) -> Self {
        Self {
            limbs: limbs.try_into().unwrap(),
        }
    }
}

impl U32LimbTargetTrait<BYTES32_LEN> for Bytes32Target {
    fn limbs(&self) -> Vec<Target> {
        self.limbs.to_vec()
    }

    fn from_slice(limbs: &[Target]) -> Self {
        Self {
            limbs: limbs.try_into().unwrap(),
        }
    }
}
