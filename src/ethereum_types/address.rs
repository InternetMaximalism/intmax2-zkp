use std::str::FromStr;

use plonky2::iop::target::Target;
use serde::{Deserialize, Serialize};

use super::u32limb_trait::{U32LimbTargetTrait, U32LimbTrait};

pub const ADDRESS_LEN: usize = 5;

/// A structure representing the address type in Ethereum.
/// The value is stored in big endian format.
#[derive(Clone, Copy, PartialEq, Default, Hash)]
pub struct Address {
    limbs: [u32; ADDRESS_LEN],
}

#[derive(Clone, Copy, Debug)]
pub struct AddressTarget {
    limbs: [Target; ADDRESS_LEN],
}

impl core::fmt::Debug for Address {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.to_hex())
    }
}

impl core::fmt::Display for Address {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        core::fmt::Debug::fmt(&self, f)
    }
}

impl FromStr for Address {
    type Err = anyhow::Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Self::from_hex(s).map_err(|e| anyhow::anyhow!("Failed to parse Address: {}", e))
    }
}

impl Serialize for Address {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(&self.to_string())
    }
}

impl<'de> Deserialize<'de> for Address {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let s = String::deserialize(deserializer)?;
        let value = Self::from_hex(&s).map_err(serde::de::Error::custom)?;
        Ok(value)
    }
}

impl U32LimbTrait<ADDRESS_LEN> for Address {
    fn to_u32_vec(&self) -> Vec<u32> {
        self.limbs.to_vec()
    }

    fn from_u32_slice(limbs: &[u32]) -> super::u32limb_trait::Result<Self> {
        if limbs.len() != ADDRESS_LEN {
            return Err(super::u32limb_trait::U32LimbError::InvalidLength(limbs.len()));
        }
        Ok(Self {
            limbs: limbs.try_into().map_err(|_| super::u32limb_trait::U32LimbError::InvalidLength(limbs.len()))?,
        })
    }
}

impl U32LimbTargetTrait<ADDRESS_LEN> for AddressTarget {
    fn to_vec(&self) -> Vec<Target> {
        self.limbs.to_vec()
    }

    fn from_slice(limbs: &[Target]) -> Self {
        assert_eq!(limbs.len(), ADDRESS_LEN, "Invalid length for AddressTarget");
        Self {
            limbs: limbs.try_into().unwrap(),
        }
    }
}
