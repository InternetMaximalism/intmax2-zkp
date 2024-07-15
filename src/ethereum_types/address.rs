use plonky2::iop::target::Target;
use serde::{Deserialize, Serialize};

use super::u32limb_trait::{U32LimbTargetTrait, U32LimbTrait};

pub const ADDRESS_LEN: usize = 5;

/// A structure representing the address type in Ethereum.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Default, Hash)]
pub struct Address {
    limbs: [u32; ADDRESS_LEN],
}

#[derive(Clone, Copy, Debug)]
pub struct AddressTarget {
    limbs: [Target; ADDRESS_LEN],
}

impl std::fmt::Display for Address {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.to_hex())
    }
}

impl Serialize for Address {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(&self.to_hex())
    }
}

impl<'de> Deserialize<'de> for Address {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let s = String::deserialize(deserializer)?;
        Ok(Self::from_hex(&s))
    }
}

impl U32LimbTrait<ADDRESS_LEN> for Address {
    fn limbs(&self) -> Vec<u32> {
        self.limbs.to_vec()
    }

    fn from_limbs(limbs: &[u32]) -> Self {
        Self {
            limbs: limbs.try_into().unwrap(),
        }
    }
}

impl U32LimbTargetTrait<ADDRESS_LEN> for AddressTarget {
    fn limbs(&self) -> Vec<Target> {
        self.limbs.to_vec()
    }

    fn from_limbs(limbs: &[Target]) -> Self {
        Self {
            limbs: limbs.try_into().unwrap(),
        }
    }
}
