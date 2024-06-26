use plonky2::iop::target::Target;
use serde::{Deserialize, Serialize};

use super::{
    u256::U256_LEN,
    u32limb_trait::{U32LimbTargetTrait, U32LimbTrait},
};

pub const BYTES32_LEN: usize = U256_LEN;

// A structure representing the bytes32 type in Ethereum.
// `T` is either `u32` or `U32Target`.
// The value is stored in big endian format.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Default, Hash)]
pub struct Bytes32<T: Clone + Copy> {
    limbs: [T; BYTES32_LEN],
}

impl std::fmt::Display for Bytes32<u32> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.to_hex())
    }
}

impl Serialize for Bytes32<u32> {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(&self.to_hex())
    }
}

impl<'de> Deserialize<'de> for Bytes32<u32> {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let s = String::deserialize(deserializer)?;
        Ok(Self::from_hex(&s))
    }
}

impl U32LimbTrait<BYTES32_LEN> for Bytes32<u32> {
    fn limbs(&self) -> Vec<u32> {
        self.limbs.to_vec()
    }

    fn from_limbs(limbs: &[u32]) -> Self {
        Self {
            limbs: limbs.try_into().unwrap(),
        }
    }
}

impl U32LimbTargetTrait<BYTES32_LEN> for Bytes32<Target> {
    fn limbs(&self) -> Vec<Target> {
        self.limbs.to_vec()
    }

    fn from_limbs(limbs: &[Target]) -> Self {
        Self {
            limbs: limbs.try_into().unwrap(),
        }
    }
}
