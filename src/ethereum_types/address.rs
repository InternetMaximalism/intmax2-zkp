use std::str::FromStr;

use plonky2::iop::target::Target;
use serde::{Deserialize, Serialize};

use super::{
    error::EthereumTypeError,
    u32limb_trait::{self, U32LimbTargetTrait, U32LimbTrait},
};

pub const ADDRESS_LEN: usize = 5;

/// A structure representing the address type in Ethereum.
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
    type Err = EthereumTypeError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Self::from_hex(s).map_err(|e| {
            EthereumTypeError::HexParseError(format!("Failed to parse Address: {}", e))
        })
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

    fn from_u32_slice(limbs: &[u32]) -> u32limb_trait::Result<Self> {
        if limbs.len() != ADDRESS_LEN {
            return Err(EthereumTypeError::InvalidLengthSimple(limbs.len()));
        }
        Ok(Self {
            limbs: limbs.try_into().unwrap(),
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_address_from_str() {
        // Test empty address
        let address = Address::from_hex("0x").unwrap();
        assert_eq!(address, Address::default());

        // Test valid address
        let address = Address::from_hex("0x1234567890abcdef1234567890abcdef12345678").unwrap();
        assert_eq!(
            address.to_u32_vec(),
            vec![0x12345678, 0x90abcdef, 0x12345678, 0x90abcdef, 0x12345678]
        );

        // Test address without 0x prefix
        let address = Address::from_hex("1234567890abcdef1234567890abcdef12345678").unwrap();
        assert_eq!(
            address.to_u32_vec(),
            vec![0x12345678, 0x90abcdef, 0x12345678, 0x90abcdef, 0x12345678]
        );
    }

    #[test]
    fn test_address_display() {
        let address =
            Address::from_u32_slice(&[0x12345678, 0x90abcdef, 0x12345678, 0x90abcdef, 0x12345678])
                .unwrap();
        assert_eq!(
            format!("{}", address),
            "0x1234567890abcdef1234567890abcdef12345678"
        );
    }

    #[test]
    fn test_address_serialize_deserialize() {
        let address =
            Address::from_u32_slice(&[0x12345678, 0x90abcdef, 0x12345678, 0x90abcdef, 0x12345678])
                .unwrap();
        let serialized = serde_json::to_string(&address).unwrap();
        let deserialized: Address = serde_json::from_str(&serialized).unwrap();
        assert_eq!(address, deserialized);
    }

    #[test]
    fn test_address_from_u32_slice() {
        // Test valid slice
        let address =
            Address::from_u32_slice(&[0x12345678, 0x90abcdef, 0x12345678, 0x90abcdef, 0x12345678])
                .unwrap();
        assert_eq!(
            address.to_u32_vec(),
            vec![0x12345678, 0x90abcdef, 0x12345678, 0x90abcdef, 0x12345678]
        );

        // Test invalid slice length
        let result = Address::from_u32_slice(&[0x12345678, 0x90abcdef, 0x12345678, 0x90abcdef]);
        assert!(result.is_err());
        if let Err(EthereumTypeError::InvalidLengthSimple(len)) = result {
            assert_eq!(len, 4);
        } else {
            panic!("Expected InvalidLengthSimple error");
        }
    }

    #[test]
    fn test_address_to_from_bytes() {
        let original =
            Address::from_u32_slice(&[0x12345678, 0x90abcdef, 0x12345678, 0x90abcdef, 0x12345678])
                .unwrap();
        let bytes = original.to_bytes_be();
        let recovered = Address::from_bytes_be(&bytes).unwrap();
        assert_eq!(original, recovered);
    }

    #[test]
    fn test_address_to_from_bits() {
        let original =
            Address::from_u32_slice(&[0x12345678, 0x90abcdef, 0x12345678, 0x90abcdef, 0x12345678])
                .unwrap();
        let bits = original.to_bits_be();
        let recovered = Address::from_bits_be(&bits).unwrap();
        assert_eq!(original, recovered);
    }

    #[test]
    fn test_address_random() {
        let mut rng = rand::thread_rng();
        let address = Address::rand(&mut rng);

        // Verify that the random address can be converted to and from bytes
        let bytes = address.to_bytes_be();
        let recovered = Address::from_bytes_be(&bytes).unwrap();
        assert_eq!(address, recovered);
    }
}
