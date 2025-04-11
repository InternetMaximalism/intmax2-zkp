use std::{fmt::Debug, str::FromStr};

use plonky2::iop::target::Target;
use serde::{Deserialize, Serialize};

use super::{
    error::EthereumTypeError,
    u256::{U256, U256_LEN},
    u32limb_trait::{self, U32LimbTargetTrait, U32LimbTrait},
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
    type Err = EthereumTypeError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Self::from_hex(s).map_err(|e| {
            EthereumTypeError::HexParseError(format!("Failed to parse Bytes32: {}", e))
        })
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
        Bytes32::from_u32_slice(&value.to_u32_vec())
            .expect("Converting from U256 to Bytes32 should never fail")
    }
}

impl From<Bytes32> for U256 {
    fn from(value: Bytes32) -> Self {
        U256::from_u32_slice(&value.to_u32_vec())
            .expect("Converting from Bytes32 to U256 should never fail")
    }
}

impl U32LimbTrait<BYTES32_LEN> for Bytes32 {
    fn to_u32_vec(&self) -> Vec<u32> {
        self.limbs.to_vec()
    }

    fn from_u32_slice(limbs: &[u32]) -> u32limb_trait::Result<Self> {
        if limbs.len() != BYTES32_LEN {
            return Err(EthereumTypeError::InvalidLengthSimple(limbs.len()));
        }
        Ok(Self {
            limbs: limbs
                .try_into()
                .map_err(|_| EthereumTypeError::InvalidLengthSimple(limbs.len()))?,
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_bytes32_from_str() {
        // Test empty bytes32
        let bytes32 = Bytes32::from_hex("0x").unwrap();
        assert_eq!(bytes32, Bytes32::default());

        // Test valid bytes32
        let hex_str = "0x1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef";
        let bytes32 = Bytes32::from_hex(hex_str).unwrap();
        assert_eq!(
            bytes32.to_u32_vec(),
            vec![
                0x12345678, 0x90abcdef, 0x12345678, 0x90abcdef,
                0x12345678, 0x90abcdef, 0x12345678, 0x90abcdef
            ]
        );

        // Test bytes32 without 0x prefix
        let hex_str = "1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef";
        let bytes32 = Bytes32::from_hex(hex_str).unwrap();
        assert_eq!(
            bytes32.to_u32_vec(),
            vec![
                0x12345678, 0x90abcdef, 0x12345678, 0x90abcdef,
                0x12345678, 0x90abcdef, 0x12345678, 0x90abcdef
            ]
        );

        // Test invalid hex string
        let result = Bytes32::from_hex("0xZZZ");
        assert!(result.is_err());
        if let Err(EthereumTypeError::InvalidHex(_)) = result {
            // Expected error
        } else {
            panic!("Expected InvalidHex error");
        }
    }

    #[test]
    fn test_bytes32_display() {
        let limbs = [
            0x12345678, 0x90abcdef, 0x12345678, 0x90abcdef,
            0x12345678, 0x90abcdef, 0x12345678, 0x90abcdef
        ];
        let bytes32 = Bytes32::from_u32_slice(&limbs).unwrap();
        assert_eq!(
            format!("{}", bytes32),
            "0x1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef"
        );
    }

    #[test]
    fn test_bytes32_serialize_deserialize() {
        let limbs = [
            0x12345678, 0x90abcdef, 0x12345678, 0x90abcdef,
            0x12345678, 0x90abcdef, 0x12345678, 0x90abcdef
        ];
        let bytes32 = Bytes32::from_u32_slice(&limbs).unwrap();
        let serialized = serde_json::to_string(&bytes32).unwrap();
        let deserialized: Bytes32 = serde_json::from_str(&serialized).unwrap();
        assert_eq!(bytes32, deserialized);
    }

    #[test]
    fn test_bytes32_from_u32_slice() {
        // Test valid slice
        let limbs = [
            0x12345678, 0x90abcdef, 0x12345678, 0x90abcdef,
            0x12345678, 0x90abcdef, 0x12345678, 0x90abcdef
        ];
        let bytes32 = Bytes32::from_u32_slice(&limbs).unwrap();
        assert_eq!(bytes32.to_u32_vec(), limbs.to_vec());

        // Test invalid slice length
        let result = Bytes32::from_u32_slice(&limbs[0..7]);
        assert!(result.is_err());
        if let Err(EthereumTypeError::InvalidLengthSimple(len)) = result {
            assert_eq!(len, 7);
        } else {
            panic!("Expected InvalidLengthSimple error");
        }
    }

    #[test]
    fn test_bytes32_to_from_bytes() {
        let limbs = [
            0x12345678, 0x90abcdef, 0x12345678, 0x90abcdef,
            0x12345678, 0x90abcdef, 0x12345678, 0x90abcdef
        ];
        let original = Bytes32::from_u32_slice(&limbs).unwrap();
        let bytes = original.to_bytes_be();
        let recovered = Bytes32::from_bytes_be(&bytes).unwrap();
        assert_eq!(original, recovered);
    }

    #[test]
    fn test_bytes32_to_from_bits() {
        let limbs = [
            0x12345678, 0x90abcdef, 0x12345678, 0x90abcdef,
            0x12345678, 0x90abcdef, 0x12345678, 0x90abcdef
        ];
        let original = Bytes32::from_u32_slice(&limbs).unwrap();
        let bits = original.to_bits_be();
        let recovered = Bytes32::from_bits_be(&bits).unwrap();
        assert_eq!(original, recovered);
    }

    #[test]
    fn test_bytes32_random() {
        let mut rng = rand::thread_rng();
        let bytes32 = Bytes32::rand(&mut rng);
        
        // Verify that the random bytes32 can be converted to and from bytes
        let bytes = bytes32.to_bytes_be();
        let recovered = Bytes32::from_bytes_be(&bytes).unwrap();
        assert_eq!(bytes32, recovered);
    }

    #[test]
    fn test_bytes32_u256_conversion() {
        // Create a U256 value
        let u256_value = U256::from_u32_slice(&[
            0x12345678, 0x90abcdef, 0x12345678, 0x90abcdef,
            0x12345678, 0x90abcdef, 0x12345678, 0x90abcdef
        ]).unwrap();
        
        // Convert to Bytes32
        let bytes32_value: Bytes32 = u256_value.into();
        
        // Convert back to U256
        let recovered_u256: U256 = bytes32_value.into();
        
        // Verify the round-trip conversion
        assert_eq!(u256_value, recovered_u256);
    }

    #[test]
    fn test_bytes32_target() {
        use plonky2::{
            field::goldilocks_field::GoldilocksField,
            iop::witness::PartialWitness,
            plonk::{
                circuit_builder::CircuitBuilder, circuit_data::CircuitConfig,
                config::PoseidonGoldilocksConfig,
            },
        };

        type F = GoldilocksField;
        const D: usize = 2;
        type C = PoseidonGoldilocksConfig;

        let limbs = [
            0x12345678, 0x90abcdef, 0x12345678, 0x90abcdef,
            0x12345678, 0x90abcdef, 0x12345678, 0x90abcdef
        ];
        let bytes32 = Bytes32::from_u32_slice(&limbs).unwrap();
        
        let mut builder = CircuitBuilder::<F, D>::new(CircuitConfig::default());
        let bytes32_target = Bytes32Target::constant::<F, D, Bytes32>(&mut builder, bytes32);
        
        let mut pw = PartialWitness::new();
        bytes32_target.set_witness(&mut pw, bytes32);
        
        let circuit = builder.build::<C>();
        circuit.prove(pw).unwrap();
    }
}
