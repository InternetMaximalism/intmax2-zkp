use std::str::FromStr;

use num::{BigUint, Zero as _};
use plonky2::iop::target::Target;
use serde::{Deserialize, Serialize};

use super::{
    error::EthereumTypeError,
    u32limb_trait::{self, U32LimbTargetTrait, U32LimbTrait},
};

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
    type Err = EthereumTypeError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Self::from_hex(s).map_err(|e| {
            EthereumTypeError::HexParseError(format!("Failed to parse Bytes16: {}", e))
        })
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
    type Error = EthereumTypeError;

    fn try_from(value: BigUint) -> Result<Self, Self::Error> {
        let mut digits = value.to_u32_digits();
        if digits.len() > BYTES16_LEN {
            return Err(EthereumTypeError::ValueTooLarge(format!(
                "Value has {} digits, but Bytes16 can only hold {}",
                digits.len(),
                BYTES16_LEN
            )));
        }
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

    fn from_u32_slice(limbs: &[u32]) -> u32limb_trait::Result<Self> {
        if limbs.len() != BYTES16_LEN {
            return Err(EthereumTypeError::InvalidLengthSimple(limbs.len()));
        }
        Ok(Self {
            limbs: limbs
                .try_into()
                .map_err(|_| EthereumTypeError::InvalidLengthSimple(limbs.len()))?,
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_bytes16_from_str() {
        // Test empty bytes16
        let bytes16 = Bytes16::from_hex("0x").unwrap();
        assert_eq!(bytes16, Bytes16::default());

        // Test valid bytes16
        let bytes16 = Bytes16::from_hex("0x1234567890abcdef1234567890abcdef").unwrap();
        assert_eq!(
            bytes16.to_u32_vec(),
            vec![0x12345678, 0x90abcdef, 0x12345678, 0x90abcdef]
        );

        // Test bytes16 without 0x prefix
        let bytes16 = Bytes16::from_hex("1234567890abcdef1234567890abcdef").unwrap();
        assert_eq!(
            bytes16.to_u32_vec(),
            vec![0x12345678, 0x90abcdef, 0x12345678, 0x90abcdef]
        );
    }

    #[test]
    fn test_bytes16_display() {
        let bytes16 = Bytes16::from_u32_slice(&[0x12345678, 0x90abcdef, 0x12345678, 0x90abcdef]).unwrap();
        assert_eq!(
            format!("{}", bytes16),
            "0x1234567890abcdef1234567890abcdef"
        );
    }

    #[test]
    fn test_bytes16_serialize_deserialize() {
        let bytes16 = Bytes16::from_u32_slice(&[0x12345678, 0x90abcdef, 0x12345678, 0x90abcdef]).unwrap();
        let serialized = serde_json::to_string(&bytes16).unwrap();
        let deserialized: Bytes16 = serde_json::from_str(&serialized).unwrap();
        assert_eq!(bytes16, deserialized);
    }

    #[test]
    fn test_bytes16_from_u32_slice() {
        // Test valid slice
        let bytes16 = Bytes16::from_u32_slice(&[0x12345678, 0x90abcdef, 0x12345678, 0x90abcdef]).unwrap();
        assert_eq!(
            bytes16.to_u32_vec(),
            vec![0x12345678, 0x90abcdef, 0x12345678, 0x90abcdef]
        );

        // Test invalid slice length
        let result = Bytes16::from_u32_slice(&[0x12345678, 0x90abcdef, 0x12345678]);
        assert!(result.is_err());
        if let Err(EthereumTypeError::InvalidLengthSimple(len)) = result {
            assert_eq!(len, 3);
        } else {
            panic!("Expected InvalidLengthSimple error");
        }
    }

    #[test]
    fn test_bytes16_to_from_bytes() {
        let original = Bytes16::from_u32_slice(&[0x12345678, 0x90abcdef, 0x12345678, 0x90abcdef]).unwrap();
        let bytes = original.to_bytes_be();
        let recovered = Bytes16::from_bytes_be(&bytes).unwrap();
        assert_eq!(original, recovered);
    }

    #[test]
    fn test_bytes16_to_from_bits() {
        let original = Bytes16::from_u32_slice(&[0x12345678, 0x90abcdef, 0x12345678, 0x90abcdef]).unwrap();
        let bits = original.to_bits_be();
        let recovered = Bytes16::from_bits_be(&bits).unwrap();
        assert_eq!(original, recovered);
    }

    #[test]
    fn test_bytes16_random() {
        let mut rng = rand::thread_rng();
        let bytes16 = Bytes16::rand(&mut rng);
        
        // Verify that the random bytes16 can be converted to and from bytes
        let bytes = bytes16.to_bytes_be();
        let recovered = Bytes16::from_bytes_be(&bytes).unwrap();
        assert_eq!(bytes16, recovered);
    }

    #[test]
    fn test_bytes16_biguint_conversion() {
        // Test conversion from BigUint to Bytes16
        let biguint = BigUint::from(0x1234567890abcdefu64);
        let bytes16 = Bytes16::try_from(biguint.clone()).unwrap();
        
        // Test conversion from Bytes16 back to BigUint
        let recovered_biguint = BigUint::from(bytes16);
        assert_eq!(biguint, recovered_biguint);
        
        // Test value too large
        let large_biguint = BigUint::from(1u8) << 128;
        let result = Bytes16::try_from(large_biguint);
        assert!(result.is_err());
        if let Err(EthereumTypeError::ValueTooLarge(_)) = result {
            // Expected error
        } else {
            panic!("Expected ValueTooLarge error");
        }
    }
}
