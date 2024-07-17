use serde::{
    de::{self, SeqAccess, Visitor},
    ser::SerializeTuple as _,
    Deserialize, Deserializer, Serialize,
};

use crate::ethereum_types::bytes32::Bytes32;

use super::flatten::{FlatG1, FlatG2};

// Serialize is designed to match the format of the pairing precompile in Solidity.
impl Serialize for FlatG1 {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        let mut seq = serializer.serialize_tuple(2)?;
        seq.serialize_element(&Bytes32::from(self.0[0]))?;
        seq.serialize_element(&Bytes32::from(self.0[1]))?;
        seq.end()
    }
}

impl Serialize for FlatG2 {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        let mut seq = serializer.serialize_tuple(4)?;
        seq.serialize_element(&Bytes32::from(self.0[0]))?;
        seq.serialize_element(&Bytes32::from(self.0[1]))?;
        seq.serialize_element(&Bytes32::from(self.0[2]))?;
        seq.serialize_element(&Bytes32::from(self.0[3]))?;
        seq.end()
    }
}

struct CurveVisitor<const N: usize>;

impl<'de> Visitor<'de> for CurveVisitor<2> {
    type Value = FlatG1;

    fn expecting(&self, formatter: &mut core::fmt::Formatter) -> core::fmt::Result {
        formatter.write_str("a tuple of length 2")
    }

    fn visit_seq<A>(self, mut seq: A) -> Result<Self::Value, A::Error>
    where
        A: SeqAccess<'de>,
    {
        let first = seq
            .next_element()?
            .ok_or_else(|| de::Error::invalid_length(0, &self))?;
        let second = seq
            .next_element()?
            .ok_or_else(|| de::Error::invalid_length(1, &self))?;
        Ok(FlatG1([first, second]))
    }
}

impl<'de> Visitor<'de> for CurveVisitor<4> {
    type Value = FlatG2;

    fn expecting(&self, formatter: &mut core::fmt::Formatter) -> core::fmt::Result {
        formatter.write_str("a tuple of length 4")
    }

    fn visit_seq<A>(self, mut seq: A) -> Result<Self::Value, A::Error>
    where
        A: SeqAccess<'de>,
    {
        let x_c1 = seq
            .next_element()?
            .ok_or_else(|| de::Error::invalid_length(0, &self))?;
        let x_c0 = seq
            .next_element()?
            .ok_or_else(|| de::Error::invalid_length(1, &self))?;
        let y_c1 = seq
            .next_element()?
            .ok_or_else(|| de::Error::invalid_length(2, &self))?;
        let y_c0 = seq
            .next_element()?
            .ok_or_else(|| de::Error::invalid_length(3, &self))?;

        Ok(FlatG2([x_c1, x_c0, y_c1, y_c0]))
    }
}

impl<'de> Deserialize<'de> for FlatG1 {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        deserializer.deserialize_tuple(2, CurveVisitor::<2>)
    }
}

impl<'de> Deserialize<'de> for FlatG2 {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        deserializer.deserialize_tuple(4, CurveVisitor::<4>)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ethereum_types::u256::U256;

    #[test]
    fn test_flat_serde() {
        let flat_g1 = FlatG1([U256::from(1), U256::from(2)]);
        let flat_g1_str = serde_json::to_string(&flat_g1).unwrap();

        let flat_g1_de: FlatG1 = serde_json::from_str(&flat_g1_str).unwrap();
        assert_eq!(flat_g1, flat_g1_de);

        let flat_g2 = FlatG2([U256::from(1), U256::from(2), U256::from(3), U256::from(4)]);
        let flat_g2_str = serde_json::to_string(&flat_g2).unwrap();

        let flat_g2_de: FlatG2 = serde_json::from_str(&flat_g2_str).unwrap();
        assert_eq!(flat_g2, flat_g2_de);
    }
}
