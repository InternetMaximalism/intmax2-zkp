use serde::{
    de::{self, SeqAccess, Visitor},
    ser::SerializeTuple as _,
    Deserialize, Deserializer, Serialize,
};

use ark_bn254::{Fq, Fq2, G1Affine, G2Affine};
use ark_ec::AffineRepr;
use plonky2::{
    field::{extension::Extendable, types::Field},
    hash::hash_types::RichField,
    iop::{
        target::{BoolTarget, Target},
        witness::WitnessWrite,
    },
    plonk::circuit_builder::CircuitBuilder,
};
use plonky2_bn254::{
    curves::{g1::G1Target, g2::G2Target},
    fields::fq2::Fq2Target,
};

use crate::ethereum_types::{
    bytes32::Bytes32,
    u256::{U256Target, U256},
    u32limb_trait::{U32LimbTargetTrait as _, U32LimbTrait},
};

#[derive(Clone, Default, Debug, PartialEq)]
pub struct FlatG1(pub [U256; 2]);

impl From<G1Affine> for FlatG1 {
    fn from(affine: G1Affine) -> Self {
        if affine.is_zero() {
            return FlatG1([U256::zero(); 2]);
        }
        let x = affine.x;
        let y = affine.y;
        FlatG1([x.into(), y.into()])
    }
}

impl From<FlatG1> for G1Affine {
    fn from(flat: FlatG1) -> Self {
        if flat.0[0] == U256::zero() && flat.0[1] == U256::zero() {
            G1Affine::zero()
        } else {
            let x: Fq = flat.0[0].into();
            let y: Fq = flat.0[1].into();
            G1Affine::new_unchecked(x, y)
        }
    }
}

impl FlatG1 {
    pub fn to_u32_vec(&self) -> Vec<u32> {
        [self.0[0].to_u32_vec(), self.0[1].to_u32_vec()].concat()
    }
}

#[derive(Clone, Default, Debug, PartialEq)]
pub struct FlatG2(pub [U256; 4]);

impl From<G2Affine> for FlatG2 {
    fn from(affine: G2Affine) -> Self {
        if affine.is_zero() {
            return FlatG2([U256::zero(); 4]);
        }
        let x_c0 = affine.x.c0;
        let x_c1 = affine.x.c1;
        let y_c0 = affine.y.c0;
        let y_c1 = affine.y.c1;
        FlatG2([x_c1.into(), x_c0.into(), y_c1.into(), y_c0.into()])
    }
}

impl From<FlatG2> for G2Affine {
    fn from(flat: FlatG2) -> Self {
        if flat.0[0] == U256::zero()
            && flat.0[1] == U256::zero()
            && flat.0[2] == U256::zero()
            && flat.0[3] == U256::zero()
        {
            G2Affine::zero()
        } else {
            let x_c0: Fq = flat.0[1].into();
            let x_c1: Fq = flat.0[0].into();
            let y_c0: Fq = flat.0[3].into();
            let y_c1: Fq = flat.0[2].into();
            let x = Fq2::new(x_c0, x_c1);
            let y = Fq2::new(y_c0, y_c1);
            G2Affine::new_unchecked(x, y)
        }
    }
}

impl FlatG2 {
    pub fn to_u32_vec(&self) -> Vec<u32> {
        [
            self.0[0].to_u32_vec(),
            self.0[1].to_u32_vec(),
            self.0[2].to_u32_vec(),
            self.0[3].to_u32_vec(),
        ]
        .concat()
    }
}

#[derive(Clone, Debug)]
pub struct FlatG1Target([U256Target; 2]);

impl<F: RichField + Extendable<D>, const D: usize> From<G1Target<F, D>> for FlatG1Target {
    fn from(value: G1Target<F, D>) -> Self {
        let x = value.x.into();
        let y = value.y.into();
        FlatG1Target([x, y])
    }
}

impl<F: RichField + Extendable<D>, const D: usize> From<FlatG1Target> for G1Target<F, D> {
    fn from(flat: FlatG1Target) -> Self {
        let x = flat.0[0].into();
        let y = flat.0[1].into();
        G1Target { x, y }
    }
}

impl FlatG1Target {
    pub fn new<F: RichField + Extendable<D>, const D: usize>(
        builder: &mut CircuitBuilder<F, D>,
        is_checked: bool,
    ) -> Self {
        let x = U256Target::new(builder, is_checked);
        let y = U256Target::new(builder, is_checked);
        FlatG1Target([x, y])
    }

    pub fn constant<F: RichField + Extendable<D>, const D: usize>(
        builder: &mut CircuitBuilder<F, D>,
        value: &FlatG1,
    ) -> Self {
        let x = U256Target::constant(builder, value.0[0]);
        let y = U256Target::constant(builder, value.0[1]);
        FlatG1Target([x, y])
    }

    pub fn to_vec(&self) -> Vec<Target> {
        [self.0[0].to_vec(), self.0[1].to_vec()].concat()
    }

    pub fn is_equal<F: RichField + Extendable<D>, const D: usize>(
        &self,
        builder: &mut CircuitBuilder<F, D>,
        other: &FlatG1Target,
    ) -> BoolTarget {
        let x_eq = self.0[0].is_equal(builder, &other.0[0]);
        let y_eq = self.0[1].is_equal(builder, &other.0[1]);
        builder.and(x_eq, y_eq)
    }

    pub fn set_witness<W: WitnessWrite<F>, F: Field>(&self, witness: &mut W, value: &FlatG1) {
        self.0[0].set_witness(witness, value.0[0]);
        self.0[1].set_witness(witness, value.0[1]);
    }
}

#[derive(Clone, Debug)]
pub struct FlatG2Target([U256Target; 4]);

impl<F: RichField + Extendable<D>, const D: usize> From<G2Target<F, D>> for FlatG2Target {
    fn from(value: G2Target<F, D>) -> Self {
        let x_c0 = value.x.c0.into();
        let x_c1 = value.x.c1.into();
        let y_c0 = value.y.c0.into();
        let y_c1 = value.y.c1.into();
        FlatG2Target([x_c1, x_c0, y_c1, y_c0])
    }
}

impl<F: RichField + Extendable<D>, const D: usize> From<FlatG2Target> for G2Target<F, D> {
    fn from(flat: FlatG2Target) -> Self {
        let x_c0 = flat.0[1].into();
        let x_c1 = flat.0[0].into();
        let y_c0 = flat.0[3].into();
        let y_c1 = flat.0[2].into();
        G2Target {
            x: Fq2Target { c0: x_c0, c1: x_c1 },
            y: Fq2Target { c0: y_c0, c1: y_c1 },
        }
    }
}

impl FlatG2Target {
    pub fn to_vec(&self) -> Vec<Target> {
        [
            self.0[0].to_vec(),
            self.0[1].to_vec(),
            self.0[2].to_vec(),
            self.0[3].to_vec(),
        ]
        .concat()
    }

    pub fn new<F: RichField + Extendable<D>, const D: usize>(
        builder: &mut CircuitBuilder<F, D>,
        is_checked: bool,
    ) -> Self {
        let x_c1 = U256Target::new(builder, is_checked);
        let x_c0 = U256Target::new(builder, is_checked);
        let y_c1 = U256Target::new(builder, is_checked);
        let y_c0 = U256Target::new(builder, is_checked);
        FlatG2Target([x_c1, x_c0, y_c1, y_c0])
    }

    pub fn constant<F: RichField + Extendable<D>, const D: usize>(
        builder: &mut CircuitBuilder<F, D>,
        value: &FlatG2,
    ) -> Self {
        let x_c1 = U256Target::constant(builder, value.0[0]);
        let x_c0 = U256Target::constant(builder, value.0[1]);
        let y_c1 = U256Target::constant(builder, value.0[2]);
        let y_c0 = U256Target::constant(builder, value.0[3]);
        FlatG2Target([x_c1, x_c0, y_c1, y_c0])
    }

    pub fn is_equal<F: RichField + Extendable<D>, const D: usize>(
        &self,
        builder: &mut CircuitBuilder<F, D>,
        other: &FlatG2Target,
    ) -> BoolTarget {
        let mut result = builder._true();
        for i in 0..4 {
            let is_eq = self.0[i].is_equal(builder, &other.0[i]);
            result = builder.and(result, is_eq);
        }
        result
    }

    pub fn set_witness<W: WitnessWrite<F>, F: Field>(&self, witness: &mut W, value: &FlatG2) {
        self.0[0].set_witness(witness, value.0[0]);
        self.0[1].set_witness(witness, value.0[1]);
        self.0[2].set_witness(witness, value.0[2]);
        self.0[3].set_witness(witness, value.0[3]);
    }
}

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
        let x: Bytes32 = seq
            .next_element()?
            .ok_or_else(|| de::Error::invalid_length(0, &self))?;
        let y: Bytes32 = seq
            .next_element()?
            .ok_or_else(|| de::Error::invalid_length(1, &self))?;
        Ok(FlatG1([x.into(), y.into()]))
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
        let x_c1: Bytes32 = seq
            .next_element()?
            .ok_or_else(|| de::Error::invalid_length(0, &self))?;
        let x_c0: Bytes32 = seq
            .next_element()?
            .ok_or_else(|| de::Error::invalid_length(1, &self))?;
        let y_c1: Bytes32 = seq
            .next_element()?
            .ok_or_else(|| de::Error::invalid_length(2, &self))?;
        let y_c0: Bytes32 = seq
            .next_element()?
            .ok_or_else(|| de::Error::invalid_length(3, &self))?;

        Ok(FlatG2([x_c1.into(), x_c0.into(), y_c1.into(), y_c0.into()]))
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
