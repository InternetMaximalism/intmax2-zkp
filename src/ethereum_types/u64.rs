use anyhow::ensure;
use ark_bn254::Fq;
use ark_std::iterable::Iterable;
use num::{BigUint, Num as _, Zero};
use plonky2::{
    field::extension::Extendable,
    hash::hash_types::RichField,
    iop::target::{BoolTarget, Target},
    plonk::circuit_builder::CircuitBuilder,
};
use plonky2_bn254::fields::{biguint::BigUintTarget, fq::FqTarget};
use plonky2_u32::gadgets::{
    arithmetic_u32::{CircuitBuilderU32, U32Target},
    multiple_comparison::list_le_circuit,
};
use rand::Rng;
use serde::{Deserialize, Serialize};

use super::u32limb_trait::{U32LimbTargetTrait, U32LimbTrait};

pub const U64_LEN: usize = 2;

// A structure representing the uint64 type in Ethereum.
// The value is stored in big endian format.
#[derive(Clone, Copy, PartialEq, Eq, Default, Hash)]
pub struct U64 {
    limbs: [u32; U64_LEN],
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct U64Target {
    limbs: [Target; U64_LEN],
}

impl U64Target {
    pub fn from_u32_target<F: RichField + Extendable<D>, const D: usize>(
        builder: &mut CircuitBuilder<F, D>,
        target: Target,
    ) -> Self {
        builder.range_check(target, 32);
        let zero = builder.zero();
        Self {
            limbs: [zero, target],
        }
    }
}

impl core::fmt::Debug for U64 {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let b: BigUint = (*self).into();
        let s = b.to_str_radix(10);
        write!(f, "{}", s)
    }
}

impl core::fmt::Display for U64 {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        core::fmt::Debug::fmt(&self, f)
    }
}

impl Serialize for U64 {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(&self.to_string())
    }
}

impl<'de> Deserialize<'de> for U64 {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let s = String::deserialize(deserializer)?;
        let b = BigUint::from_str_radix(&s, 10).map_err(serde::de::Error::custom)?;
        let u: U64 = b.try_into().unwrap();
        Ok(u)
    }
}

impl PartialOrd for U64 {
    #[inline]
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.limbs.cmp(&other.limbs))
    }
}

impl Ord for U64 {
    #[inline]
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        Iterator::cmp(self.limbs.iter(), other.limbs.iter())
    }
}

impl From<u64> for U64 {
    fn from(value: u64) -> Self {
        let hi = (value >> 32) as u32;
        let lo = value as u32;
        Self { limbs: [hi, lo] }
    }
}

impl From<U64> for u64 {
    fn from(value: U64) -> Self {
        let hi = value.limbs[0] as u64;
        let lo = value.limbs[1] as u64;
        (hi << 32) | lo
    }
}

impl TryFrom<BigUint> for U64 {
    type Error = anyhow::Error;
    fn try_from(value: BigUint) -> anyhow::Result<Self> {
        let mut digits = value.to_u32_digits();
        ensure!(digits.len() <= U64_LEN, "value is too large");
        digits.resize(U64_LEN, 0);
        digits.reverse(); // little endian to big endian
        Ok(Self {
            limbs: digits.try_into().unwrap(),
        })
    }
}

impl From<U64> for BigUint {
    fn from(value: U64) -> Self {
        let mut sum = BigUint::zero();
        for (i, digit) in value.limbs.iter().rev().enumerate() {
            sum += BigUint::from(digit) << (32 * i);
        }
        sum
    }
}

impl From<Fq> for U64 {
    fn from(value: Fq) -> Self {
        // Fq is less than 64 bits, so we can safely convert it to U64
        U64::try_from(BigUint::from(value)).unwrap()
    }
}

impl From<U64> for Fq {
    fn from(value: U64) -> Self {
        Fq::from(BigUint::from(value))
    }
}

impl<F: RichField + Extendable<D>, const D: usize> From<FqTarget<F, D>> for U64Target {
    fn from(value: FqTarget<F, D>) -> Self {
        U64Target::from_slice(
            value
                .value()
                .limbs
                .into_iter()
                .map(|t| t.0)
                .rev()
                .collect::<Vec<_>>()
                .as_slice(),
        )
    }
}

impl<F: RichField + Extendable<D>, const D: usize> From<U64Target> for FqTarget<F, D> {
    fn from(value: U64Target) -> Self {
        FqTarget::from_slice(&value.to_vec().into_iter().rev().collect::<Vec<_>>())
    }
}

impl From<U64Target> for BigUintTarget {
    fn from(value: U64Target) -> Self {
        let limbs = value
            .to_vec()
            .into_iter()
            .rev()
            .map(U32Target)
            .collect::<Vec<_>>();
        BigUintTarget { limbs }
    }
}

impl U32LimbTrait<U64_LEN> for U64 {
    fn to_u32_vec(&self) -> Vec<u32> {
        self.limbs.to_vec()
    }
    fn from_u32_slice(limbs: &[u32]) -> Self {
        Self {
            limbs: limbs.try_into().unwrap(),
        }
    }
}

impl std::ops::Add for U64 {
    type Output = Self;

    fn add(self, rhs: Self) -> Self::Output {
        let mut result_limbs = vec![];
        let mut carry = 0u64;
        for (a, b) in self.limbs.iter().rev().zip(rhs.limbs.iter().rev()) {
            let c = carry + a as u64 + b as u64;
            let result = c as u32;
            carry = c >> 32;
            result_limbs.push(result);
        }

        // Carry should be zero here.
        assert_eq!(carry, 0, "U64 addition overflow occurred");

        result_limbs.reverse();

        Self {
            limbs: result_limbs.try_into().unwrap(),
        }
    }
}

impl std::ops::AddAssign for U64 {
    fn add_assign(&mut self, rhs: Self) {
        *self = *self + rhs;
    }
}

impl std::ops::Sub for U64 {
    type Output = Self;

    fn sub(self, rhs: Self) -> Self::Output {
        let mut result_limbs = vec![];

        let mut borrow = 0i64;
        for (a, b) in self.limbs.iter().rev().zip(rhs.limbs.iter().rev()) {
            let c = a as i64 - b as i64 + borrow;
            let result = c as u32;
            borrow = (c >> 32) as i32 as i64;
            result_limbs.push(result);
        }

        // Borrow should be zero here.
        assert_eq!(borrow, 0, "U64 sub underflow occurred");

        result_limbs.reverse();

        Self {
            limbs: result_limbs.try_into().unwrap(),
        }
    }
}

impl std::ops::SubAssign for U64 {
    fn sub_assign(&mut self, rhs: Self) {
        *self = *self - rhs;
    }
}

impl U64 {
    pub fn rand<T: Rng>(rng: &mut T) -> Self {
        Self { limbs: rng.gen() }
    }
}

impl U32LimbTargetTrait<U64_LEN> for U64Target {
    fn to_vec(&self) -> Vec<Target> {
        self.limbs.to_vec()
    }
    fn from_slice(limbs: &[Target]) -> Self {
        Self {
            limbs: limbs.try_into().unwrap(),
        }
    }
}

impl U64Target {
    pub fn add<F: RichField + Extendable<D>, const D: usize>(
        &self,
        builder: &mut CircuitBuilder<F, D>,
        other: &Self,
    ) -> Self {
        let zero = builder.zero_u32();
        let mut combined_limbs = vec![];
        let mut carry = zero;
        for (a, b) in self.limbs.iter().rev().zip(other.limbs.iter().rev()) {
            let (new_limb, new_carry) = builder.add_many_u32(&[carry, U32Target(a), U32Target(b)]);
            carry = new_carry;
            combined_limbs.push(new_limb);
        }
        // Carry should be zero here.
        builder.connect_u32(carry, zero);
        combined_limbs.reverse();
        Self {
            limbs: combined_limbs
                .iter()
                .map(|t| t.0)
                .collect::<Vec<_>>()
                .try_into()
                .unwrap(),
        }
    }

    pub fn sub<F: RichField + Extendable<D>, const D: usize>(
        &self,
        builder: &mut CircuitBuilder<F, D>,
        other: &Self,
    ) -> Self {
        let zero = builder.zero_u32();
        let mut result_limbs = vec![];

        let mut borrow = zero;
        for (a, b) in self.limbs.iter().rev().zip(other.limbs.iter().rev()) {
            let (result, new_borrow) = builder.sub_u32(U32Target(a), U32Target(b), borrow);
            result_limbs.push(result);
            borrow = new_borrow;
        }

        // Borrow should be zero here.
        builder.connect_u32(borrow, zero);
        result_limbs.reverse();

        Self {
            limbs: result_limbs
                .iter()
                .map(|t| t.0)
                .collect::<Vec<_>>()
                .try_into()
                .unwrap(),
        }
    }

    /// returns true if self <= other and false otherwise
    pub fn is_le<F: RichField + Extendable<D>, const D: usize>(
        &self,
        builder: &mut CircuitBuilder<F, D>,
        other: &Self,
    ) -> BoolTarget {
        list_le_circuit(
            builder,
            self.limbs.iter().rev().collect(),
            other.limbs.iter().rev().collect(),
            32,
        )
    }

    /// returns true if self < other and false otherwise
    pub fn is_lt<F: RichField + Extendable<D>, const D: usize>(
        &self,
        builder: &mut CircuitBuilder<F, D>,
        other: &Self,
    ) -> BoolTarget {
        let is_le = self.is_le(builder, other);
        let is_eq = self.is_equal(builder, other);
        let is_not_eq = builder.not(is_eq);
        builder.and(is_le, is_not_eq)
    }
}

#[cfg(test)]
mod tests {
    use num_bigint::BigUint;
    use plonky2::{
        field::goldilocks_field::GoldilocksField,
        iop::witness::{PartialWitness, WitnessWrite},
        plonk::{
            circuit_builder::CircuitBuilder, circuit_data::CircuitConfig,
            config::PoseidonGoldilocksConfig,
        },
    };

    use crate::ethereum_types::{
        u32limb_trait::{U32LimbTargetTrait, U32LimbTrait as _},
        u64::U64,
    };

    use super::U64Target;

    type F = GoldilocksField;
    const D: usize = 2;
    type C = PoseidonGoldilocksConfig;

    #[test]
    fn u64_display() {
        let u = U64::try_from(BigUint::from(123u64)).unwrap();
        assert_eq!(format!("{}", u), "123");
    }

    #[test]
    fn u64_order() {
        let a = U64::from_u32_slice(&[0, 2]);
        let b = U64::from_u32_slice(&[1, 1]);
        assert!(a < b);
    }

    #[test]
    fn u64_add_sub() {
        let a = U64::from_u32_slice(&[1, 2]);
        let b = U64::from_u32_slice(&[0, u32::MAX]);
        let c = U64::from_u32_slice(&[2, 1]);
        let d = U64::from_u32_slice(&[0, 3]);
        assert_eq!(a + b, c);
        assert_eq!(a - b, d);
    }

    #[test]
    #[should_panic]
    fn u64_sub_underflow() {
        let a = U64::from_u32_slice(&[1, 2]);
        let b = U64::from_u32_slice(&[0, u32::MAX]);

        _ = b - a;
    }

    #[test]
    fn u64_le() {
        let a = U64::from_u32_slice(&[1, 2]);
        let b = U64::from_u32_slice(&[0, u32::MAX]);

        let mut builder = CircuitBuilder::<F, D>::new(CircuitConfig::default());
        let a_t = U64Target::constant(&mut builder, a);
        let b_t = U64Target::constant(&mut builder, b);
        let le_ab = a_t.is_le(&mut builder, &b_t);
        let le_aa = a_t.is_le(&mut builder, &a_t);

        let mut pw = PartialWitness::new();
        pw.set_bool_target(le_ab, a <= b);
        pw.set_bool_target(le_aa, a <= a);
        let circuit = builder.build::<C>();
        circuit.prove(pw).unwrap();
    }

    #[test]
    fn u64_add_sub_circuit() {
        let mut rng = rand::thread_rng();
        let a = U64::rand(&mut rng);
        let b = U64::try_from(BigUint::from(1u64)).unwrap();
        let a_plus_b = a + b;
        let a_minus_b = a - b;

        let mut builder = CircuitBuilder::<F, D>::new(CircuitConfig::default());
        let a_t = U64Target::constant(&mut builder, a);
        let b_t = U64Target::constant(&mut builder, b);
        let a_plus_b_t = a_t.add(&mut builder, &b_t);
        let a_minus_b_t = a_t.sub(&mut builder, &b_t);
        let mut pw = PartialWitness::new();
        a_minus_b_t.set_witness(&mut pw, a_minus_b);
        a_plus_b_t.set_witness(&mut pw, a_plus_b);
        let circuit = builder.build::<C>();
        circuit.prove(pw).unwrap();
    }
}
