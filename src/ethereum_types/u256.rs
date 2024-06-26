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

pub const U256_LEN: usize = 8;

// A structure representing the uint256 type in Ethereum.
// `T` is either `u32` or `U32Target`.
// The value is stored in big endian format.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Default, Hash)]
pub struct U256<T: Clone + Copy> {
    limbs: [T; U256_LEN],
}

impl std::fmt::Display for U256<u32> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let b: BigUint = (*self).into();
        let s = b.to_str_radix(10);
        write!(f, "{}", s)
    }
}

impl Serialize for U256<u32> {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        let b: BigUint = (*self).into();
        let s = b.to_str_radix(10);
        serializer.serialize_str(&s)
    }
}

impl<'de> Deserialize<'de> for U256<u32> {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let s = String::deserialize(deserializer)?;
        let b = BigUint::from_str_radix(&s, 10).map_err(serde::de::Error::custom)?;
        let u: U256<u32> = b.try_into().unwrap();
        Ok(u)
    }
}

impl PartialOrd for U256<u32> {
    #[inline]
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.limbs.cmp(&other.limbs))
    }
}

impl Ord for U256<u32> {
    #[inline]
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        Iterator::cmp(self.limbs.iter(), other.limbs.iter())
    }
}

impl TryFrom<BigUint> for U256<u32> {
    type Error = anyhow::Error;
    fn try_from(value: BigUint) -> anyhow::Result<Self> {
        let mut digits = value.to_u32_digits();
        ensure!(digits.len() <= U256_LEN, "value is too large");
        digits.resize(U256_LEN, 0);
        digits.reverse(); // little endian to big endian
        Ok(Self {
            limbs: digits.try_into().unwrap(),
        })
    }
}

impl From<U256<u32>> for BigUint {
    fn from(value: U256<u32>) -> Self {
        let mut sum = BigUint::zero();
        for (i, digit) in value.limbs.iter().rev().enumerate() {
            sum += BigUint::from(digit) << (32 * i);
        }
        sum
    }
}

impl From<Fq> for U256<u32> {
    fn from(value: Fq) -> Self {
        // Fq is less than 256 bits, so we can safely convert it to U256
        U256::<u32>::try_from(BigUint::from(value)).unwrap()
    }
}

impl From<U256<u32>> for Fq {
    fn from(value: U256<u32>) -> Self {
        Fq::from(BigUint::from(value))
    }
}

impl<F: RichField + Extendable<D>, const D: usize> From<FqTarget<F, D>> for U256<Target> {
    fn from(value: FqTarget<F, D>) -> Self {
        U256::<Target>::from_limbs(
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

impl<F: RichField + Extendable<D>, const D: usize> From<U256<Target>> for FqTarget<F, D> {
    fn from(value: U256<Target>) -> Self {
        FqTarget::from_vec(&value.limbs().into_iter().rev().collect::<Vec<_>>())
    }
}

impl From<U256<Target>> for BigUintTarget {
    fn from(value: U256<Target>) -> Self {
        let limbs = value
            .limbs()
            .into_iter()
            .rev()
            .map(|x| U32Target(x))
            .collect::<Vec<_>>();
        BigUintTarget { limbs }
    }
}

impl U32LimbTrait<U256_LEN> for U256<u32> {
    fn limbs(&self) -> Vec<u32> {
        self.limbs.to_vec()
    }
    fn from_limbs(limbs: &[u32]) -> Self {
        Self {
            limbs: limbs.try_into().unwrap(),
        }
    }
}

impl U256<u32> {
    // generate small random value for testing
    pub fn rand_small<R: Rng>(rng: &mut R) -> Self {
        let mut limbs = rng.gen::<[u32; 6]>().to_vec();
        limbs.resize(U256_LEN, 0);
        limbs.reverse();
        Self::from_limbs(&limbs)
    }
}

impl std::ops::Add for U256<u32> {
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
        assert_eq!(carry, 0, "U256 addition overflow occured");

        result_limbs.reverse();

        Self {
            limbs: result_limbs.try_into().unwrap(),
        }
    }
}

impl std::ops::AddAssign for U256<u32> {
    fn add_assign(&mut self, rhs: Self) {
        *self = *self + rhs;
    }
}

impl std::ops::Sub for U256<u32> {
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
        assert_eq!(borrow, 0, "U256 sub underflow occured");

        result_limbs.reverse();

        Self {
            limbs: result_limbs.try_into().unwrap(),
        }
    }
}

impl std::ops::SubAssign for U256<u32> {
    fn sub_assign(&mut self, rhs: Self) {
        *self = *self - rhs;
    }
}

impl U256<u32> {
    pub fn rand<T: Rng>(rng: &mut T) -> Self {
        Self { limbs: rng.gen() }
    }
}

impl U32LimbTargetTrait<U256_LEN> for U256<Target> {
    fn limbs(&self) -> Vec<Target> {
        self.limbs.to_vec()
    }
    fn from_limbs(limbs: &[Target]) -> Self {
        Self {
            limbs: limbs.try_into().unwrap(),
        }
    }
}

impl U256<Target> {
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
            self.limbs.iter().rev().map(|t| t).collect(),
            other.limbs.iter().rev().map(|t| t).collect(),
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
        iop::{
            target::Target,
            witness::{PartialWitness, WitnessWrite},
        },
        plonk::{
            circuit_builder::CircuitBuilder, circuit_data::CircuitConfig,
            config::PoseidonGoldilocksConfig,
        },
    };

    use crate::ethereum_types::{
        u256::U256,
        u32limb_trait::{U32LimbTargetTrait, U32LimbTrait as _},
    };

    type F = GoldilocksField;
    const D: usize = 2;
    type C = PoseidonGoldilocksConfig;

    #[test]
    fn u256_display() {
        let u = U256::try_from(BigUint::from(123u64)).unwrap();
        assert_eq!(format!("{}", u), "123");
    }

    #[test]
    fn u256_order() {
        let a = U256::<u32>::from_limbs(&[0, 0, 0, 0, 2, 0, 0, 0]);
        let b = U256::<u32>::from_limbs(&[0, 0, 0, 1, 1, 0, 0, 0]);
        assert!(a < b);
    }

    #[test]
    fn u256_add_sub() {
        let a = U256::<u32>::from_limbs(&[0, 0, 0, 1, 2, 0, 0, 0]);
        let b = U256::<u32>::from_limbs(&[0, 0, 0, 0, u32::MAX, 0, 0, 0]);
        let c = U256::<u32>::from_limbs(&[0, 0, 0, 2, 1, 0, 0, 0]);
        let d = U256::<u32>::from_limbs(&[0, 0, 0, 0, 3, 0, 0, 0]);
        assert_eq!(a + b, c);
        assert_eq!(a - b, d);
    }

    #[test]
    #[should_panic]
    fn u256_sub_underflow() {
        let a = U256::<u32>::from_limbs(&[0, 0, 0, 1, 2, 0, 0, 0]);
        let b = U256::<u32>::from_limbs(&[0, 0, 0, 0, u32::MAX, 0, 0, 0]);

        _ = b - a;
    }

    #[test]
    fn u256_le() {
        let a = U256::<u32>::from_limbs(&[0, 0, 0, 1, 2, 0, 0, 0]);
        let b = U256::<u32>::from_limbs(&[0, 0, 0, 0, u32::MAX, 0, 0, 0]);

        let mut builder = CircuitBuilder::<F, D>::new(CircuitConfig::default());
        let a_t = U256::<Target>::constant(&mut builder, a);
        let b_t = U256::<Target>::constant(&mut builder, b);
        let le_ab = a_t.is_le(&mut builder, &b_t);
        let le_aa = a_t.is_le(&mut builder, &a_t);

        let mut pw = PartialWitness::new();
        pw.set_bool_target(le_ab, a <= b);
        pw.set_bool_target(le_aa, a <= a);
        let circuit = builder.build::<C>();
        circuit.prove(pw).unwrap();
    }

    #[test]
    fn u256_add_sub_circuit() {
        let mut rng = rand::thread_rng();
        let a = U256::<u32>::rand(&mut rng);
        let b = U256::<u32>::try_from(BigUint::from(1u64)).unwrap();
        let a_plus_b = a + b;
        let a_minus_b = a - b;

        let mut builder = CircuitBuilder::<F, D>::new(CircuitConfig::default());
        let a_t = U256::<Target>::constant(&mut builder, a);
        let b_t = U256::<Target>::constant(&mut builder, b);
        let a_plus_b_t = a_t.add(&mut builder, &b_t);
        let a_minus_b_t = a_t.sub(&mut builder, &b_t);
        let mut pw = PartialWitness::new();
        a_minus_b_t.set_witness(&mut pw, a_minus_b);
        a_plus_b_t.set_witness(&mut pw, a_plus_b);
        let circuit = builder.build::<C>();
        circuit.prove(pw).unwrap();
    }
}
