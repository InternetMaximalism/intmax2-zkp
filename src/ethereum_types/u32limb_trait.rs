use plonky2::{
    field::{
        extension::Extendable,
        types::{Field, PrimeField64},
    },
    hash::hash_types::RichField,
    iop::{
        target::{BoolTarget, Target},
        witness::{Witness, WitnessWrite},
    },
    plonk::circuit_builder::CircuitBuilder,
};
use rand::Rng;

// trait for types with u32 value limbs
pub trait U32LimbTrait<const NUM_LIMBS: usize>: Clone + Copy {
    fn to_u32_vec(&self) -> Vec<u32>;
    fn from_slice(limbs: &[u32]) -> Self;

    fn to_vec<F: Field>(&self) -> Vec<F> {
        self.to_u32_vec()
            .iter()
            .map(|x| F::from_canonical_u32(*x))
            .collect()
    }

    fn to_u64_vec(&self) -> Vec<u64> {
        self.to_u32_vec().iter().map(|x| *x as u64).collect()
    }

    fn from_u64_slice(input: &[u64]) -> Self {
        let range_checked_input = input
            .iter()
            .map(|&x| {
                assert!(x <= u32::MAX as u64);
                x as u32
            })
            .collect::<Vec<_>>();
        Self::from_slice(&range_checked_input)
    }

    fn zero() -> Self {
        let limbs = vec![0; NUM_LIMBS];
        Self::from_slice(&limbs)
    }

    fn one() -> Self {
        let mut limbs = vec![0; NUM_LIMBS];
        limbs[NUM_LIMBS - 1] = 1;
        Self::from_slice(&limbs)
    }

    // Assuming that original order is big endian,
    // returns big endian bytes
    fn from_bytes_be(bytes: &[u8]) -> Self {
        assert_eq!(bytes.len(), 4 * NUM_LIMBS);
        let limbs = bytes
            .chunks(4)
            .map(|c| u32::from_be_bytes(c.try_into().unwrap()))
            .collect::<Vec<_>>();
        Self::from_slice(&limbs)
    }

    fn to_bytes_be(self) -> Vec<u8> {
        let mut result = vec![];
        for limb in self.to_u32_vec().iter() {
            result.extend_from_slice(&limb.to_be_bytes());
        }
        result.try_into().unwrap()
    }

    fn to_bits_be(&self) -> Vec<bool> {
        self.to_u32_vec()
            .into_iter()
            .flat_map(u32_to_bits_be)
            .collect()
    }

    fn from_bits_be(bits: &[bool]) -> Self {
        assert_eq!(bits.len(), 32 * NUM_LIMBS);
        let limbs = bits
            .chunks(32)
            .map(|chunk| bits_be_to_u32(chunk))
            .collect::<Vec<_>>();
        Self::from_slice(&limbs)
    }

    fn from_hex(hex: &str) -> anyhow::Result<Self> {
        anyhow::ensure!(hex.starts_with("0x"));
        let bytes = hex::decode(hex[2..].as_bytes())?;
        Ok(Self::from_bytes_be(&bytes))
    }

    fn to_hex(&self) -> String {
        "0x".to_string() + &hex::encode(self.to_bytes_be())
    }

    fn rand<R: Rng>(rng: &mut R) -> Self {
        let limbs = (0..NUM_LIMBS).map(|_| rng.gen()).collect::<Vec<_>>();
        Self::from_slice(&limbs)
    }
}

// trait for types with u32 target limbs
pub trait U32LimbTargetTrait<const NUM_LIMBS: usize>: Clone + Copy {
    fn to_vec(&self) -> Vec<Target>;
    fn from_slice(limbs: &[Target]) -> Self;

    fn _new_unchecked<F: RichField + Extendable<D>, const D: usize>(
        builder: &mut CircuitBuilder<F, D>,
    ) -> Self {
        let limbs = (0..NUM_LIMBS)
            .map(|_| builder.add_virtual_target())
            .collect::<Vec<_>>();
        Self::from_slice(&limbs)
    }

    fn _new_checked<F: RichField + Extendable<D>, const D: usize>(
        builder: &mut CircuitBuilder<F, D>,
    ) -> Self {
        let x = Self::_new_unchecked(builder);
        x.assert_u32(builder);
        x
    }

    fn new<F: RichField + Extendable<D>, const D: usize>(
        builder: &mut CircuitBuilder<F, D>,
        is_checked: bool,
    ) -> Self {
        if is_checked {
            Self::_new_checked(builder)
        } else {
            Self::_new_unchecked(builder)
        }
    }

    fn assert_u32<F: RichField + Extendable<D>, const D: usize>(
        &self,
        builder: &mut CircuitBuilder<F, D>,
    ) {
        self.to_vec()
            .iter()
            .for_each(|x| builder.range_check(*x, 32))
    }

    fn connect<F: RichField + Extendable<D>, const D: usize>(
        &self,
        builder: &mut CircuitBuilder<F, D>,
        other: Self,
    ) {
        for (a, b) in self.to_vec().iter().zip(other.to_vec().iter()) {
            builder.connect(*a, *b);
        }
    }

    fn conditional_assert_eq<F: RichField + Extendable<D>, const D: usize>(
        &self,
        builder: &mut CircuitBuilder<F, D>,
        other: Self,
        condition: BoolTarget,
    ) {
        for (l, r) in self.to_vec().iter().zip(other.to_vec().iter()) {
            builder.conditional_assert_eq(condition.target, *l, *r);
        }
    }

    fn is_equal<F: RichField + Extendable<D>, const D: usize>(
        &self,
        builder: &mut CircuitBuilder<F, D>,
        other: &Self,
    ) -> BoolTarget {
        let mut result = builder._true();
        for (a, b) in self.to_vec().iter().zip(other.to_vec().iter()) {
            let eq = builder.is_equal(*a, *b);
            result = builder.and(result, eq);
        }
        result
    }

    fn is_zero<F: RichField + Extendable<D>, const D: usize, V: U32LimbTrait<NUM_LIMBS>>(
        &self,
        builder: &mut CircuitBuilder<F, D>,
    ) -> BoolTarget {
        let zero = Self::zero::<F, D, V>(builder);
        self.is_equal(builder, &zero)
    }

    fn is_one<F: RichField + Extendable<D>, const D: usize, V: U32LimbTrait<NUM_LIMBS>>(
        &self,
        builder: &mut CircuitBuilder<F, D>,
    ) -> BoolTarget {
        let one = Self::one::<F, D, V>(builder);
        self.is_equal(builder, &one)
    }

    fn to_bits_be<F: RichField + Extendable<D>, const D: usize>(
        &self,
        builder: &mut CircuitBuilder<F, D>,
    ) -> Vec<BoolTarget> {
        self.to_vec()
            .iter()
            .flat_map(|e| builder.split_le(*e, 32).into_iter().rev())
            .collect::<Vec<_>>()
    }

    fn from_bits_be<F: RichField + Extendable<D>, const D: usize>(
        builder: &mut CircuitBuilder<F, D>,
        bits: &[BoolTarget],
    ) -> Self {
        assert_eq!(bits.len(), 32 * NUM_LIMBS);
        let limbs = bits
            .chunks(32)
            .map(|chunk| builder.le_sum(chunk.into_iter().rev()))
            .collect::<Vec<_>>();
        Self::from_slice(&limbs)
    }

    fn mul_bool<F: RichField + Extendable<D>, const D: usize>(
        &self,
        builder: &mut CircuitBuilder<F, D>,
        b: BoolTarget,
    ) -> Self {
        let limbs = self
            .to_vec()
            .iter()
            .map(|x| builder.mul(b.target, *x))
            .collect::<Vec<_>>();
        Self::from_slice(&limbs)
    }

    fn select<F: RichField + Extendable<D>, const D: usize>(
        builder: &mut CircuitBuilder<F, D>,
        b: BoolTarget,
        x: Self,
        y: Self,
    ) -> Self {
        let limbs = x
            .to_vec()
            .iter()
            .zip(y.to_vec().iter())
            .map(|(x, y)| builder.select(b, *x, *y))
            .collect::<Vec<_>>();
        Self::from_slice(&limbs)
    }

    fn set_witness<F: Field, V: U32LimbTrait<NUM_LIMBS>>(
        &self,
        witness: &mut impl WitnessWrite<F>,
        value: V,
    ) {
        for (target, value) in self.to_vec().iter().zip(value.to_u32_vec().iter()) {
            witness.set_target(*target, F::from_canonical_u32(*value));
        }
    }

    fn get_witness<F: PrimeField64, V: U32LimbTrait<NUM_LIMBS>>(&self, pw: &impl Witness<F>) -> V {
        let mut limbs = vec![];
        for target in self.to_vec().iter() {
            let value = pw.get_target(*target);
            limbs.push(value.to_canonical_u64() as u32);
        }
        V::from_slice(&limbs)
    }

    fn constant<F: RichField + Extendable<D>, const D: usize, V: U32LimbTrait<NUM_LIMBS>>(
        builder: &mut CircuitBuilder<F, D>,
        value: V,
    ) -> Self {
        let limbs = value
            .to_u32_vec()
            .into_iter()
            .map(|v| builder.constant(F::from_canonical_u32(v)))
            .collect::<Vec<_>>();
        Self::from_slice(&limbs)
    }

    fn zero<F: RichField + Extendable<D>, const D: usize, V: U32LimbTrait<NUM_LIMBS>>(
        builder: &mut CircuitBuilder<F, D>,
    ) -> Self {
        Self::constant(builder, V::zero())
    }

    fn one<F: RichField + Extendable<D>, const D: usize, V: U32LimbTrait<NUM_LIMBS>>(
        builder: &mut CircuitBuilder<F, D>,
    ) -> Self {
        Self::constant(builder, V::one())
    }
}

fn u32_to_bits_be(x: u32) -> Vec<bool> {
    let mut result = Vec::with_capacity(32);
    for i in (0..32).rev() {
        result.push((x & (1 << i)) != 0);
    }
    result
}

fn bits_be_to_u32(vec: &[bool]) -> u32 {
    let mut result = 0u32;
    for (i, &bit) in vec.iter().enumerate() {
        if bit {
            result |= 1 << (31 - i);
        }
    }
    result
}
