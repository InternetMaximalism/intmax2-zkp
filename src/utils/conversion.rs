use std::slice::Iter;

use plonky2::field::types::{Field, PrimeField64};

pub trait ToU64 {
    fn to_u64_vec(&self) -> Vec<u64>;
}

pub trait ToField {
    fn to_field_vec<F: Field>(&self) -> Vec<F>;
}

impl<F: PrimeField64> ToU64 for &[F] {
    fn to_u64_vec(&self) -> Vec<u64> {
        self.into_iter()
            .map(|x| x.to_canonical_u64())
            .collect::<Vec<u64>>()
    }
}

impl<F: PrimeField64> ToU64 for [F] {
    fn to_u64_vec(&self) -> Vec<u64> {
        self.into_iter()
            .map(|x| x.to_canonical_u64())
            .collect::<Vec<u64>>()
    }
}

impl<'a, F: PrimeField64> ToU64 for Iter<'a, F> {
    fn to_u64_vec(&self) -> Vec<u64> {
        self.clone()
            .map(|x| x.to_canonical_u64())
            .collect::<Vec<u64>>()
    }
}

impl<F: PrimeField64> ToU64 for Vec<F> {
    fn to_u64_vec(&self) -> Vec<u64> {
        self.into_iter()
            .map(|x| x.to_canonical_u64())
            .collect::<Vec<u64>>()
    }
}

impl ToField for &[u64] {
    fn to_field_vec<F: Field>(&self) -> Vec<F> {
        self.into_iter()
            .map(|x| F::from_canonical_u64(*x))
            .collect::<Vec<_>>()
    }
}

impl ToField for Vec<u64> {
    fn to_field_vec<F: Field>(&self) -> Vec<F> {
        self.into_iter()
            .map(|x| F::from_canonical_u64(*x))
            .collect::<Vec<_>>()
    }
}
