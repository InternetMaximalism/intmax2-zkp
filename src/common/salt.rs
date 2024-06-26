use plonky2::{
    field::{extension::Extendable, types::Field},
    hash::hash_types::RichField,
    iop::{target::Target, witness::WitnessWrite},
    plonk::circuit_builder::CircuitBuilder,
};
use rand::Rng;

use crate::utils::poseidon_hash_out::{
    PoseidonHashOut, PoseidonHashOutTarget, POSEIDON_HASH_OUT_LEN,
};

pub const SALT_LEN: usize = POSEIDON_HASH_OUT_LEN;

#[derive(Debug, Clone, Copy, Default)]
pub struct Salt(PoseidonHashOut);

#[derive(Debug, Clone, Copy)]
pub struct SaltTarget(PoseidonHashOutTarget);

impl Salt {
    pub fn to_u64_vec(&self) -> Vec<u64> {
        self.0.to_u64_vec()
    }

    pub fn rand<R: Rng>(rng: &mut R) -> Self {
        Self(PoseidonHashOut::rand(rng))
    }
}

impl SaltTarget {
    pub fn new<F: RichField + Extendable<D>, const D: usize>(
        builder: &mut CircuitBuilder<F, D>,
    ) -> Self {
        let hash = PoseidonHashOutTarget::new(builder);
        Self(hash)
    }

    pub fn to_vec(&self) -> Vec<Target> {
        self.0.to_vec()
    }

    pub fn constant<F: RichField + Extendable<D>, const D: usize>(
        builder: &mut CircuitBuilder<F, D>,
        value: Salt,
    ) -> Self {
        let hash = PoseidonHashOutTarget::constant(builder, value.0);
        Self(hash)
    }

    pub fn set_witness<F: Field, W: WitnessWrite<F>>(&self, witness: &mut W, value: Salt) {
        self.0.set_witness(witness, value.0)
    }
}
