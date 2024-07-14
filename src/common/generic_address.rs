use crate::ethereum_types::{
    address::{Address, ADDRESS_LEN},
    u256::{U256, U256_LEN},
    u32limb_trait::{U32LimbTargetTrait as _, U32LimbTrait},
};
use anyhow::{ensure, Result};
use plonky2::{
    field::{extension::Extendable, types::Field},
    hash::hash_types::RichField,
    iop::{
        target::{BoolTarget, Target},
        witness::WitnessWrite,
    },
    plonk::circuit_builder::CircuitBuilder,
};
use rand::Rng;

use super::signature::key_set::KeySet;

pub const GENERIC_ADDRESS_LEN: usize = 1 + U256_LEN;

// A structure representing a pubkey or Ethereum address
#[derive(Debug, Default, Copy, Clone, Eq, PartialEq)]
pub struct GenericAddress {
    pub is_pubkey: bool,
    pub data: U256<u32>,
}

#[derive(Debug, Copy, Clone)]
pub struct GenericAddressTarget {
    pub is_pubkey: BoolTarget,
    pub data: U256<Target>,
}

impl GenericAddress {
    pub fn to_u64_vec(&self) -> Vec<u64> {
        let vec = vec![self.is_pubkey as u64]
            .into_iter()
            .chain(self.data.to_u64_vec().into_iter())
            .collect::<Vec<_>>();
        assert_eq!(vec.len(), GENERIC_ADDRESS_LEN);
        vec
    }

    pub fn from_pubkey(pubkey: U256<u32>) -> Self {
        Self {
            is_pubkey: true,
            data: pubkey,
        }
    }

    pub fn from_address(address: Address<u32>) -> Self {
        let mut limbs = address.limbs();
        limbs.resize(U256_LEN, 0);
        Self {
            is_pubkey: false,
            data: U256::<u32>::from_limbs(&limbs),
        }
    }

    pub fn to_pubkey(&self) -> Result<U256<u32>> {
        ensure!(self.is_pubkey, "not a pubkey");
        Ok(self.data)
    }

    pub fn to_address(&self) -> Result<Address<u32>> {
        ensure!(!self.is_pubkey, "not an address");
        let limbs = self.data.limbs();
        Ok(Address::<u32>::from_limbs(&limbs[0..ADDRESS_LEN]))
    }

    pub fn rand_pubkey<R: Rng>(rng: &mut R) -> Self {
        Self::from_pubkey(KeySet::rand(rng).pubkey_x)
    }

    pub fn rand_address<R: Rng>(rng: &mut R) -> Self {
        Self::from_address(Address::rand(rng))
    }
}

impl GenericAddressTarget {
    pub fn to_vec(&self) -> Vec<Target> {
        let vec = vec![self.is_pubkey.target]
            .into_iter()
            .chain(self.data.to_vec().into_iter())
            .collect::<Vec<_>>();
        assert_eq!(vec.len(), GENERIC_ADDRESS_LEN);
        vec
    }

    pub fn new<F: RichField + Extendable<D>, const D: usize>(
        builder: &mut CircuitBuilder<F, D>,
        is_checked: bool,
    ) -> Self {
        let is_pubkey = builder.add_virtual_bool_target_unsafe();
        if is_checked {
            builder.assert_bool(is_pubkey);
        }
        Self {
            is_pubkey,
            data: U256::<Target>::new(builder, is_checked),
        }
    }

    pub fn connect<F: RichField + Extendable<D>, const D: usize>(
        &self,
        builder: &mut CircuitBuilder<F, D>,
        other: Self,
    ) {
        builder.connect(self.is_pubkey.target, other.is_pubkey.target);
        self.data.connect(builder, other.data);
    }

    pub fn constant<F: RichField + Extendable<D>, const D: usize>(
        builder: &mut CircuitBuilder<F, D>,
        value: GenericAddress,
    ) -> Self {
        Self {
            is_pubkey: builder.constant_bool(value.is_pubkey),
            data: U256::<Target>::constant(builder, value.data),
        }
    }

    pub fn to_address<F: RichField + Extendable<D>, const D: usize>(
        &self,
        builder: &mut CircuitBuilder<F, D>,
    ) -> Address<Target> {
        builder.assert_zero(self.is_pubkey.target);
        let limbs = self.data.limbs();
        Address::<Target>::from_limbs(&limbs[0..ADDRESS_LEN])
    }

    pub fn to_pubkey<F: RichField + Extendable<D>, const D: usize>(
        &self,
        builder: &mut CircuitBuilder<F, D>,
    ) -> U256<Target> {
        builder.assert_one(self.is_pubkey.target);
        self.data.clone()
    }

    pub fn set_witness<F: Field, W: WitnessWrite<F>>(&self, pw: &mut W, address: GenericAddress) {
        pw.set_bool_target(self.is_pubkey, address.is_pubkey);
        self.data.set_witness(pw, address.data);
    }
}
