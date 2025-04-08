use crate::{
    common::error::CommonError,
    ethereum_types::{
        address::{Address, AddressTarget, ADDRESS_LEN},
        u256::{U256Target, U256, U256_LEN},
        u32limb_trait::{U32LimbTargetTrait as _, U32LimbTrait},
    },
};
use plonky2::{
    field::{extension::Extendable, types::Field},
    hash::hash_types::RichField,
    iop::{
        target::{BoolTarget, Target},
        witness::WitnessWrite,
    },
    plonk::circuit_builder::CircuitBuilder,
};
use serde::{Deserialize, Serialize};

pub const GENERIC_ADDRESS_LEN: usize = 1 + U256_LEN;

/// A structure representing a pubkey or Ethereum address
#[derive(Debug, Default, Copy, Clone, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct GenericAddress {
    pub is_pubkey: bool,
    pub data: U256,
}

#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub struct GenericAddressTarget {
    pub is_pubkey: BoolTarget,
    pub data: U256Target,
}

impl From<Address> for GenericAddress {
    fn from(address: Address) -> Self {
        let mut limbs = address.to_u32_vec();
        limbs.resize(U256_LEN, 0);
        Self {
            is_pubkey: false,
            data: U256::from_u32_slice(&limbs).unwrap(),
        }
    }
}

impl From<U256> for GenericAddress {
    fn from(pubkey: U256) -> Self {
        Self {
            is_pubkey: true,
            data: pubkey,
        }
    }
}

impl GenericAddress {
    pub fn to_u64_vec(&self) -> Vec<u64> {
        let vec = vec![self.is_pubkey as u64]
            .into_iter()
            .chain(self.data.to_u64_vec())
            .collect::<Vec<_>>();
        assert_eq!(vec.len(), GENERIC_ADDRESS_LEN);
        vec
    }

    pub fn to_pubkey(&self) -> Result<U256, CommonError> {
        if !self.is_pubkey {
            return Err(CommonError::InvalidData("not a pubkey".to_string()));
        }
        Ok(self.data)
    }

    pub fn to_address(&self) -> Result<Address, CommonError> {
        if self.is_pubkey {
            return Err(CommonError::InvalidData("not an address".to_string()));
        }
        let limbs = self.data.to_u32_vec();
        Ok(Address::from_u32_slice(&limbs[0..ADDRESS_LEN]).unwrap())
    }
}

impl GenericAddressTarget {
    pub fn to_vec(&self) -> Vec<Target> {
        let vec = vec![self.is_pubkey.target]
            .into_iter()
            .chain(self.data.to_vec())
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
            data: U256Target::new(builder, is_checked),
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
            data: U256Target::constant(builder, value.data),
        }
    }

    pub fn from_address<F: RichField + Extendable<D>, const D: usize>(
        builder: &mut CircuitBuilder<F, D>,
        address: AddressTarget,
    ) -> Self {
        let mut limbs = address.to_vec();
        let zero = builder.zero();
        limbs.resize(U256_LEN, zero);
        Self {
            is_pubkey: builder._false(),
            data: U256Target::from_slice(&limbs),
        }
    }

    pub fn to_address<F: RichField + Extendable<D>, const D: usize>(
        &self,
        builder: &mut CircuitBuilder<F, D>,
    ) -> AddressTarget {
        builder.assert_zero(self.is_pubkey.target);
        let limbs = self.data.to_vec();
        AddressTarget::from_slice(&limbs[0..ADDRESS_LEN])
    }

    pub fn to_pubkey<F: RichField + Extendable<D>, const D: usize>(
        &self,
        builder: &mut CircuitBuilder<F, D>,
    ) -> U256Target {
        builder.assert_one(self.is_pubkey.target);
        self.data
    }

    pub fn set_witness<F: Field, W: WitnessWrite<F>>(&self, pw: &mut W, address: GenericAddress) {
        pw.set_bool_target(self.is_pubkey, address.is_pubkey);
        self.data.set_witness(pw, address.data);
    }
}
