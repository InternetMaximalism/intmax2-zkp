use std::str::FromStr;

use super::{
    bytes32::{Bytes32, Bytes32Target},
    u32limb_trait::{U32LimbTargetTrait, U32LimbTrait},
};
use crate::constants::{ACCOUNT_ID_BITS, NUM_SENDERS_IN_BLOCK};
use anyhow::ensure;
use itertools::Itertools;
use plonky2::{
    field::extension::Extendable,
    hash::hash_types::RichField,
    iop::target::Target,
    plonk::{
        circuit_builder::CircuitBuilder,
        config::{AlgebraicHasher, GenericConfig},
    },
};
use plonky2_keccak::{builder::BuilderKeccak256 as _, utils::solidity_keccak256};
use serde::{Deserialize, Serialize};

pub const ACCOUNT_ID_PACKED_LEN: usize = ACCOUNT_ID_BITS * NUM_SENDERS_IN_BLOCK / 32;
pub const ACCOUNT_ID_BYTES_LEN: usize = ACCOUNT_ID_BITS / 8;

/// ACCOUNT_ID_BITS bits account ID.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct AccountId(pub u64);

impl AccountId {
    pub fn dummy() -> Self {
        AccountId(1)
    }

    pub fn is_dummy(&self) -> bool {
        self == &Self::dummy()
    }

    pub fn to_bits_be(&self) -> Vec<bool> {
        let mut result = Vec::with_capacity(40);
        for i in (0..ACCOUNT_ID_BITS).rev() {
            result.push((self.0 & (1 << i)) != 0);
        }
        result
    }

    pub fn from_bits_be(input: &[bool]) -> Self {
        assert_eq!(input.len(), ACCOUNT_ID_BITS);
        let mut value = 0;
        for (i, &bit) in input.iter().enumerate() {
            if bit {
                value |= 1 << (ACCOUNT_ID_BITS - 1 - i);
            }
        }
        AccountId(value)
    }

    pub fn to_bytes_be(&self) -> Vec<u8> {
        let bytes: [u8; 8] = self.0.to_be_bytes();
        // only last ACCOUNT_ID_BYTES_LEN bytes are needed
        bytes[8 - ACCOUNT_ID_BYTES_LEN..].to_vec()
    }

    pub fn from_bytes_be(input: &[u8]) -> Self {
        assert_eq!(input.len(), ACCOUNT_ID_BYTES_LEN);
        let mut bytes = [0u8; 8];
        bytes[8 - ACCOUNT_ID_BYTES_LEN..].copy_from_slice(input);
        AccountId(u64::from_be_bytes(bytes))
    }
}

/// A packed account ID.
/// The value is stored in big endian format.
#[derive(Clone, Copy, PartialEq, Hash)]
pub struct AccountIdPacked {
    limbs: [u32; ACCOUNT_ID_PACKED_LEN],
}

#[derive(Clone, Copy, Debug)]
pub struct AccountIdPackedTarget {
    limbs: [Target; ACCOUNT_ID_PACKED_LEN],
}

impl core::fmt::Debug for AccountIdPacked {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.to_hex())
    }
}

impl core::fmt::Display for AccountIdPacked {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        core::fmt::Debug::fmt(&self, f)
    }
}

impl FromStr for AccountIdPacked {
    type Err = anyhow::Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Self::from_hex(s).map_err(|e| anyhow::anyhow!("Failed to parse AccountIdPacked: {}", e))
    }
}

impl Serialize for AccountIdPacked {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(&self.to_string())
    }
}

impl<'de> Deserialize<'de> for AccountIdPacked {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let s = String::deserialize(deserializer)?;
        let value = Self::from_hex(&s).map_err(serde::de::Error::custom)?;
        Ok(value)
    }
}

impl U32LimbTrait<ACCOUNT_ID_PACKED_LEN> for AccountIdPacked {
    fn to_u32_vec(&self) -> Vec<u32> {
        self.limbs.to_vec()
    }

    fn from_u32_slice(limbs: &[u32]) -> Self {
        Self {
            limbs: limbs.try_into().unwrap(),
        }
    }
}

impl U32LimbTargetTrait<ACCOUNT_ID_PACKED_LEN> for AccountIdPackedTarget {
    fn to_vec(&self) -> Vec<Target> {
        self.limbs.to_vec()
    }

    fn from_slice(limbs: &[Target]) -> Self {
        Self {
            limbs: limbs.try_into().unwrap(),
        }
    }
}

impl AccountIdPacked {
    pub fn pack(account_ids: &[AccountId]) -> Self {
        assert_eq!(account_ids.len(), NUM_SENDERS_IN_BLOCK);
        let bytes = account_ids
            .iter()
            .flat_map(|&account_id| account_id.to_bytes_be())
            .collect::<Vec<_>>();
        Self::from_bytes_be(&bytes)
    }

    pub fn unpack(&self) -> Vec<AccountId> {
        self.to_bytes_be()
            .chunks(ACCOUNT_ID_BYTES_LEN)
            .map(|c| AccountId::from_bytes_be(c))
            .collect::<Vec<_>>()
    }

    /// Trim dummy account ids and return bytes representation.
    pub fn to_trimmed_bytes(&self) -> Vec<u8> {
        let trimmed_account_ids = self
            .unpack()
            .into_iter()
            .filter(|&x| !x.is_dummy()) // filter out dummy
            .collect::<Vec<_>>();
        trimmed_account_ids
            .iter()
            .flat_map(|&account_id| account_id.to_bytes_be())
            .collect::<Vec<_>>()
    }

    // Recovers account id packed from bytes representation of account ids where
    // dummy accounts are trimmed.
    pub fn from_trimmed_bytes(input: &[u8]) -> anyhow::Result<Self> {
        ensure!(
            input.len() <= ACCOUNT_ID_BYTES_LEN * NUM_SENDERS_IN_BLOCK,
            "too long account id bytes"
        );
        ensure!(
            input.len() % ACCOUNT_ID_BYTES_LEN == 0,
            "invalid account id bytes length"
        );
        let dummy_account_id_bytes = AccountId::dummy().to_bytes_be();
        let mut inputs = input.to_vec();
        while inputs.len() < ACCOUNT_ID_BYTES_LEN * NUM_SENDERS_IN_BLOCK {
            inputs.extend_from_slice(&dummy_account_id_bytes);
        }
        Ok(Self::from_bytes_be(&inputs))
    }

    pub fn hash(&self) -> Bytes32 {
        Bytes32::from_u32_slice(&solidity_keccak256(&self.to_u32_vec()))
    }
}

impl AccountIdPackedTarget {
    pub fn unpack<F: RichField + Extendable<D>, const D: usize>(
        &self,
        builder: &mut CircuitBuilder<F, D>,
    ) -> Vec<Target> {
        let bits = self.to_bits_be(builder);
        let account_ids = bits
            .into_iter()
            .chunks(ACCOUNT_ID_BITS)
            .into_iter()
            .map(|chunk| {
                let chunk_bits = chunk.into_iter().collect::<Vec<_>>();
                builder.le_sum(chunk_bits.iter().rev())
            })
            .collect::<Vec<_>>();
        account_ids
    }

    pub fn hash<
        F: RichField + Extendable<D>,
        C: GenericConfig<D, F = F> + 'static,
        const D: usize,
    >(
        &self,
        builder: &mut CircuitBuilder<F, D>,
    ) -> Bytes32Target
    where
        <C as GenericConfig<D>>::Hasher: AlgebraicHasher<F>,
    {
        Bytes32Target::from_slice(&builder.keccak256::<C>(&self.to_vec()))
    }
}

fn bits_be_to_u8(vec: &[bool]) -> u8 {
    assert_eq!(vec.len(), 8);
    let mut result = 0;
    for (i, &bit) in vec.iter().enumerate() {
        if bit {
            result |= 1 << (7 - i);
        }
    }
    result
}

#[cfg(test)]
mod tests {
    use rand::Rng;

    use super::*;

    #[test]
    fn pack_and_unpack() {
        let mut rng = rand::thread_rng();
        let account_ids = (0..NUM_SENDERS_IN_BLOCK)
            .map(|_| AccountId(rng.gen_range(0..1 << ACCOUNT_ID_BITS)))
            .collect::<Vec<_>>();
        let packed = AccountIdPacked::pack(&account_ids);
        let unpacked = packed.unpack();
        assert_eq!(account_ids, unpacked);
    }

    #[test]
    fn trim_account_ids() {
        let num_ids = 10;
        let mut rng = rand::thread_rng();
        let mut account_ids = (0..num_ids)
            .map(|_| AccountId(rng.gen_range(0..1 << ACCOUNT_ID_BITS)))
            .collect::<Vec<_>>();
        account_ids.resize(NUM_SENDERS_IN_BLOCK, AccountId::dummy());

        let packed = AccountIdPacked::pack(&account_ids);
        let trimmed_bytes = packed.to_trimmed_bytes();
        let recovered = AccountIdPacked::from_trimmed_bytes(&trimmed_bytes).unwrap();
        assert_eq!(packed, recovered);
    }
}
