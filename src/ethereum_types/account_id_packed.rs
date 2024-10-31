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
pub const ACCOUNT_ID_BTYTES_LEN: usize = ACCOUNT_ID_BITS / 8;
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
    pub fn pack(account_ids: &[usize]) -> Self {
        assert_eq!(account_ids.len(), NUM_SENDERS_IN_BLOCK);
        let account_id_bits = account_ids
            .into_iter()
            .flat_map(|&account_id| account_id_to_bits_be(account_id))
            .collect::<Vec<_>>();
        Self::from_bits_be(&account_id_bits)
    }

    pub fn unpack(&self) -> Vec<usize> {
        let bits = self.to_bits_be();
        let account_ids = bits
            .into_iter()
            .chunks(ACCOUNT_ID_BITS)
            .into_iter()
            .map(|chunk| {
                let chunk_bits = chunk.into_iter().collect::<Vec<_>>();
                bits_be_to_account_id(&chunk_bits)
            })
            .collect::<Vec<_>>();
        assert_eq!(account_ids.len(), NUM_SENDERS_IN_BLOCK);
        account_ids
    }

    // Recovers account id packed from bytes representation of account ids where
    // dummy accounts are trimmed.
    pub fn from_trimmed_bytes(input: &[u8]) -> anyhow::Result<Self> {
        ensure!(
            input.len() <= ACCOUNT_ID_BTYTES_LEN * NUM_SENDERS_IN_BLOCK,
            "too long account id bytes"
        );
        ensure!(
            input.len() % ACCOUNT_ID_BTYTES_LEN == 0,
            "invalid account id bytes length"
        );
        let mut dummy_account_id_bytes = [0u8; ACCOUNT_ID_BTYTES_LEN];
        dummy_account_id_bytes[ACCOUNT_ID_BTYTES_LEN - 1] = 1; // least byte is 1
        let mut inputs = input.to_vec();
        while inputs.len() < ACCOUNT_ID_BTYTES_LEN * NUM_SENDERS_IN_BLOCK {
            inputs.extend_from_slice(&dummy_account_id_bytes);
        }
        Ok(Self::from_bytes_be(&inputs))
    }

    pub fn to_trimmed_bytes(&self) -> Vec<u8> {
        let trimmed_account_ids = self
            .unpack()
            .into_iter()
            .filter(|&x| x != 1) // filter out dummy
            .collect::<Vec<_>>();
        let account_id_bits = trimmed_account_ids
            .into_iter()
            .flat_map(|account_id| account_id_to_bits_be(account_id))
            .collect::<Vec<_>>();
        account_id_bits
            .chunks(8)
            .map(|c| bits_be_to_u8(c))
            .collect()
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

fn account_id_to_bits_be(account_id: usize) -> Vec<bool> {
    assert!(account_id < 1 << ACCOUNT_ID_BITS);
    let mut result = Vec::with_capacity(40);
    for i in (0..ACCOUNT_ID_BITS).rev() {
        result.push((account_id & (1 << i)) != 0);
    }
    result
}

fn bits_be_to_account_id(vec: &[bool]) -> usize {
    assert_eq!(vec.len(), ACCOUNT_ID_BITS);
    let mut result = 0;
    for (i, &bit) in vec.iter().enumerate() {
        if bit {
            result |= 1 << (ACCOUNT_ID_BITS - 1 - i);
        }
    }
    result
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
            .map(|_| rng.gen_range(0..1 << ACCOUNT_ID_BITS))
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
            .map(|_| rng.gen_range(0..1 << ACCOUNT_ID_BITS))
            .collect::<Vec<_>>();
        account_ids.resize(NUM_SENDERS_IN_BLOCK, 1);

        let packed = AccountIdPacked::pack(&account_ids);
        let trimmed_bytes = packed.to_trimmed_bytes();
        let recovered = AccountIdPacked::from_trimmed_bytes(&trimmed_bytes).unwrap();
        assert_eq!(packed, recovered);
    }
}
