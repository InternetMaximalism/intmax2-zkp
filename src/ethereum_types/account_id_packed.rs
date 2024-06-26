use super::{
    bytes32::Bytes32,
    u32limb_trait::{U32LimbTargetTrait, U32LimbTrait},
};
use crate::constants::{ACCOUNT_ID_BITS, NUM_SENDERS_IN_BLOCK};
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
use serde::{Deserialize, Serialize};
pub const ACCOUNT_ID_PACKED_LEN: usize = ACCOUNT_ID_BITS * NUM_SENDERS_IN_BLOCK / 32;
use plonky2_keccak::{builder::BuilderKeccak256 as _, utils::solidity_keccak256};

/// A packed account ID.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct AccountIdPacked<T: Clone + Copy> {
    limbs: [T; ACCOUNT_ID_PACKED_LEN],
}

impl std::fmt::Display for AccountIdPacked<u32> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.to_hex())
    }
}

impl Serialize for AccountIdPacked<u32> {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(&self.to_hex())
    }
}

impl<'de> Deserialize<'de> for AccountIdPacked<u32> {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let s = String::deserialize(deserializer)?;
        Ok(Self::from_hex(&s))
    }
}

impl U32LimbTrait<ACCOUNT_ID_PACKED_LEN> for AccountIdPacked<u32> {
    fn limbs(&self) -> Vec<u32> {
        self.limbs.to_vec()
    }

    fn from_limbs(limbs: &[u32]) -> Self {
        Self {
            limbs: limbs.try_into().unwrap(),
        }
    }
}

impl U32LimbTargetTrait<ACCOUNT_ID_PACKED_LEN> for AccountIdPacked<Target> {
    fn limbs(&self) -> Vec<Target> {
        self.limbs.to_vec()
    }

    fn from_limbs(limbs: &[Target]) -> Self {
        Self {
            limbs: limbs.try_into().unwrap(),
        }
    }
}

impl AccountIdPacked<u32> {
    pub fn pack(account_ids: &[usize]) -> Self {
        assert_eq!(account_ids.len(), NUM_SENDERS_IN_BLOCK);
        let account_id_bits = account_ids
            .iter()
            .flat_map(|&account_id| (0..ACCOUNT_ID_BITS).map(move |i| (account_id >> i) & 1 == 1))
            .collect::<Vec<_>>();
        Self::from_bits_le(&account_id_bits)
    }

    pub fn unpack(&self) -> Vec<usize> {
        let bits = self.to_bits_le();
        let account_ids = bits
            .into_iter()
            .chunks(ACCOUNT_ID_BITS)
            .into_iter()
            .map(|chunk| {
                let chunk_bits = chunk.into_iter().collect::<Vec<_>>();
                le_bits_to_usize(&chunk_bits)
            })
            .collect::<Vec<_>>();
        assert_eq!(account_ids.len(), NUM_SENDERS_IN_BLOCK);
        account_ids
    }

    pub fn hash(&self) -> Bytes32<u32> {
        Bytes32::<u32>::from_limbs(&solidity_keccak256(&self.limbs()))
    }
}

impl AccountIdPacked<Target> {
    pub fn unpack<F: RichField + Extendable<D>, const D: usize>(
        &self,
        builder: &mut CircuitBuilder<F, D>,
    ) -> Vec<Target> {
        let bits = self.to_bits_le(builder);
        let account_ids = bits
            .into_iter()
            .chunks(ACCOUNT_ID_BITS)
            .into_iter()
            .map(|chunk| builder.le_sum(chunk.into_iter()))
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
    ) -> Bytes32<Target>
    where
        <C as GenericConfig<D>>::Hasher: AlgebraicHasher<F>,
    {
        Bytes32::<Target>::from_limbs(&builder.keccak256::<C>(&self.limbs()))
    }
}

pub(crate) fn le_bits_to_usize(bits: &[bool]) -> usize {
    let mut account_id = 0;
    for (i, bit) in bits.iter().enumerate() {
        if *bit {
            account_id |= 1 << i;
        }
    }
    account_id
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
}
