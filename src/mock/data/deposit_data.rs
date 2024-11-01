use serde::{Deserialize, Serialize};

use crate::{
    common::{deposit::Deposit, salt::Salt, signature::key_set::KeySet},
    ethereum_types::u256::U256,
};

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct DepositData {
    pub deposit_salt: Salt,
    pub deposit_index: usize,
    pub deposit: Deposit,
}

impl DepositData {
    fn to_bytes(&self) -> Vec<u8> {
        bincode::serialize(self).unwrap()
    }

    fn from_bytes(bytes: &[u8]) -> anyhow::Result<Self> {
        let data = bincode::deserialize(bytes)?;
        Ok(data)
    }

    pub fn encrypt(&self, _pubkey: U256) -> Vec<u8> {
        let bytes = self.to_bytes();
        bytes
    }

    pub fn decrypt(bytes: &[u8], _key: KeySet) -> anyhow::Result<Self> {
        let data = Self::from_bytes(bytes)?;
        Ok(data)
    }
}
