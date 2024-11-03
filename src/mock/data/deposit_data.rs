use anyhow::ensure;
use serde::{Deserialize, Serialize};

use crate::{
    common::{
        deposit::{get_pubkey_salt_hash, Deposit},
        salt::Salt,
        signature::key_set::KeySet,
    },
    ethereum_types::u256::U256,
};

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct DepositData {
    pub deposit_id: u32,
    pub deposit_salt: Salt,
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

    pub fn decrypt(bytes: &[u8], key: KeySet) -> anyhow::Result<Self> {
        let data = Self::from_bytes(bytes)?;
        data.validate(key)?;
        Ok(data)
    }

    fn validate(&self, key: KeySet) -> anyhow::Result<()> {
        ensure!(
            self.deposit.pubkey_salt_hash == get_pubkey_salt_hash(key.pubkey, self.deposit_salt),
            "invalid pubkey_salt_hash"
        );
        todo!()
    }
}
