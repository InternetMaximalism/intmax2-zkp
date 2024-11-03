use plonky2::{
    field::extension::Extendable,
    hash::hash_types::RichField,
    plonk::{config::GenericConfig, proof::ProofWithPublicInputs},
};
use serde::{Deserialize, Serialize};

use crate::{
    common::{
        signature::key_set::KeySet,
        trees::{sender_tree::SenderLeaf, tx_tree::TxMerkleProof},
        tx::Tx,
    },
    ethereum_types::{bytes32::Bytes32, u256::U256},
};

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
#[serde(bound = "")]
pub struct TxData<F, C, const D: usize>
where
    F: RichField + Extendable<D>,
    C: GenericConfig<D, F = F>,
{
    // Sender's spent proof of the target tx.
    pub spent_proof: ProofWithPublicInputs<F, C, D>,

    // Used for updating sender's balance proof
    pub tx: Tx,
    pub tx_index: usize,
    pub tx_merkle_proof: TxMerkleProof,
    pub tx_tree_root: Bytes32,
    pub sender_leaves: Vec<SenderLeaf>, // Sender leaves of the block where the tx is included
}

impl<F, C, const D: usize> TxData<F, C, D>
where
    F: RichField + Extendable<D>,
    C: GenericConfig<D, F = F>,
{
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
        data.validate(_key)?;
        Ok(data)
    }

    pub fn validate(&self, _key: KeySet) -> anyhow::Result<()> {
        self.tx_merkle_proof
            .verify(&self.tx, self.tx_index, self.tx_tree_root.try_into()?)?;
        Ok(())
    }
}
