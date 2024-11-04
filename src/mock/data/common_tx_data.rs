use plonky2::{
    field::extension::Extendable,
    hash::hash_types::RichField,
    plonk::{config::GenericConfig, proof::ProofWithPublicInputs},
};
use serde::{Deserialize, Serialize};

use crate::{
    common::{trees::tx_tree::TxMerkleProof, tx::Tx},
    ethereum_types::bytes32::Bytes32,
};

// tx data for both sender and receiver
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
#[serde(bound = "")]
pub struct CommonTxData<F, C, const D: usize>
where
    F: RichField + Extendable<D>,
    C: GenericConfig<D, F = F>,
{
    // Sender's spent proof of the target tx.
    pub spent_proof: ProofWithPublicInputs<F, C, D>,
    // Block number of the sender's balance proof before the target tx.
    pub sender_prev_block_number: u32,

    // Used for updating sender's balance proof
    pub tx: Tx,
    pub tx_index: usize,
    pub tx_merkle_proof: TxMerkleProof,
    pub tx_tree_root: Bytes32,
}

impl<F, C, const D: usize> CommonTxData<F, C, D>
where
    F: RichField + Extendable<D>,
    C: GenericConfig<D, F = F>,
{
    pub fn validate(&self) -> anyhow::Result<()> {
        self.tx_merkle_proof
            .verify(&self.tx, self.tx_index, self.tx_tree_root.try_into()?)?;
        Ok(())
    }
}
