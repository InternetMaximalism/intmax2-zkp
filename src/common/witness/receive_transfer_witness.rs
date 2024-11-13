use plonky2::{
    field::extension::Extendable,
    hash::hash_types::RichField,
    plonk::{config::GenericConfig, proof::ProofWithPublicInputs},
};
use serde::{Deserialize, Serialize};

use crate::common::trees::block_hash_tree::BlockHashMerkleProof;

use super::{
    private_transition_witness::PrivateTransitionWitness, transfer_witness::TransferWitness,
};

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
#[serde(bound = "")]
pub struct ReceiveTransferWitness<F, C, const D: usize>
where
    F: RichField + Extendable<D>,
    C: GenericConfig<D, F = F>,
{
    pub transfer_witness: TransferWitness,
    pub private_transition_witness: PrivateTransitionWitness,
    pub sender_balance_proof: ProofWithPublicInputs<F, C, D>,
    pub block_merkle_proof: BlockHashMerkleProof, /* root: receiver's block number, leaf:
                                                   * sender's block number */
}
