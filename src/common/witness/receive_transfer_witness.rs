use plonky2::{
    field::extension::Extendable,
    hash::hash_types::RichField,
    plonk::{config::GenericConfig, proof::ProofWithPublicInputs},
};

use crate::common::trees::block_hash_tree::BlockHashMerkleProof;

use super::{private_witness::PrivateWitness, transfer_witness::TransferWitness};

#[derive(Debug, Clone)]
pub struct ReceiveTransferWitness<F, C, const D: usize>
where
    F: RichField + Extendable<D>,
    C: GenericConfig<D, F = F>,
{
    pub transfer_witness: TransferWitness,
    pub private_witness: PrivateWitness,
    pub balance_proof: ProofWithPublicInputs<F, C, D>,
    pub block_merkle_proof: BlockHashMerkleProof,
}
