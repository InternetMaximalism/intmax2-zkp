use plonky2::{
    field::extension::Extendable,
    hash::hash_types::RichField,
    plonk::{config::GenericConfig, proof::ProofWithPublicInputs},
};

use crate::common::trees::{
    account_tree::AccountMembershipProof, block_hash_tree::BlockHashMerkleProof,
};

#[derive(Debug, Clone)]
pub struct UpdateWitness<F, C, const D: usize>
where
    F: RichField + Extendable<D>,
    C: GenericConfig<D, F = F>,
{
    pub validity_proof: ProofWithPublicInputs<F, C, D>,
    pub block_merkle_proof: BlockHashMerkleProof,
    pub account_membership_proof: AccountMembershipProof,
}
