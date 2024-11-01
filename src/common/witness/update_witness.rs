use anyhow::ensure;
use plonky2::{
    field::extension::Extendable,
    hash::hash_types::RichField,
    plonk::{config::GenericConfig, proof::ProofWithPublicInputs},
};

use crate::{
    circuits::validity::validity_pis::ValidityPublicInputs,
    common::{
        public_state::PublicState,
        trees::{account_tree::AccountMembershipProof, block_hash_tree::BlockHashMerkleProof},
    },
};

#[derive(Debug, Clone)]
pub struct UpdateWitness<F, C, const D: usize>
where
    F: RichField + Extendable<D>,
    C: GenericConfig<D, F = F>,
{
    pub is_prev_account_tree: bool,
    pub validity_proof: ProofWithPublicInputs<F, C, D>,
    pub block_merkle_proof: BlockHashMerkleProof, /* block merkle proof that shows the
                                                   * block of prev_public_state is included in
                                                   * the
                                                   * block tree of validity_proof */
    pub account_membership_proof: AccountMembershipProof, /* account membership proof that
                                                           * shows no tx has been sent
                                                           * before
                                                           * the block of validity proof. */
}

impl<F, C, const D: usize> UpdateWitness<F, C, D>
where
    F: RichField + Extendable<D>,
    C: GenericConfig<D, F = F>,
{
    pub fn prev_account_membership_proof(&self) -> anyhow::Result<AccountMembershipProof> {
        ensure!(
            self.is_prev_account_tree,
            "prev account tree is not available"
        );
        Ok(self.account_membership_proof.clone())
    }

    pub fn get_last_block_number(&self) -> u32 {
        self.account_membership_proof.get_value() as u32
    }

    pub fn validity_pis(&self) -> ValidityPublicInputs {
        ValidityPublicInputs::from_pis(&self.validity_proof.public_inputs)
    }

    pub fn public_state(&self) -> PublicState {
        self.validity_pis().public_state
    }
}
