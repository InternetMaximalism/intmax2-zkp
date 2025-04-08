use crate::{
    circuits::balance::receive::{error::UpdateError, update_circuit::UpdateValue},
    common::error::CommonError,
    ethereum_types::u256::U256,
};
use plonky2::{
    field::extension::Extendable,
    hash::hash_types::RichField,
    plonk::{
        circuit_data::VerifierCircuitData,
        config::{AlgebraicHasher, GenericConfig},
        proof::ProofWithPublicInputs,
    },
};
use serde::{Deserialize, Serialize};

use crate::{
    circuits::validity::validity_pis::ValidityPublicInputs,
    common::{
        public_state::PublicState,
        trees::{account_tree::AccountMembershipProof, block_hash_tree::BlockHashMerkleProof},
    },
};

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
#[serde(bound = "")]
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
    pub fn prev_account_membership_proof(&self) -> Result<AccountMembershipProof, CommonError> {
        if !self.is_prev_account_tree {
            return Err(CommonError::InvalidWitness(
                "prev account tree is not available".to_string(),
            ));
        }
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

    pub fn to_value(
        &self,
        validity_vd: &VerifierCircuitData<F, C, D>,
        pubkey: U256,
        prev_public_state: &PublicState,
    ) -> Result<UpdateValue<F, C, D>, UpdateError>
    where
        <C as GenericConfig<D>>::Hasher: AlgebraicHasher<F>,
    {
        UpdateValue::new(
            validity_vd,
            pubkey,
            &self.validity_proof,
            prev_public_state,
            &self.block_merkle_proof,
            &self.account_membership_proof,
        )
    }
}
