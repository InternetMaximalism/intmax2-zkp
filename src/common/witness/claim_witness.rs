use plonky2::{
    field::extension::Extendable, hash::hash_types::RichField, plonk::config::GenericConfig,
};
use serde::{Deserialize, Serialize};

use crate::{
    circuits::claim::utils::get_mining_deposit_nullifier, common::claim::Claim,
    ethereum_types::address::Address,
};

use super::{deposit_time_witness::DepositTimeWitness, update_witness::UpdateWitness};

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
#[serde(bound = "")]
pub struct ClaimWitness<F, C, const D: usize>
where
    F: RichField + Extendable<D>,
    C: GenericConfig<D, F = F>,
{
    pub recipient: Address,
    pub deposit_time_witness: DepositTimeWitness,
    pub update_witness: UpdateWitness<F, C, D>,
}

impl<F, C, const D: usize> ClaimWitness<F, C, D>
where
    F: RichField + Extendable<D>,
    C: GenericConfig<D, F = F>,
{
    pub fn to_claim(&self) -> Claim {
        let deposit = self.deposit_time_witness.deposit.clone();
        let deposit_salt = self.deposit_time_witness.deposit_salt;
        let nullifier = get_mining_deposit_nullifier(&deposit, deposit_salt);
        let validity_pis = self.update_witness.validity_pis();
        Claim {
            recipient: self.recipient,
            amount: deposit.amount,
            nullifier,
            block_hash: validity_pis.public_state.block_hash,
            block_number: validity_pis.public_state.block_number,
        }
    }
}
