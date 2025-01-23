use plonky2::{
    field::extension::Extendable, hash::hash_types::RichField, plonk::config::GenericConfig,
};
use serde::{Deserialize, Serialize};

use super::{deposit_time_witness::DepositTimeWitness, update_witness::UpdateWitness};

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
#[serde(bound = "")]
pub struct ClaimWitness<F, C, const D: usize>
where
    F: RichField + Extendable<D>,
    C: GenericConfig<D, F = F>,
{
    pub deposit_time_witness: DepositTimeWitness,
    pub update_witness: UpdateWitness<F, C, D>,
}
