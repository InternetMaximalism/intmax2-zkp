use plonky2::{field::extension::Extendable, hash::hash_types::RichField, plonk::config::GenericConfig};
use serde::{Deserialize, Serialize};

use super::common_tx_data::CommonTxData;

// tx data for sender
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
#[serde(bound = "")]
pub struct TxData<F, C, const D: usize>
where
    F: RichField + Extendable<D>,
    C: GenericConfig<D, F = F>,
{
    pub common: CommonTxData<F, C, D>,
    
}
