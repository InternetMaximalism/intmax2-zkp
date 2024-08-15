use serde::{Deserialize, Serialize};

use super::{deposit_witness::DepositWitness, private_witness::PrivateWitness};

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ReceiveDepositWitness {
    pub deposit_witness: DepositWitness,
    pub private_witness: PrivateWitness,
}
