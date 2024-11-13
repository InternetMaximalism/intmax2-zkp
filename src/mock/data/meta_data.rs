use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct MetaData {
    pub uuid: String,
    pub timestamp: u64,

    pub block_number: Option<u32>,
}
