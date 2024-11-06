#[derive(Debug, Clone)]
pub struct MetaData {
    pub uuid: String,
    pub timestamp: u64,

    pub block_number: Option<u32>,
}
