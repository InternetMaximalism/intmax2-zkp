use uuid::Uuid;

#[derive(Debug, Clone, Copy)]
pub struct MetaData {
    pub uuid: Uuid,
    pub block_number: u32,
}
