use crate::{
    common::{block::Block, deposit::Deposit, trees::deposit_tree::DepositMerkleProof},
    ethereum_types::{
        bytes32::{Bytes32, BYTES32_LEN},
        u256::{U256, U256_LEN},
        u32limb_trait::U32LimbTrait,
        u64::{U64, U64_LEN},
    },
    utils::poseidon_hash_out::PoseidonHashOut,
};

const START_TIME_PUBLIC_INPUTS_LEN: usize = U256_LEN + BYTES32_LEN + 1 + U64_LEN + BYTES32_LEN + 1;

pub struct StartTimePublicInputs {
    pub pubkey: U256,
    pub nullifier: Bytes32,
    pub lock_time: u32,
    pub block_timestamp: u64,
    pub block_hash: Bytes32,
    pub block_number: u32,
}

impl StartTimePublicInputs {
    pub fn to_vec_u32(&self) -> Vec<u32> {
        let mut result = self.pubkey.to_u32_vec();
        result.push(self.lock_time);
        result.extend_from_slice(&self.nullifier.to_u32_vec());
        result.extend_from_slice(&U64::from(self.block_timestamp).to_u32_vec());
        result.extend_from_slice(&self.block_hash.to_u32_vec());
        result.push(self.block_number);
        assert_eq!(result.len(), START_TIME_PUBLIC_INPUTS_LEN);
        result
    }

    pub fn from_u32_vec(inputs: &[u32]) -> Self {
        assert_eq!(inputs.len(), START_TIME_PUBLIC_INPUTS_LEN);
        let pubkey = U256::from_u32_slice(&inputs[0..U256_LEN]);
        let nullifier = Bytes32::from_u32_slice(&inputs[U256_LEN..U256_LEN + BYTES32_LEN]);
        let lock_time = inputs[U256_LEN + BYTES32_LEN];
        let block_timestamp = U64::from_u32_slice(
            &inputs[U256_LEN + BYTES32_LEN + 1..U256_LEN + BYTES32_LEN + 1 + U64_LEN],
        );
        let block_hash = Bytes32::from_u32_slice(
            &inputs[U256_LEN + BYTES32_LEN + 1 + U64_LEN
                ..U256_LEN + BYTES32_LEN + 1 + U64_LEN + BYTES32_LEN],
        );
        let block_number = inputs[U256_LEN + BYTES32_LEN + 1 + U64_LEN + BYTES32_LEN];
        Self {
            pubkey,
            nullifier,
            lock_time,
            block_timestamp: block_timestamp.into(),
            block_hash,
            block_number,
        }
    }
}

pub struct StartTimeValue {
    pub prev_block: Block,
    pub block: Block,
    pub prev_deposit_merkle_proof: DepositMerkleProof,
    pub deposit_merkle_proof: DepositMerkleProof,
    pub deposit: Deposit,
    pub deposit_index: u32,
    pub deposit_salt: PoseidonHashOut,
    pub pubkey: U256,
    pub nullifier: Bytes32,
    pub lock_time: u32,
    pub block_hash: Bytes32,
    pub block_number: u32,
}

