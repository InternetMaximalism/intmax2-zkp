use crate::{
    circuits::mining::{
        determine_lock_time::DetermineLockTimeValue, utils::get_mining_deposit_nullifier,
    },
    common::{
        block::Block,
        deposit::{get_pubkey_salt_hash, Deposit},
        salt::Salt,
        trees::deposit_tree::DepositMerkleProof,
    },
    ethereum_types::{
        bytes32::{Bytes32, BYTES32_LEN},
        u256::{U256, U256_LEN},
        u32limb_trait::U32LimbTrait,
        u64::{U64, U64_LEN},
    },
    utils::leafable::Leafable,
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
    pub deposit_salt: Salt,
    pub pubkey: U256,
    pub nullifier: Bytes32,
    pub lock_time: u32,
    pub block_hash: Bytes32,
}

impl StartTimeValue {
    pub fn new(
        prev_block: Block,
        block: Block,
        prev_deposit_merkle_proof: DepositMerkleProof,
        deposit_merkle_proof: DepositMerkleProof,
        deposit: Deposit,
        deposit_index: u32,
        deposit_salt: Salt,
        pubkey: U256,
    ) -> anyhow::Result<Self> {
        // deposit non-inclusion proof of prev_deposit_merkle_proof
        prev_deposit_merkle_proof
            .verify(
                &Deposit::empty_leaf(),
                deposit_index as u64,
                prev_block.deposit_tree_root,
            )
            .map_err(|e| anyhow::anyhow!("prev_deposit_merkle_proof.verify failed: {:?}", e))?;
        // deposit inclusion proof of deposit_merkle_proof
        deposit_merkle_proof
            .verify(&deposit, deposit_index as u64, block.deposit_tree_root)
            .map_err(|e| anyhow::anyhow!("deposit_merkle_proof.verify failed: {:?}", e))?;
        // ensure that prev_block is the parent of block
        if prev_block.hash() != block.prev_block_hash {
            return Err(anyhow::anyhow!(
                "prev_block.hash() != block.prev_block_hash"
            ));
        }
        // proving that the deposit is bound to the pubkey
        let pubkey_salt_hash = get_pubkey_salt_hash(pubkey, deposit_salt);
        if pubkey_salt_hash != deposit.pubkey_salt_hash {
            return Err(anyhow::anyhow!(
                "pubkey_salt_hash != deposit.pubkey_salt_hash"
            ));
        }

        let nullifier = get_mining_deposit_nullifier(&deposit, deposit_salt);
        let block_hash = block.hash();
        let determine_lock_time_value = DetermineLockTimeValue::new(block_hash, deposit_salt);
        let lock_time = determine_lock_time_value.lock_time;

        Ok(Self {
            prev_block,
            block,
            prev_deposit_merkle_proof,
            deposit_merkle_proof,
            deposit,
            deposit_index,
            deposit_salt,
            pubkey,
            nullifier,
            lock_time,
            block_hash,
        })
    }
}
