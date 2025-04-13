//! Deposit time verification circuit for claim process.
//!
//! This circuit proves that a deposit was included in a specific block for the first time:
//! 1. Verifies the deposit was not in the previous block (non-inclusion proof)
//! 2. Verifies the deposit is in the current block (inclusion proof)
//! 3. Verifies the deposit is bound to the provided public key
//! 4. Calculates a nullifier for the deposit to prevent double-claiming
//! 5. Determines a lock time for the deposit based on the block hash and deposit salt
//!
//! The deposit time circuit is a critical component of the claim process, establishing
//! when a deposit became available and calculating its lock time before it can be claimed.

use plonky2::{
    field::{extension::Extendable, types::Field},
    hash::hash_types::RichField,
    iop::{
        target::Target,
        witness::{PartialWitness, WitnessWrite},
    },
    plonk::{
        circuit_builder::CircuitBuilder,
        circuit_data::{CircuitConfig, CircuitData},
        config::{AlgebraicHasher, GenericConfig},
        proof::ProofWithPublicInputs,
    },
};

use crate::{
    circuits::claim::{
        determine_lock_time::DetermineLockTimeValue,
        error::ClaimError,
        utils::{get_mining_deposit_nullifier, get_mining_deposit_nullifier_circuit},
    },
    common::{
        block::{Block, BlockTarget},
        deposit::{get_pubkey_salt_hash, get_pubkey_salt_hash_circuit, Deposit, DepositTarget},
        error::CommonError,
        salt::{Salt, SaltTarget},
        trees::deposit_tree::{DepositMerkleProof, DepositMerkleProofTarget},
    },
    constants::DEPOSIT_TREE_HEIGHT,
    ethereum_types::{
        bytes32::{Bytes32, Bytes32Target, BYTES32_LEN},
        u256::{U256Target, U256, U256_LEN},
        u32limb_trait::{U32LimbTargetTrait as _, U32LimbTrait},
        u64::{U64Target, U64, U64_LEN},
    },
    utils::leafable::{Leafable, LeafableTarget},
};

use super::determine_lock_time::{DetermineLockTimeTarget, LockTimeConfig};

/// Length of public inputs for the deposit time circuit
const DEPOSIT_TIME_PUBLIC_INPUTS_LEN: usize =
    U256_LEN + BYTES32_LEN + U256_LEN + 1 + U64_LEN + BYTES32_LEN + 1;

/// Public inputs for the deposit time circuit
///
/// These values are made public in the ZKP and are used to verify the deposit's
/// eligibility for claiming and to calculate the lock time before it can be claimed.
#[derive(Debug, Clone)]
pub struct DepositTimePublicInputs {
    pub pubkey: U256,         // Public key of the claimer
    pub nullifier: Bytes32,   // Nullifier to prevent double-claiming
    pub deposit_amount: U256, // Amount of the deposit
    pub lock_time: u32,       // Time period the deposit must be locked before claiming
    pub block_timestamp: u64, // Timestamp of the block containing the deposit
    pub block_hash: Bytes32,  // Hash of the block containing the deposit
    pub block_number: u32,    // Number of the block containing the deposit
}

impl DepositTimePublicInputs {
    pub fn to_vec_u32(&self) -> Vec<u32> {
        let mut result = self.pubkey.to_u32_vec();
        result.extend_from_slice(&self.nullifier.to_u32_vec());
        result.push(self.lock_time);
        result.extend_from_slice(&self.nullifier.to_u32_vec());
        result.extend_from_slice(&U64::from(self.block_timestamp).to_u32_vec());
        result.extend_from_slice(&self.block_hash.to_u32_vec());
        result.push(self.block_number);
        assert_eq!(result.len(), DEPOSIT_TIME_PUBLIC_INPUTS_LEN);
        result
    }

    pub fn from_u32_slice(inputs: &[u32]) -> Result<Self, super::error::ClaimError> {
        if inputs.len() != DEPOSIT_TIME_PUBLIC_INPUTS_LEN {
            return Err(super::error::ClaimError::InvalidInput(format!(
                "Invalid input length for DepositTimePublicInputs: expected {}, got {}",
                DEPOSIT_TIME_PUBLIC_INPUTS_LEN,
                inputs.len()
            )));
        }
        let pubkey = U256::from_u32_slice(&inputs[0..U256_LEN]).unwrap();
        let nullifier = Bytes32::from_u32_slice(&inputs[U256_LEN..U256_LEN + BYTES32_LEN]).unwrap();
        let deposit_amount = U256::from_u32_slice(
            &inputs[U256_LEN + BYTES32_LEN..U256_LEN + BYTES32_LEN + U256_LEN],
        )
        .unwrap();
        let lock_time = inputs[U256_LEN + BYTES32_LEN + U256_LEN];
        let block_timestamp = U64::from_u32_slice(
            &inputs[U256_LEN + BYTES32_LEN + U256_LEN + 1
                ..U256_LEN + BYTES32_LEN + U256_LEN + 1 + U64_LEN],
        )
        .unwrap();
        let block_hash = Bytes32::from_u32_slice(
            &inputs[U256_LEN + BYTES32_LEN + U256_LEN + 1 + U64_LEN
                ..U256_LEN + BYTES32_LEN + U256_LEN + 1 + U64_LEN + BYTES32_LEN],
        )
        .unwrap();
        let block_number = inputs[U256_LEN + BYTES32_LEN + U256_LEN + 1 + U64_LEN + BYTES32_LEN];
        Ok(Self {
            pubkey,
            nullifier,
            deposit_amount,
            lock_time,
            block_timestamp: block_timestamp.into(),
            block_hash,
            block_number,
        })
    }

    pub fn from_u64_slice(inputs: &[u64]) -> Result<Self, super::error::ClaimError> {
        let input_u32: Result<Vec<u32>, super::error::ClaimError> = inputs
            .iter()
            .map(|&x| {
                if x <= u32::MAX as u64 {
                    Ok(x as u32)
                } else {
                    Err(super::error::ClaimError::InvalidInput(format!(
                        "Value {} exceeds u32::MAX",
                        x
                    )))
                }
            })
            .collect();
        Self::from_u32_slice(&input_u32?)
    }
}

/// Target version of DepositTimePublicInputs for use in ZKP circuits
///
/// Contains circuit targets for all public inputs that will be exposed
/// in the proof for verification.
#[derive(Debug, Clone)]
pub struct DepositTimePublicInputsTarget {
    pub pubkey: U256Target,         // Target for claimer's public key
    pub nullifier: Bytes32Target,   // Target for deposit nullifier
    pub deposit_amount: U256Target, // Target for deposit amount
    pub lock_time: Target,          // Target for lock time duration
    pub block_timestamp: U64Target, // Target for block timestamp
    pub block_hash: Bytes32Target,  // Target for block hash
    pub block_number: Target,       // Target for block number
}

impl DepositTimePublicInputsTarget {
    pub fn to_vec(&self) -> Vec<Target> {
        let mut result = self.pubkey.to_vec();
        result.extend_from_slice(&self.nullifier.to_vec());
        result.extend_from_slice(&self.deposit_amount.to_vec());
        result.push(self.lock_time);
        result.extend_from_slice(&self.block_timestamp.to_vec());
        result.extend_from_slice(&self.block_hash.to_vec());
        result.push(self.block_number);
        assert_eq!(result.len(), DEPOSIT_TIME_PUBLIC_INPUTS_LEN);
        result
    }

    pub fn from_slice(inputs: &[Target]) -> Self {
        assert_eq!(inputs.len(), DEPOSIT_TIME_PUBLIC_INPUTS_LEN);
        let pubkey = U256Target::from_slice(&inputs[0..U256_LEN]);
        let nullifier = Bytes32Target::from_slice(&inputs[U256_LEN..U256_LEN + BYTES32_LEN]);
        let deposit_amount = U256Target::from_slice(
            &inputs[U256_LEN + BYTES32_LEN..U256_LEN + BYTES32_LEN + U256_LEN],
        );
        let lock_time = inputs[U256_LEN + BYTES32_LEN + U256_LEN];
        let block_timestamp = U64Target::from_slice(
            &inputs[U256_LEN + BYTES32_LEN + U256_LEN + 1
                ..U256_LEN + BYTES32_LEN + U256_LEN + 1 + U64_LEN],
        );
        let block_hash = Bytes32Target::from_slice(
            &inputs[U256_LEN + BYTES32_LEN + U256_LEN + 1 + U64_LEN
                ..U256_LEN + BYTES32_LEN + U256_LEN + 1 + U64_LEN + BYTES32_LEN],
        );
        let block_number = inputs[U256_LEN + BYTES32_LEN + U256_LEN + 1 + U64_LEN + BYTES32_LEN];
        Self {
            pubkey,
            nullifier,
            deposit_amount,
            lock_time,
            block_timestamp,
            block_hash,
            block_number,
        }
    }
}

/// Values needed to prove deposit time verification
///
/// Contains all the data required to prove that a deposit was included in a specific block
/// for the first time and to calculate its lock time and nullifier.
pub struct DepositTimeValue {
    pub prev_block: Block, // Previous block (to prove deposit wasn't included yet)
    pub block: Block,      // Block containing the deposit
    pub prev_deposit_merkle_proof: DepositMerkleProof, // Proof of non-inclusion in previous block
    pub deposit_merkle_proof: DepositMerkleProof, // Proof of inclusion in current block
    pub deposit: Deposit,  // The deposit being verified
    pub deposit_index: u32, // Index of the deposit in the deposit tree
    pub deposit_salt: Salt, // Salt used to hide the public key in the deposit
    pub block_hash: Bytes32, // Hash of the block containing the deposit
    pub pubkey: U256,      // Public key of the claimer
    pub nullifier: Bytes32, // Calculated nullifier for the deposit
    pub determine_lock_time_value: DetermineLockTimeValue, // Lock time calculation data
}

impl DepositTimeValue {
    /// Creates a new DepositTimeValue by validating the deposit's inclusion in the block
    /// and calculating its nullifier and lock time.
    ///
    /// This function:
    /// 1. Verifies the deposit is eligible for mining
    /// 2. Verifies the deposit was not in the previous block (non-inclusion proof)
    /// 3. Verifies the deposit is in the current block (inclusion proof)
    /// 4. Verifies the blocks are sequential (prev_block is parent of block)
    /// 5. Verifies the deposit is bound to the provided public key
    /// 6. Calculates the deposit's nullifier and lock time
    ///
    /// # Arguments
    /// * `config` - Configuration for lock time calculation
    /// * `prev_block` - Previous block (to prove deposit wasn't included yet)
    /// * `block` - Block containing the deposit
    /// * `prev_deposit_merkle_proof` - Proof of non-inclusion in previous block
    /// * `deposit_merkle_proof` - Proof of inclusion in current block
    /// * `deposit` - The deposit being verified
    /// * `deposit_index` - Index of the deposit in the deposit tree
    /// * `deposit_salt` - Salt used to hide the public key in the deposit
    /// * `pubkey` - Public key of the claimer
    ///
    /// # Returns
    /// A Result containing either the new DepositTimeValue or an error
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        config: &LockTimeConfig,
        prev_block: &Block,
        block: &Block,
        prev_deposit_merkle_proof: &DepositMerkleProof,
        deposit_merkle_proof: &DepositMerkleProof,
        deposit: &Deposit,
        deposit_index: u32,
        deposit_salt: Salt,
        pubkey: U256,
    ) -> Result<Self, CommonError> {
        if !deposit.is_eligible {
            return Err(CommonError::InvalidData(
                "deposit is not eligible for mining".to_string(),
            ));
        }
        // deposit non-inclusion proof of prev_deposit_merkle_proof
        prev_deposit_merkle_proof
            .verify(
                &Deposit::empty_leaf(),
                deposit_index as u64,
                prev_block.deposit_tree_root,
            )
            .map_err(|e| {
                CommonError::InvalidProof(format!(
                    "prev_deposit_merkle_proof.verify failed: {:?}",
                    e
                ))
            })?;
        // deposit inclusion proof of deposit_merkle_proof
        deposit_merkle_proof
            .verify(deposit, deposit_index as u64, block.deposit_tree_root)
            .map_err(|e| {
                CommonError::InvalidProof(format!("deposit_merkle_proof.verify failed: {:?}", e))
            })?;
        // ensure that prev_block is the parent of block
        if prev_block.hash() != block.prev_block_hash {
            return Err(CommonError::InvalidBlock(
                "prev_block.hash() != block.prev_block_hash".to_string(),
            ));
        }
        // proving that the deposit is bound to the pubkey
        let pubkey_salt_hash = get_pubkey_salt_hash(pubkey, deposit_salt);
        if pubkey_salt_hash != deposit.pubkey_salt_hash {
            return Err(CommonError::InvalidData(
                "pubkey_salt_hash != deposit.pubkey_salt_hash".to_string(),
            ));
        }

        let nullifier = get_mining_deposit_nullifier(deposit, deposit_salt);
        let block_hash = block.hash();
        let determine_lock_time_value =
            DetermineLockTimeValue::new(config, block_hash, deposit_salt);

        Ok(Self {
            prev_block: prev_block.clone(),
            block: block.clone(),
            prev_deposit_merkle_proof: prev_deposit_merkle_proof.clone(),
            deposit_merkle_proof: deposit_merkle_proof.clone(),
            deposit: deposit.clone(),
            deposit_index,
            deposit_salt,
            block_hash,
            pubkey,
            nullifier,
            determine_lock_time_value,
        })
    }
}

/// Target version of DepositTimeValue for use in ZKP circuits
///
/// Contains circuit targets for all components needed to verify a deposit's
/// inclusion in a block and calculate its lock time and nullifier.
#[derive(Debug, Clone)]
pub struct DepositTimeTarget {
    pub prev_block: BlockTarget, // Target for previous block
    pub block: BlockTarget,      // Target for block containing the deposit
    pub prev_deposit_merkle_proof: DepositMerkleProofTarget, // Target for non-inclusion proof
    pub deposit_merkle_proof: DepositMerkleProofTarget, // Target for inclusion proof
    pub deposit: DepositTarget,  // Target for the deposit
    pub deposit_index: Target,   // Target for deposit index
    pub deposit_salt: SaltTarget, // Target for deposit salt
    pub block_hash: Bytes32Target, // Target for block hash
    pub pubkey: U256Target,      // Target for claimer's public key
    pub nullifier: Bytes32Target, // Target for deposit nullifier
    pub determine_lock_time_target: DetermineLockTimeTarget, // Target for lock time calculation
}

impl DepositTimeTarget {
    /// Creates a new DepositTimeTarget with circuit constraints that enforce
    /// the deposit time verification rules.
    ///
    /// The circuit enforces:
    /// 1. Deposit is eligible for mining
    /// 2. Deposit was not in the previous block (non-inclusion proof)
    /// 3. Deposit is in the current block (inclusion proof)
    /// 4. Blocks are sequential (prev_block is parent of block)
    /// 5. Deposit is bound to the provided public key
    /// 6. Correct calculation of the deposit's nullifier and lock time
    ///
    /// # Arguments
    /// * `builder` - Circuit builder
    /// * `is_checked` - Whether to add constraints for checking the values
    /// * `config` - Configuration for lock time calculation
    ///
    /// # Returns
    /// A new DepositTimeTarget with all necessary targets and constraints
    pub fn new<F: RichField + Extendable<D>, C: GenericConfig<D, F = F> + 'static, const D: usize>(
        builder: &mut CircuitBuilder<F, D>,
        is_checked: bool,
        config: &LockTimeConfig,
    ) -> Self
    where
        <C as GenericConfig<D>>::Hasher: AlgebraicHasher<F>,
    {
        let prev_block = BlockTarget::new(builder, is_checked);
        let block = BlockTarget::new(builder, is_checked);
        let prev_deposit_merkle_proof = DepositMerkleProofTarget::new(builder, DEPOSIT_TREE_HEIGHT);
        let deposit_merkle_proof = DepositMerkleProofTarget::new(builder, DEPOSIT_TREE_HEIGHT);
        let deposit = DepositTarget::new(builder, is_checked);
        let deposit_index = builder.add_virtual_target();
        if is_checked {
            builder.range_check(deposit_index, 32);
        }
        let deposit_salt = SaltTarget::new(builder);
        let pubkey = U256Target::new(builder, is_checked);

        builder.assert_one(deposit.is_eligible.target);

        let empty_deposit = DepositTarget::empty_leaf(builder);
        prev_deposit_merkle_proof.verify::<F, C, D>(
            builder,
            &empty_deposit,
            deposit_index,
            prev_block.deposit_tree_root,
        );
        deposit_merkle_proof.verify::<F, C, D>(
            builder,
            &deposit,
            deposit_index,
            block.deposit_tree_root,
        );
        let prev_block_hash = prev_block.hash::<F, C, D>(builder);
        prev_block_hash.connect(builder, block.prev_block_hash);
        let pubkey_salt_hash = get_pubkey_salt_hash_circuit(builder, pubkey, deposit_salt);
        pubkey_salt_hash.connect(builder, deposit.pubkey_salt_hash);

        let nullifier = get_mining_deposit_nullifier_circuit(builder, &deposit, deposit_salt);
        let block_hash = block.hash::<F, C, D>(builder);

        let determine_lock_time_target = DetermineLockTimeTarget::new(builder, is_checked, config);
        determine_lock_time_target
            .block_hash
            .connect(builder, block_hash);
        determine_lock_time_target
            .deposit_salt
            .connect(builder, deposit_salt);
        Self {
            prev_block,
            block,
            prev_deposit_merkle_proof,
            deposit_merkle_proof,
            deposit,
            deposit_index,
            deposit_salt,
            block_hash,
            pubkey,
            nullifier,
            determine_lock_time_target,
        }
    }

    pub fn set_witness<W: WitnessWrite<F>, F: Field>(
        &self,
        witness: &mut W,
        value: &DepositTimeValue,
    ) {
        self.prev_block.set_witness(witness, &value.prev_block);
        self.block.set_witness(witness, &value.block);
        self.prev_deposit_merkle_proof
            .set_witness(witness, &value.prev_deposit_merkle_proof);
        self.deposit_merkle_proof
            .set_witness(witness, &value.deposit_merkle_proof);
        self.deposit.set_witness(witness, &value.deposit);
        witness.set_target(
            self.deposit_index,
            F::from_canonical_u32(value.deposit_index),
        );
        self.deposit_salt.set_witness(witness, value.deposit_salt);
        self.block_hash.set_witness(witness, value.block_hash);
        self.pubkey.set_witness(witness, value.pubkey);
        self.nullifier.set_witness(witness, value.nullifier);
        self.determine_lock_time_target
            .set_witness(witness, &value.determine_lock_time_value);
    }
}

/// Circuit for verifying deposit time and calculating lock time and nullifier
///
/// This circuit proves:
/// 1. A deposit was included in a specific block for the first time
/// 2. The deposit is bound to the provided public key
/// 3. The deposit is eligible for mining
///
/// And calculates:
/// 1. A nullifier for the deposit to prevent double-claiming
/// 2. A lock time for the deposit based on the block hash and deposit salt
#[derive(Debug)]
pub struct DepositTimeCircuit<F, C, const D: usize>
where
    F: RichField + Extendable<D>,
    C: GenericConfig<D, F = F>,
{
    pub data: CircuitData<F, C, D>,
    pub target: DepositTimeTarget,
}

impl<F, C, const D: usize> DepositTimeCircuit<F, C, D>
where
    F: RichField + Extendable<D>,
    C: GenericConfig<D, F = F> + 'static,
    C::Hasher: AlgebraicHasher<F>,
{
    /// Creates a new DepositTimeCircuit with the specified lock time configuration
    ///
    /// # Arguments
    /// * `lock_config` - Configuration for lock time calculation
    ///
    /// # Returns
    /// A new DepositTimeCircuit ready to generate proofs
    pub fn new(lock_config: &LockTimeConfig) -> Self {
        let config = CircuitConfig::default();
        let mut builder = CircuitBuilder::<F, D>::new(config.clone());
        let target = DepositTimeTarget::new::<F, C, D>(&mut builder, true, lock_config);
        let pis = DepositTimePublicInputsTarget {
            pubkey: target.pubkey,
            nullifier: target.nullifier,
            deposit_amount: target.deposit.amount,
            lock_time: target.determine_lock_time_target.lock_time,
            block_timestamp: target.block.timestamp,
            block_hash: target.block_hash,
            block_number: target.block.block_number,
        };
        builder.register_public_inputs(&pis.to_vec());
        let data = builder.build();
        Self { data, target }
    }

    /// Generates a proof for the deposit time verification
    ///
    /// # Arguments
    /// * `value` - DepositTimeValue containing all the data needed for the proof
    ///
    /// # Returns
    /// A Result containing either the proof or an error
    pub fn prove(
        &self,
        value: &DepositTimeValue,
    ) -> Result<ProofWithPublicInputs<F, C, D>, ClaimError> {
        let mut pw = PartialWitness::<F>::new();
        self.target.set_witness(&mut pw, value);
        self.data
            .prove(pw)
            .map_err(|e| ClaimError::ProofGenerationError(format!("{:?}", e)))
    }
}

#[cfg(test)]
mod tests {
    use plonky2::{
        field::goldilocks_field::GoldilocksField, plonk::config::PoseidonGoldilocksConfig,
    };
    use rand::Rng as _;

    use crate::{
        common::{
            block::Block,
            deposit::{get_pubkey_salt_hash, Deposit},
            salt::Salt,
            trees::deposit_tree::DepositTree,
        },
        constants::DEPOSIT_TREE_HEIGHT,
        ethereum_types::{
            address::Address, bytes32::Bytes32, u256::U256, u32limb_trait::U32LimbTrait,
        },
    };

    type F = GoldilocksField;
    type C = PoseidonGoldilocksConfig;
    const D: usize = 2;

    /// Tests the deposit time circuit by creating a scenario where a deposit is included
    /// in a block for the first time and verifying that the circuit correctly proves this.
    ///
    /// The test:
    /// 1. Creates a random public key and deposit salt
    /// 2. Creates a deposit with the pubkey_salt_hash and marks it as eligible
    /// 3. Creates a previous block without the deposit
    /// 4. Creates a current block with the deposit
    /// 5. Generates proofs of non-inclusion in the previous block and inclusion in the current
    ///    block
    /// 6. Creates a DepositTimeValue with all the necessary data
    /// 7. Creates a DepositTimeCircuit and generates a proof
    /// 8. Verifies the proof is valid
    #[test]
    fn test_deposit_time_circuit() {
        let lock_config = super::LockTimeConfig::normal();
        let mut rng = rand::thread_rng();

        let pubkey = U256::rand(&mut rng);
        let deposit_salt = Salt::rand(&mut rng);
        let pubkey_salt_hash = get_pubkey_salt_hash(pubkey, deposit_salt);
        let deposit_index = 100;

        let mut deposit_tree = DepositTree::new(DEPOSIT_TREE_HEIGHT);
        let deposit = Deposit {
            depositor: Address::rand(&mut rng),
            pubkey_salt_hash,
            amount: U256::rand(&mut rng),
            token_index: rng.gen(),
            is_eligible: true,
        };

        let prev_block = Block {
            prev_block_hash: Bytes32::rand(&mut rng),
            deposit_tree_root: deposit_tree.get_root(),
            signature_hash: Bytes32::rand(&mut rng),
            timestamp: 0,
            block_number: 1,
        };
        let prev_deposit_merkle_proof = deposit_tree.prove(deposit_index as u64);
        // add random deposits to the tree
        for _ in 0..deposit_index {
            deposit_tree.push(Deposit::rand(&mut rng));
        }
        deposit_tree.push(deposit.clone());
        for _ in 0..deposit_index {
            deposit_tree.push(Deposit::rand(&mut rng));
        }
        let block = Block {
            prev_block_hash: prev_block.hash(),
            deposit_tree_root: deposit_tree.get_root(),
            signature_hash: Bytes32::rand(&mut rng),
            timestamp: 111,
            block_number: 2,
        };
        let deposit_merkle_proof = deposit_tree.prove(deposit_index as u64);

        let value = super::DepositTimeValue::new(
            &lock_config,
            &prev_block,
            &block,
            &prev_deposit_merkle_proof,
            &deposit_merkle_proof,
            &deposit,
            deposit_index,
            deposit_salt,
            pubkey,
        )
        .unwrap();

        let circuit = super::DepositTimeCircuit::<F, C, D>::new(&lock_config);
        let proof = circuit.prove(&value).unwrap();
        circuit.data.verify(proof).unwrap();
    }
}
