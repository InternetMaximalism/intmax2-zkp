//! Lock time determination circuit for deposit claims.
//!
//! This circuit calculates a random lock time for deposits based on:
//! 1. The block hash of the block where the deposit was first included
//! 2. The deposit salt used to hide the public key in the deposit
//!
//! The lock time is determined by the formula:
//! lock_time = lock_time_min + (seed % lock_time_delta)
//! where seed = PoseidonHash(block_hash, deposit_salt)
//!
//! This randomization mechanism ensures that:
//! - Lock times cannot be precisely predicted or manipulated by users
//! - The block hash depends on the deposit tree root, which depends on all deposit salts
//! - Manipulating the deposit salt to target a specific lock time is impractical
//!
//! Two configurations are provided:
//! - "normal" for mainnet (2-5 days)
//! - "faster" for testnet environments (2-5 minutes)

use num::BigUint;
use plonky2::{
    field::{extension::Extendable, types::Field},
    hash::hash_types::RichField,
    iop::{target::Target, witness::WitnessWrite},
    plonk::circuit_builder::CircuitBuilder,
};
use plonky2_bn254::fields::biguint::{BigUintTarget, CircuitBuilderBiguint};

use crate::{
    common::salt::{Salt, SaltTarget},
    ethereum_types::{
        bytes32::{Bytes32, Bytes32Target},
        u256::{U256Target, U256},
        u32limb_trait::{U32LimbTargetTrait, U32LimbTrait},
    },
    utils::poseidon_hash_out::{PoseidonHashOut, PoseidonHashOutTarget},
};

/// Configuration for lock time calculation
///
/// Defines the minimum and maximum lock time values that will be used
/// to determine the random lock time range for deposits.
#[derive(Debug, Clone, PartialEq)]
pub struct LockTimeConfig {
    pub lock_time_min: u32, // Minimum lock time in seconds
    pub lock_time_max: u32, // Maximum lock time in seconds
}

impl LockTimeConfig {
    /// Creates a normal lock time configuration for mainnet
    ///
    /// Returns a configuration with:
    /// - Minimum lock time: 2 days (172800 seconds)
    /// - Maximum lock time: 5 days (432000 seconds)
    pub fn normal() -> Self {
        LockTimeConfig {
            lock_time_min: 172800,
            lock_time_max: 432000,
        }
    }

    /// Creates a faster lock time configuration for testnet environments
    ///
    /// Returns a configuration with:
    /// - Minimum lock time: 2 minutes (120 seconds)
    /// - Maximum lock time: 5 minutes (300 seconds)
    pub fn faster() -> Self {
        LockTimeConfig {
            lock_time_min: 120,
            lock_time_max: 300,
        }
    }

    /// Calculates the difference between maximum and minimum lock times
    ///
    /// This value is used as the modulus for the random seed to determine
    /// how much additional time beyond the minimum will be required.
    pub fn lock_time_delta(&self) -> u32 {
        self.lock_time_max - self.lock_time_min
    }
}

/// Values needed to determine the lock time for a deposit
///
/// Contains the inputs (block hash and deposit salt) and the calculated
/// lock time for a deposit based on the formula:
/// lock_time = lock_time_min + (seed % lock_time_delta)
/// where seed = PoseidonHash(block_hash, deposit_salt)
pub struct DetermineLockTimeValue {
    pub block_hash: Bytes32, // Hash of the block containing the deposit
    pub deposit_salt: Salt,  // Salt used to hide the public key in the deposit
    pub lock_time: u32,      // Calculated lock time in seconds
}

impl DetermineLockTimeValue {
    /// Creates a new DetermineLockTimeValue by calculating the lock time
    /// based on the block hash and deposit salt.
    ///
    /// The lock time is calculated using the formula:
    /// lock_time = lock_time_min + (seed % lock_time_delta)
    /// where seed = PoseidonHash(block_hash, deposit_salt)
    ///
    /// # Arguments
    /// * `config` - Configuration for lock time calculation
    /// * `block_hash` - Hash of the block containing the deposit
    /// * `deposit_salt` - Salt used to hide the public key in the deposit
    ///
    /// # Returns
    /// A new DetermineLockTimeValue with the calculated lock time
    pub fn new(config: &LockTimeConfig, block_hash: Bytes32, deposit_salt: Salt) -> Self {
        // Concatenate block hash and deposit salt as inputs for the hash function
        let inputs = [block_hash.to_u64_vec(), deposit_salt.to_u64_vec()].concat();

        // Generate a random seed using Poseidon hash
        let seed: BigUint = BigUint::from(U256::from(Bytes32::from(
            PoseidonHashOut::hash_inputs_u64(&inputs),
        )));

        // Calculate the modulus to get a value within the lock time range
        let delta = BigUint::from(config.lock_time_delta());
        let delta_r = seed % delta;
        let delta_r_u32 = delta_r.to_u32_digits().first().cloned().unwrap_or(0);

        // Calculate the final lock time
        let lock_time = config.lock_time_min + delta_r_u32;

        DetermineLockTimeValue {
            block_hash,
            deposit_salt,
            lock_time,
        }
    }
}

/// Target version of DetermineLockTimeValue for use in ZKP circuits
///
/// Contains circuit targets for the inputs (block hash and deposit salt)
/// and the calculated lock time for a deposit.
#[derive(Debug, Clone)]
pub struct DetermineLockTimeTarget {
    pub block_hash: Bytes32Target, // Target for block hash
    pub deposit_salt: SaltTarget,  // Target for deposit salt
    pub lock_time: Target,         // Target for calculated lock time
}

impl DetermineLockTimeTarget {
    /// Creates a new DetermineLockTimeTarget with circuit constraints that enforce
    /// the lock time calculation formula.
    ///
    /// The circuit implements the formula:
    /// lock_time = lock_time_min + (seed % lock_time_delta)
    /// where seed = PoseidonHash(block_hash, deposit_salt)
    ///
    /// # Arguments
    /// * `builder` - Circuit builder
    /// * `is_checked` - Whether to add constraints for checking the values
    /// * `config` - Configuration for lock time calculation
    ///
    /// # Returns
    /// A new DetermineLockTimeTarget with all necessary targets and constraints
    pub fn new<F: RichField + Extendable<D>, const D: usize>(
        builder: &mut CircuitBuilder<F, D>,
        is_checked: bool,
        config: &LockTimeConfig,
    ) -> Self {
        // Create targets for inputs
        let block_hash = Bytes32Target::new(builder, is_checked);
        let deposit_salt = SaltTarget::new(builder);

        // Concatenate inputs for hashing
        let inputs = [block_hash.to_vec(), deposit_salt.to_vec()].concat();

        // Generate a random seed using Poseidon hash
        let seed_poseidon = PoseidonHashOutTarget::hash_inputs(builder, &inputs);
        let seed_bytes32 = Bytes32Target::from_hash_out(builder, seed_poseidon);
        let seed_u256 = U256Target::from_slice(seed_bytes32.to_vec().as_slice());
        let seed_biguint = BigUintTarget::from(seed_u256);

        // Calculate the modulus to get a value within the lock time range
        let delta = BigUint::from(config.lock_time_delta());
        let (_, delta_r) = builder.div_rem_biguint(&seed_biguint, &delta);

        // Calculate the final lock time
        let lock_time_min = builder.constant_biguint(&BigUint::from(config.lock_time_min));
        let lock_time_biguint = builder.add_biguint(&lock_time_min, &delta_r);
        let lock_time = lock_time_biguint.limbs[0].0;

        Self {
            block_hash,
            deposit_salt,
            lock_time,
        }
    }

    /// Sets the witness values for the DetermineLockTimeTarget
    ///
    /// # Arguments
    /// * `witness` - Witness to write values to
    /// * `value` - DetermineLockTimeValue containing the values to set
    pub fn set_witness<W: WitnessWrite<F>, F: Field>(
        &self,
        witness: &mut W,
        value: &DetermineLockTimeValue,
    ) {
        self.block_hash.set_witness(witness, value.block_hash);
        self.deposit_salt.set_witness(witness, value.deposit_salt);
        witness.set_target(self.lock_time, F::from_canonical_u32(value.lock_time));
    }
}

/// Helper function to calculate the lock time for a deposit
///
/// # Arguments
/// * `config` - Configuration for lock time calculation
/// * `block_hash` - Hash of the block containing the deposit
/// * `deposit_salt` - Salt used to hide the public key in the deposit
///
/// # Returns
/// The calculated lock time in seconds as a u64
pub fn get_lock_time(config: &LockTimeConfig, block_hash: Bytes32, deposit_salt: Salt) -> u64 {
    let value = DetermineLockTimeValue::new(config, block_hash, deposit_salt);
    value.lock_time as u64
}

#[cfg(test)]
mod tests {
    use plonky2::{
        field::goldilocks_field::GoldilocksField,
        iop::witness::PartialWitness,
        plonk::{
            circuit_builder::CircuitBuilder, circuit_data::CircuitConfig,
            config::PoseidonGoldilocksConfig,
        },
    };

    use crate::{
        common::salt::Salt,
        ethereum_types::{bytes32::Bytes32, u32limb_trait::U32LimbTrait},
    };

    use super::DetermineLockTimeTarget;

    type F = GoldilocksField;
    type C = PoseidonGoldilocksConfig;
    const D: usize = 2;

    /// Tests the lock time determination circuit by:
    /// 1. Creating a random block hash and deposit salt
    /// 2. Calculating the lock time using DetermineLockTimeValue
    /// 3. Verifying the lock time is within the expected range
    /// 4. Building a circuit with DetermineLockTimeTarget
    /// 5. Generating and verifying a proof
    #[test]
    fn test_determine_lock_time() {
        let config = super::LockTimeConfig::normal();
        let mut rng = rand::thread_rng();
        let block_hash = Bytes32::rand(&mut rng);
        let deposit_salt = Salt::rand(&mut rng);
        let value = super::DetermineLockTimeValue::new(&config, block_hash, deposit_salt);

        // Verify the lock time is within the expected range
        assert!(value.lock_time >= config.lock_time_min && value.lock_time <= config.lock_time_max);

        // Build and test the circuit
        let mut builder = CircuitBuilder::new(CircuitConfig::default());
        let target = DetermineLockTimeTarget::new::<F, D>(&mut builder, true, &config);
        let data = builder.build::<C>();

        let mut pw = PartialWitness::new();
        target.set_witness(&mut pw, &value);
        let proof = data.prove(pw).unwrap();
        assert!(data.verify(proof).is_ok());
    }
}
