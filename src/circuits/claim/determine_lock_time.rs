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

#[derive(Debug, Clone, PartialEq)]
pub struct LockTimeConfig {
    pub lock_time_min: u32,
    pub lock_time_max: u32,
}

impl LockTimeConfig {
    pub fn normal() -> Self {
        LockTimeConfig {
            lock_time_min: 172800, // 2 days
            lock_time_max: 432000, // 5 days
        }
    }

    pub fn faster() -> Self {
        LockTimeConfig {
            lock_time_min: 120, // 2 minutes
            lock_time_max: 300, // 5 minutes
        }
    }

    pub fn lock_time_delta(&self) -> u32 {
        self.lock_time_max - self.lock_time_min
    }
}

// lock time is determined by the following formula:
// lock_time = lock_time_min + (seed % lock_time_max),
// where seed = PoseidonHash(block_hash, deposit_salt)
pub struct DetermineLockTimeValue {
    pub block_hash: Bytes32,
    pub deposit_salt: Salt,
    pub lock_time: u32,
}

impl DetermineLockTimeValue {
    pub fn new(config: &LockTimeConfig, block_hash: Bytes32, deposit_salt: Salt) -> Self {
        let inputs = [block_hash.to_u64_vec(), deposit_salt.to_u64_vec()].concat();
        let seed: BigUint = BigUint::from(U256::from(Bytes32::from(
            PoseidonHashOut::hash_inputs_u64(&inputs),
        )));
        let delta = BigUint::from(config.lock_time_max);
        let delta_r = seed % delta;
        let delta_r_u32 = delta_r.to_u32_digits().first().cloned().unwrap_or(0);
        let lock_time = config.lock_time_min + delta_r_u32;
        DetermineLockTimeValue {
            block_hash,
            deposit_salt,
            lock_time,
        }
    }
}

#[derive(Debug, Clone)]
pub struct DetermineLockTimeTarget {
    pub block_hash: Bytes32Target,
    pub deposit_salt: SaltTarget,
    pub lock_time: Target,
}

impl DetermineLockTimeTarget {
    pub fn new<F: RichField + Extendable<D>, const D: usize>(
        builder: &mut CircuitBuilder<F, D>,
        is_checked: bool,
        config: &LockTimeConfig,
    ) -> Self {
        let block_hash = Bytes32Target::new(builder, is_checked);
        let deposit_salt = SaltTarget::new(builder);

        let inputs = [block_hash.to_vec(), deposit_salt.to_vec()].concat();
        let seed_poseidon = PoseidonHashOutTarget::hash_inputs(builder, &inputs);
        let seed_bytes32 = Bytes32Target::from_hash_out(builder, seed_poseidon);
        let seed_u256 = U256Target::from_slice(seed_bytes32.to_vec().as_slice());
        let seed_biguint = BigUintTarget::from(seed_u256);

        let delta = BigUint::from(config.lock_time_max);
        let (_, delta_r) = builder.div_rem_biguint(&seed_biguint, &delta);

        let lock_time_min = builder.constant_biguint(&BigUint::from(config.lock_time_min));
        let lock_time_biguint = builder.add_biguint(&lock_time_min, &delta_r);
        let lock_time = lock_time_biguint.limbs[0].0;
        Self {
            block_hash,
            deposit_salt,
            lock_time,
        }
    }

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

    #[test]
    fn test_determine_lock_time() {
        let config = super::LockTimeConfig::normal();
        let mut rng = rand::thread_rng();
        let block_hash = Bytes32::rand(&mut rng);
        let deposit_salt = Salt::rand(&mut rng);
        let value = super::DetermineLockTimeValue::new(&config, block_hash, deposit_salt);

        assert!(value.lock_time >= config.lock_time_min && value.lock_time <= config.lock_time_max);

        let mut builder = CircuitBuilder::new(CircuitConfig::default());
        let target = DetermineLockTimeTarget::new::<F, D>(&mut builder, true, &config);
        let data = builder.build::<C>();

        let mut pw = PartialWitness::new();
        target.set_witness(&mut pw, &value);
        let proof = data.prove(pw).unwrap();
        assert!(data.verify(proof).is_ok());
    }
}
