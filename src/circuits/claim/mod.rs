pub mod deposit_time;
pub mod determine_lock_time;
pub mod single_claim_processor;
pub mod single_claim_proof;
pub mod utils;

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use crate::{
        circuits::{
            test_utils::state_manager::ValidityStateManager,
            validity::validity_processor::ValidityProcessor,
        },
        common::{
            deposit::{get_pubkey_salt_hash, Deposit},
            salt::Salt,
            signature::key_set::KeySet,
            witness::{claim_witness::ClaimWitness, deposit_time_witness::DepositTimeWitness},
        },
        ethereum_types::{address::Address, u256::U256, u32limb_trait::U32LimbTrait},
        utils::hash_chain::hash_chain_processor::HashChainProcessor,
        wrapper_config::plonky2_config::PoseidonBN128GoldilocksConfig,
    };
    use plonky2::{
        field::goldilocks_field::GoldilocksField, plonk::config::PoseidonGoldilocksConfig,
    };
    use plonky2_bn254::generators::fq::single;
    use rand::Rng as _;

    use super::{determine_lock_time::LOCK_TIME_MAX, single_claim_processor::SingleClaimProcessor};

    type F = GoldilocksField;
    type C = PoseidonGoldilocksConfig;
    type OuterC = PoseidonBN128GoldilocksConfig;
    const D: usize = 2;

    #[test]
    fn test_claim() {
        let mut rng = rand::thread_rng();
        let validity_processor = Arc::new(ValidityProcessor::<F, C, D>::new());
        let mut validity_state_manager = ValidityStateManager::new(validity_processor.clone());
        let single_claim_processor =
            SingleClaimProcessor::new(&validity_processor.get_verifier_data());
        let claim_processor = HashChainProcessor::new(&single_claim_processor.get_verifier_data());

        let key = KeySet::rand(&mut rng);

        // deposit
        let deposit_salt = Salt::rand(&mut rng);
        let deposit_salt_hash = get_pubkey_salt_hash(key.pubkey, deposit_salt);
        let deposit = Deposit {
            depositor: Address::rand(&mut rng),
            pubkey_salt_hash: deposit_salt_hash,
            amount: U256::rand_small(&mut rng),
            token_index: rng.gen(),
            is_eligible: true,
        };
        let deposit_index = validity_state_manager.deposit(&deposit).unwrap();

        // post empty block to sync deposit tree
        validity_state_manager.tick(false, &[], 0).unwrap();

        // lock time max passed in this block
        validity_state_manager
            .tick(false, &[], LOCK_TIME_MAX as u64)
            .unwrap();

        let update_witness = validity_state_manager
            .get_update_witness(key.pubkey, 2, 1, false)
            .unwrap();
        let deposit_time_public_witness = validity_state_manager
            .get_deposit_time_public_witness(2, deposit_index)
            .unwrap();

        let deposit_time_witness = DepositTimeWitness {
            public_witness: deposit_time_public_witness,
            deposit_index,
            deposit,
            deposit_salt,
            pubkey: key.pubkey,
        };
        let recipient = Address::rand(&mut rng);
        let claim_witness = ClaimWitness {
            recipient,
            deposit_time_witness,
            update_witness,
        };
        let single_claim_proof = single_claim_processor.prove(&claim_witness).unwrap();
    }
}
