pub mod deposit_time;
pub mod determine_lock_time;
pub mod error;
pub mod single_claim_processor;
pub mod single_claim_proof;
pub mod utils;

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use crate::{
        circuits::{
            claim::determine_lock_time::LockTimeConfig,
            test_utils::state_manager::ValidityStateManager,
            validity::validity_processor::ValidityProcessor,
        },
        common::{
            deposit::{get_pubkey_salt_hash, Deposit},
            salt::Salt,
            signature_content::key_set::KeySet,
            witness::{claim_witness::ClaimWitness, deposit_time_witness::DepositTimeWitness},
        },
        ethereum_types::{
            address::Address, bytes32::Bytes32, u256::U256, u32limb_trait::U32LimbTrait,
        },
        utils::{
            conversion::ToU64 as _,
            hash_chain::{
                chain_end_circuit::ChainEndProofPublicInputs,
                hash_chain_processor::HashChainProcessor, hash_with_prev_hash,
            },
            wrapper::WrapperCircuit,
        },
        wrapper_config::plonky2_config::PoseidonBN128GoldilocksConfig,
    };
    use base64::{prelude::BASE64_STANDARD, Engine};
    use plonky2::{
        field::goldilocks_field::GoldilocksField, plonk::config::PoseidonGoldilocksConfig,
    };
    use rand::Rng as _;

    use super::single_claim_processor::SingleClaimProcessor;

    type F = GoldilocksField;
    type C = PoseidonGoldilocksConfig;
    type OuterC = PoseidonBN128GoldilocksConfig;
    const D: usize = 2;

    #[test]
    fn test_claim() {
        //
        let lock_config = LockTimeConfig::normal();

        let mut rng = rand::thread_rng();
        let validity_processor = Arc::new(ValidityProcessor::<F, C, D>::new());
        let mut validity_state_manager =
            ValidityStateManager::new(validity_processor.clone(), Address::default());
        let single_claim_processor =
            SingleClaimProcessor::new(&validity_processor.get_verifier_data(), &lock_config);
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
        validity_state_manager.tick(false, &[], 0, 0).unwrap();

        // lock time max passed in this block
        validity_state_manager
            .tick(false, &[], 0, lock_config.lock_time_max as u64)
            .unwrap();

        let update_witness = validity_state_manager
            .get_update_witness(key.pubkey, 2, 1, false)
            .unwrap();
        let deposit_time_public_witness = validity_state_manager
            .get_deposit_time_public_witness(1, deposit_index)
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

        let cyclic_claim_proof = claim_processor
            .prove_chain(&single_claim_proof, &None)
            .unwrap();

        let aggregator = Address::default();
        let end_claim_proof = claim_processor
            .prove_end(&cyclic_claim_proof, aggregator)
            .unwrap();

        // public inputs check
        let claim = claim_witness.to_claim();
        let mut hash = Bytes32::default();
        hash = hash_with_prev_hash(&claim.to_u32_vec(), hash);
        let expected_end_withdrawal_pis = ChainEndProofPublicInputs {
            last_hash: hash,
            aggregator,
        };
        let pis_hash = expected_end_withdrawal_pis.hash();
        let pis_hash_vec = pis_hash.to_u64_vec();
        assert_eq!(pis_hash_vec, end_claim_proof.public_inputs.to_u64_vec());

        let inner_wrapper_circuit = WrapperCircuit::<F, C, C, D>::new(
            &claim_processor.chain_end_circuit.data.verifier_data(),
        );
        let final_circuit =
            WrapperCircuit::<F, C, OuterC, D>::new(&inner_wrapper_circuit.data.verifier_data());

        let inner_wrapper_proof = inner_wrapper_circuit.prove(&end_claim_proof).unwrap();
        let final_proof = final_circuit.prove(&inner_wrapper_proof).unwrap();

        println!(
            "Final circuit degree: {}",
            final_circuit.data.common.degree_bits()
        );

        let claim_name = if lock_config == LockTimeConfig::faster() {
            "faster_claim"
        } else {
            "claim"
        };

        // for test data
        let single_claim_proof_bytes = bincode::serialize(&single_claim_proof).unwrap();
        let single_claim_proof_str = BASE64_STANDARD.encode(single_claim_proof_bytes);
        std::fs::write(
            format!(
                "circuit_data/{}/single_{}_proof.txt",
                claim_name, claim_name
            ),
            single_claim_proof_str,
        )
        .unwrap();

        let final_proof_str = serde_json::to_string_pretty(&final_proof).unwrap();
        let final_circuit_vd =
            serde_json::to_string_pretty(&final_circuit.data.verifier_only).unwrap();
        let final_circuit_cd = serde_json::to_string_pretty(&final_circuit.data.common).unwrap();
        // save to files
        std::fs::write(
            format!("circuit_data/{}/proof_with_public_inputs.json", claim_name),
            final_proof_str,
        )
        .unwrap();
        std::fs::write(
            format!(
                "circuit_data/{}/verifier_only_circuit_data.json",
                claim_name
            ),
            final_circuit_vd,
        )
        .unwrap();
        std::fs::write(
            format!("circuit_data/{}/common_circuit_data.json", claim_name),
            final_circuit_cd,
        )
        .unwrap();
    }
}
