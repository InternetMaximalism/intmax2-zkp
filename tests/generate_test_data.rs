use std::{
    fs::{self, File},
    io::Write as _,
    path::Path,
};

use intmax2_zkp::{
    circuits::withdrawal::withdrawal_wrapper_circuit::WithdrawalProofPublicInputs,
    common::{transfer::Transfer, withdrawal::Withdrawal, witness::block_witness::FullBlock},
    ethereum_types::{address::Address, bytes32::Bytes32, u32limb_trait::U32LimbTrait},
    mock::{block_builder::MockBlockBuilder, wallet::MockWallet},
};
use serde::{Deserialize, Serialize};

// Save full blocks to json files, so that they can be used for contract testing
#[test]
fn generate_test_data() {
    let mut rng = rand::thread_rng();
    let mut block_builder = MockBlockBuilder::new();
    let mut wallet = MockWallet::new_rand(&mut rng);

    // post register block
    let transfer0 = Transfer::rand(&mut rng);
    wallet.send_tx_and_update(&mut rng, &mut block_builder, &[transfer0]);
    // post account id block
    let transfer1 = Transfer::rand(&mut rng);
    wallet.send_tx_and_update(&mut rng, &mut block_builder, &[transfer1]);

    let mut full_blocks = vec![];
    for i in 0..3 {
        let full_block = block_builder
            .aux_info
            .get(&i)
            .unwrap()
            .validity_witness
            .block_witness
            .to_full_block();
        full_blocks.push(full_block);
    }
    save_full_blocks("test_data", &full_blocks).unwrap();

    let withdrawal_block = full_blocks.last().unwrap();
    let withdrawals = (0..3)
        .map(|_| Withdrawal::rand_with_block(&mut rng, &withdrawal_block.block))
        .collect::<Vec<_>>();

    let mut withdrawal_hash = Bytes32::default();
    for withdrawal in &withdrawals {
        withdrawal_hash = withdrawal.hash_with_prev_hash(withdrawal_hash);
    }
    let withdrawal_aggregator = Address::rand(&mut rng);
    let pis = WithdrawalProofPublicInputs {
        last_withdrawal_hash: withdrawal_hash,
        withdrawal_aggregator,
    };
    let withdrawal_info = WithdralwalInfo {
        withdrawals,
        withdrawal_proof_public_inputs: pis.clone(),
        pis_hash: pis.hash(),
    };
    save_withdrawal_info("test_data", &withdrawal_info).unwrap();
}

fn save_full_blocks<P: AsRef<Path>>(dir_path: P, full_blocks: &[FullBlock]) -> anyhow::Result<()> {
    if !Path::new(dir_path.as_ref()).exists() {
        fs::create_dir(dir_path.as_ref())?;
    }
    for full_block in full_blocks.iter() {
        let block_bumber = full_block.block.block_number;
        let block_str = serde_json::to_string_pretty(full_block)?;
        let file_path = format!("{}/block{}.json", dir_path.as_ref().display(), block_bumber);
        let mut file = File::create(file_path)?;
        file.write_all(block_str.as_bytes())?;
    }
    Ok(())
}

fn save_withdrawal_info<P: AsRef<Path>>(
    dir_path: P,
    withdrawal_info: &WithdralwalInfo,
) -> anyhow::Result<()> {
    if !Path::new(dir_path.as_ref()).exists() {
        fs::create_dir(dir_path.as_ref())?;
    }
    let withdrawal_info_str = serde_json::to_string_pretty(withdrawal_info)?;
    let file_path = format!("{}/withdrawal_info.json", dir_path.as_ref().display());
    let mut file = File::create(file_path)?;
    file.write_all(withdrawal_info_str.as_bytes())?;
    Ok(())
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct WithdralwalInfo {
    withdrawals: Vec<Withdrawal>,
    withdrawal_proof_public_inputs: WithdrawalProofPublicInputs,
    pis_hash: Bytes32,
}
