use std::{
    fs::{self, File},
    io::Write as _,
    path::Path,
};

use intmax2_zkp::{
    common::{transfer::Transfer, witness::block_witness::FullBlock},
    mock::{block_builder::MockBlockBuilder, wallet::MockWallet},
};

// Save full blocks to json files, so that they can be used for contract testing
#[test]
fn test_save_blocks() {
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

    save_full_blocks("block_data", &full_blocks).unwrap();
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
