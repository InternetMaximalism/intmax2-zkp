use std::env;

use hashbrown::HashMap;
use intmax2_zkp::{
    circuits::{
        balance::balance_processor::BalanceProcessor,
        withdrawal::withdrawal_processor::WithdrawalProcessor,
    },
    common::{
        generic_address::GenericAddress, salt::Salt, signature::key_set::KeySet,
        transfer::Transfer, trees::asset_tree::AssetLeaf,
    },
    ethereum_types::{address::Address, u32limb_trait::U32LimbTrait as _},
    mock::{
        block_builder::BlockBuilder, client::Client, contract::MockContract,
        data_store_server::DataStoreServer, sync_validity_prover::SyncValidityProver,
    },
};
use plonky2::{field::goldilocks_field::GoldilocksField, plonk::config::PoseidonGoldilocksConfig};

type F = GoldilocksField;
type C = PoseidonGoldilocksConfig;
const D: usize = 2;

#[test]
fn e2e_test() {
    env::set_var("RUST_LOG", "info");
    env_logger::init();

    let mut contract = MockContract::new();
    let mut validity_prover = SyncValidityProver::<F, C, D>::new();
    let balance_processor = BalanceProcessor::new(validity_prover.validity_circuit());
    let mut data_store_server = DataStoreServer::<F, C, D>::new();
    let withdrawal_processor = WithdrawalProcessor::new(&balance_processor.balance_circuit);
    let block_builder = BlockBuilder;
    let client = Client;

    log::info!("set up done");

    let mut rng = rand::thread_rng();
    let alice_key = KeySet::rand(&mut rng);

    // deposit 100wei ETH to alice wallet
    client
        .deposit(
            alice_key,
            &mut contract,
            &mut data_store_server,
            0,
            100.into(),
        )
        .unwrap();

    // post empty block to reflect the deposit
    block_builder
        .post_block(&mut contract, &validity_prover, false, vec![])
        .unwrap();

    // sync validity prover to the latest block
    validity_prover.sync(&contract).unwrap();
    log::info!("synced to block {}", validity_prover.block_number());

    // sync alice's balance proof to receive the deposit
    client
        .sync_balance_proof(
            alice_key,
            &mut data_store_server,
            &validity_prover,
            &balance_processor,
        )
        .unwrap();
    let alice_data = client.get_user_data(alice_key, &data_store_server).unwrap();
    log::info!(
        "Synced alice balance proof to block {}",
        alice_data.block_number
    );
    print_balances(&alice_data.balances());

    let bob_key = KeySet::rand(&mut rng);

    // transfer 50wei ETH to bob
    let transfer_to_bob = Transfer {
        recipient: GenericAddress::from_pubkey(bob_key.pubkey),
        token_index: 0,
        amount: 50.into(),
        salt: Salt::rand(&mut rng),
    };
    client
        .send_tx(
            alice_key,
            &mut contract,
            &block_builder,
            &mut data_store_server,
            &validity_prover,
            &balance_processor,
            vec![transfer_to_bob],
        )
        .unwrap();

    // sync validity prover to the latest block
    validity_prover.sync(&contract).unwrap();
    log::info!("synced to block {}", validity_prover.block_number());

    // sync bob wallet to the latest block
    client
        .sync_balance_proof(
            bob_key,
            &mut data_store_server,
            &validity_prover,
            &balance_processor,
        )
        .unwrap();
    let bob_data = client.get_user_data(bob_key, &data_store_server).unwrap();
    log::info!(
        "Synced bob balance proof to block {}",
        bob_data.block_number
    );
    print_balances(&bob_data.balances());

    // bob withdraw 10wei ETH
    let bob_eth_address = Address::rand(&mut rng);
    let withdrawal = Transfer {
        recipient: GenericAddress::from_address(bob_eth_address),
        token_index: 0,
        amount: 10.into(),
        salt: Salt::rand(&mut rng),
    };
    client
        .send_tx(
            bob_key,
            &mut contract,
            &block_builder,
            &mut data_store_server,
            &validity_prover,
            &balance_processor,
            vec![withdrawal],
        )
        .unwrap();

    // sync validity prover to the latest block
    validity_prover.sync(&contract).unwrap();

    // sync bob withdrawals
    client
        .sync_withdrawals(
            bob_key,
            &mut data_store_server,
            &validity_prover,
            &balance_processor,
            &withdrawal_processor,
        )
        .unwrap();
    // let bob_data = client.get_user_data(bob_key, &data_store_server).unwrap();
    // log::info!(
    //     "Synced bob balance proof to block {}",
    //     bob_data.block_number
    // );
}

fn print_balances(balances: &HashMap<usize, AssetLeaf>) {
    for (token_index, asset_leaf) in balances {
        if asset_leaf.is_insufficient {
            continue;
        }
        println!(
            "token index; {}, balance: {}",
            token_index, asset_leaf.amount
        );
    }
}
