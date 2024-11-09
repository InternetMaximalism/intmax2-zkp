use std::env;

use hashbrown::HashMap;
use intmax2_zkp::{
    circuits::balance::balance_processor::BalanceProcessor,
    common::{
        generic_address::GenericAddress, salt::Salt, signature::key_set::KeySet,
        transfer::Transfer, trees::asset_tree::AssetLeaf,
    },
    ethereum_types::{address::Address, u32limb_trait::U32LimbTrait as _},
    mock::{
        block_builder::BlockBuilder, block_validity_prover::BlockValidityProver, client::Client,
        contract::MockContract, store_vault_server::StoreVaultServer,
        withdrawal_aggregator::WithdrawalAggregator,
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
    let mut validity_prover = BlockValidityProver::<F, C, D>::new();
    let balance_processor = BalanceProcessor::new(&validity_prover.validity_vd());
    let mut store_vault_server = StoreVaultServer::<F, C, D>::new();
    let mut block_builder = BlockBuilder::new();
    let client = Client::new(0, 0);

    log::info!("set up done");

    let mut rng = rand::thread_rng();
    let alice_key = KeySet::rand(&mut rng);

    // deposit 100wei ETH to alice wallet
    client
        .deposit(
            alice_key,
            &mut contract,
            &mut store_vault_server,
            0,
            100.into(),
        )
        .unwrap();

    // post empty block to reflect the deposit
    block_builder
        .post_empty_block(&mut contract, &validity_prover)
        .unwrap();

    // sync validity prover to the latest block
    validity_prover.sync(&contract).unwrap();
    log::info!("synced to block {}", validity_prover.block_number());

    // sync alice's balance proof to receive the deposit
    client
        .sync(
            alice_key,
            &mut store_vault_server,
            &validity_prover,
            &balance_processor,
        )
        .unwrap();
    let alice_data = client
        .get_user_data(alice_key, &store_vault_server)
        .unwrap();
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
    send_transfers(
        alice_key,
        &client,
        &mut contract,
        &mut block_builder,
        &mut store_vault_server,
        &validity_prover,
        &balance_processor,
        vec![transfer_to_bob],
    );

    // sync validity prover to the latest block
    validity_prover.sync(&contract).unwrap();
    log::info!("synced to block {}", validity_prover.block_number());

    // sync bob wallet to the latest block
    client
        .sync(
            bob_key,
            &mut store_vault_server,
            &validity_prover,
            &balance_processor,
        )
        .unwrap();
    let bob_data = client.get_user_data(bob_key, &store_vault_server).unwrap();
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
    send_transfers(
        bob_key,
        &client,
        &mut contract,
        &mut block_builder,
        &mut store_vault_server,
        &validity_prover,
        &balance_processor,
        vec![withdrawal],
    );

    // sync validity prover to the latest block
    validity_prover.sync(&contract).unwrap();

    let mut withdrawal_aggregator =
        WithdrawalAggregator::<F, C, D>::new(&balance_processor.get_verifier_data().common);
    // sync bob withdrawals
    client
        .sync_withdrawals(
            bob_key,
            &mut store_vault_server,
            &mut withdrawal_aggregator,
            &validity_prover,
            &balance_processor,
        )
        .unwrap();

    let (withdrawals, _withdrawal_wrap_proof) =
        withdrawal_aggregator.wrap(Address::rand(&mut rng)).unwrap();
    log::info!("withdrawals: {:?}", withdrawals);
}

fn send_transfers(
    sender_key: KeySet,
    client: &Client,
    contract: &mut MockContract,
    block_builder: &mut BlockBuilder,
    store_vault_server: &mut StoreVaultServer<F, C, D>,
    validity_prover: &BlockValidityProver<F, C, D>,
    balance_processor: &BalanceProcessor<F, C, D>,
    transfers: Vec<Transfer>,
) {
    let tx_request_memo = client
        .send_tx_request(
            sender_key,
            block_builder,
            store_vault_server,
            validity_prover,
            balance_processor,
            transfers,
        )
        .unwrap();

    // block builder construct block
    block_builder.construct_block().unwrap();

    // finalize tx
    client
        .finalize_tx(
            sender_key,
            block_builder,
            store_vault_server,
            &tx_request_memo,
        )
        .unwrap();

    // block builder post block
    block_builder
        .post_block(contract, &validity_prover)
        .unwrap();
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
