use std::env;

use intmax2_zkp::{
    circuits::balance::balance_processor::BalanceProcessor,
    common::signature::key_set::KeySet,
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

    // // depost 100wei ETH to alice wallet
    // let deposit_index = alice_wallet.deposit(&mut rng, &mut block_builder, 0, 100.into());

    // // post dummy block to reflect the deposit tree
    // block_builder.post_block(true, vec![]);

    // // sync alice wallet to the latest block, which includes the deposit
    // alice_prover.sync_all(
    //     &mut sync_validity_prover,
    //     &mut alice_wallet,
    //     &balance_processor,
    //     &block_builder,
    // );
    // let balance_pis = alice_prover.get_balance_pis();
    // assert_eq!(balance_pis.public_state.block_number, 1); // balance proof synced to block 1

    // // receive deposit and update alice balance proof
    // alice_prover.receive_deposit(
    //     &mut rng,
    //     &mut alice_wallet,
    //     &balance_processor,
    //     &block_builder,
    //     deposit_index,
    // );
    // assert_eq!(get_asset_balance(&alice_wallet, 0), 100.into()); // check ETH balance

    // let mut bob_wallet = MockWallet::new_rand(&mut rng);
    // let mut bob_prover = SyncBalanceProver::<F, C, D>::new();

    // // transfer 50wei ETH to bob
    // let transfer_to_bob = Transfer {
    //     recipient: GenericAddress::from_pubkey(bob_wallet.get_pubkey()),
    //     token_index: 0,
    //     amount: 50.into(),
    //     salt: Salt::rand(&mut rng),
    // };
    // let send_witness =
    //     alice_wallet.send_tx_and_update(&mut rng, &mut block_builder, &[transfer_to_bob]);
    // let transfer_witness = alice_wallet
    //     .get_transfer_witnesses(send_witness.get_included_block_number())
    //     .unwrap()[0] // first transfer in the tx
    //     .clone();

    // // update alice balance proof
    // alice_prover.sync_all(
    //     &mut sync_validity_prover,
    //     &mut alice_wallet,
    //     &balance_processor,
    //     &block_builder,
    // );
    // assert_eq!(get_asset_balance(&alice_wallet, 0), 50.into()); // check ETH balance
    // let alice_balance_proof = alice_prover.get_balance_proof();

    // // sync bob wallet to the latest block
    // bob_prover.sync_all(
    //     &mut sync_validity_prover,
    //     &mut bob_wallet,
    //     &balance_processor,
    //     &block_builder,
    // );

    // // receive transfer and update bob balance proof
    // bob_prover.receive_transfer(
    //     &mut rng,
    //     &mut bob_wallet,
    //     &balance_processor,
    //     &block_builder,
    //     &transfer_witness,
    //     &alice_balance_proof,
    // );
    // assert_eq!(get_asset_balance(&bob_wallet, 0), 50.into()); // check ETH balance

    // // bob withdraw 10wei ETH
    // let bob_eth_address = Address::rand(&mut rng);
    // let withdrawal = Transfer {
    //     recipient: GenericAddress::from_address(bob_eth_address),
    //     token_index: 0,
    //     amount: 10.into(),
    //     salt: Salt::rand(&mut rng),
    // };
    // let withdrawal_send_witness =
    //     bob_wallet.send_tx_and_update(&mut rng, &mut block_builder, &[withdrawal]);
    // let withdrawal_transfer_witness = bob_wallet
    //     .get_transfer_witnesses(withdrawal_send_witness.get_included_block_number())
    //     .unwrap()[0] // first transfer in the tx
    //     .clone();

    // // update bob balance proof
    // bob_prover.sync_all(
    //     &mut sync_validity_prover,
    //     &mut bob_wallet,
    //     &balance_processor,
    //     &block_builder,
    // );
    // assert_eq!(get_asset_balance(&bob_wallet, 0), 40.into());
    // let bob_balance_proof = bob_prover.get_balance_proof();

    // // prove withdrawal
    // let withdrawal_processor = WithdrawalProcessor::new(&balance_processor.balance_circuit);
    // let withdrawal_witness = WithdrawalWitness {
    //     transfer_witness: withdrawal_transfer_witness,
    //     balance_proof: bob_balance_proof,
    // };
    // let withdrawal = withdrawal_witness.to_withdrawal();
    // assert_eq!(withdrawal.amount, 10.into()); // check withdrawal amount
    // let _withdrawal_proof = withdrawal_processor
    //     .prove(&withdrawal_witness, &None)
    //     .unwrap();
}
