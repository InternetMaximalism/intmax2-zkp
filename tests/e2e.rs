use intmax2_zkp::{
    circuits::{
        balance::balance_processor::BalanceProcessor,
        withdrawal::{
            withdrawal_processor::WithdrawalProcessor,
            withdrawal_wrapper_processor::WithdrawalWrapperProcessor,
        },
    },
    common::{
        generic_address::GenericAddress, salt::Salt, transfer::Transfer,
        witness::withdrawal_witness::WithdrawalWitness,
    },
    ethereum_types::{address::Address, bytes32::Bytes32, u256::U256, u32limb_trait::U32LimbTrait},
    mock::{
        block_builder::MockBlockBuilder, sync_balance_prover::SyncBalanceProver,
        sync_validity_prover::SyncValidityProver, wallet::MockWallet,
    },
};
use plonky2::{field::goldilocks_field::GoldilocksField, plonk::config::PoseidonGoldilocksConfig};

type F = GoldilocksField;
type C = PoseidonGoldilocksConfig;
const D: usize = 2;

#[test]
fn e2e_test() {
    let mut rng = rand::thread_rng();
    let mut block_builder = MockBlockBuilder::new();
    let mut sync_validity_prover = SyncValidityProver::<F, C, D>::new();
    let balance_processor = BalanceProcessor::new(sync_validity_prover.validity_circuit());

    let mut alice_wallet = MockWallet::new_rand(&mut rng);
    let mut alice_prover = SyncBalanceProver::<F, C, D>::new();

    // depost 100wei ETH to alice wallet
    let deposit_index = alice_wallet.deposit(&mut rng, &mut block_builder, 0, 100.into());

    // post dummy block to reflect the deposit tree
    block_builder.post_random_block(&mut rng);

    // sync alice wallet to the latest block, which includes the deposit
    alice_prover.sync_all(
        &mut sync_validity_prover,
        &mut alice_wallet,
        &balance_processor,
        &block_builder,
    );
    let balance_pis = alice_prover.get_balance_pis();
    assert_eq!(balance_pis.public_state.block_number, 1); // balance proof synced to block 1

    // receive deposit and update alice balance proof
    alice_prover.receive_deposit(
        &mut rng,
        &mut alice_wallet,
        &balance_processor,
        &block_builder,
        deposit_index,
    );
    assert_eq!(get_asset_balance(&alice_wallet, 0), 100.into()); // check ETH balance

    let mut bob_wallet = MockWallet::new_rand(&mut rng);
    let mut bob_prover = SyncBalanceProver::<F, C, D>::new();

    // transfer 50wei ETH to bob
    let transfer_to_bob = Transfer {
        recipient: GenericAddress::from_pubkey(bob_wallet.get_pubkey()),
        token_index: 0,
        amount: 50.into(),
        salt: Salt::rand(&mut rng),
    };
    let send_witness =
        alice_wallet.send_tx_and_update(&mut rng, &mut block_builder, &[transfer_to_bob]);
    let transfer_witness = alice_wallet
        .get_transfer_witnesses(send_witness.get_included_block_number())
        .unwrap()[0] // first transfer in the tx
        .clone();

    // update alice balance proof
    alice_prover.sync_all(
        &mut sync_validity_prover,
        &mut alice_wallet,
        &balance_processor,
        &block_builder,
    );
    assert_eq!(get_asset_balance(&alice_wallet, 0), 50.into()); // check ETH balance
    let alice_balance_proof = alice_prover.get_balance_proof();

    // sync bob wallet to the latest block
    bob_prover.sync_all(
        &mut sync_validity_prover,
        &mut bob_wallet,
        &balance_processor,
        &block_builder,
    );

    // receive transfer and update bob balance proof
    bob_prover.receive_transfer(
        &mut rng,
        &mut bob_wallet,
        &balance_processor,
        &block_builder,
        &transfer_witness,
        &alice_balance_proof,
    );
    assert_eq!(get_asset_balance(&bob_wallet, 0), 50.into()); // check ETH balance

    // bob withdraw 10wei ETH
    let bob_eth_address = Address::rand(&mut rng);
    let withdrawal = Transfer {
        recipient: GenericAddress::from_address(bob_eth_address),
        token_index: 0,
        amount: 10.into(),
        salt: Salt::rand(&mut rng),
    };
    let withdrawal_send_witness =
        bob_wallet.send_tx_and_update(&mut rng, &mut block_builder, &[withdrawal]);
    let withdrawal_transfer_witness = bob_wallet
        .get_transfer_witnesses(withdrawal_send_witness.get_included_block_number())
        .unwrap()[0] // first transfer in the tx
        .clone();

    // update bob balance proof
    bob_prover.sync_all(
        &mut sync_validity_prover,
        &mut bob_wallet,
        &balance_processor,
        &block_builder,
    );
    assert_eq!(get_asset_balance(&bob_wallet, 0), 40.into());
    let bob_balance_proof = bob_prover.get_balance_proof();

    // prove withdrawal
    let withdrawal_processor = WithdrawalProcessor::new(&balance_processor.balance_circuit);
    let withdrawal_witness = WithdrawalWitness {
        transfer_witness: withdrawal_transfer_witness,
        balance_proof: bob_balance_proof,
    };
    let withdrawal = withdrawal_witness.to_withdrawal(Bytes32::default());
    assert_eq!(withdrawal.amount, 10.into()); // check withdrawal amount
    let withdrawal_proof = withdrawal_processor
        .prove(&withdrawal_witness, &None)
        .unwrap();
    let withdrawal_wrapper_processor =
        WithdrawalWrapperProcessor::new(&withdrawal_processor.withdrawal_circuit);
    let withdrawal_aggregator = Address::rand(&mut rng);
    let _final_withdrawal_proof = withdrawal_wrapper_processor
        .prove(&withdrawal_proof, withdrawal_aggregator)
        .unwrap();
}

fn get_asset_balance(wallet: &MockWallet, token_index: u32) -> U256 {
    let private_state = wallet.get_private_state();
    assert_eq!(
        private_state.asset_tree_root,
        wallet.asset_tree.get_root(),
        "asset tree root mismatch"
    );
    let asset_leaf = wallet.asset_tree.get_leaf(token_index as usize);
    assert!(!asset_leaf.is_insufficient, "insufficient asset balance");
    asset_leaf.amount
}
