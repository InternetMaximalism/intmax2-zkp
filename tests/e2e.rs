use num::BigUint;
use plonky2::{
    field::goldilocks_field::GoldilocksField,
    plonk::{config::PoseidonGoldilocksConfig, proof::ProofWithPublicInputs},
};
use std::sync::Arc;

use intmax2_zkp::{
    circuits::{
        balance::{
            balance_pis::BalancePublicInputs, balance_processor::BalanceProcessor,
            receive::receive_targets::transfer_inclusion::TransferInclusionValue,
        },
        test_utils::{
            state_manager::ValidityStateManager,
            witness_generator::{construct_spent_and_transfer_witness, MockTxRequest},
        },
        validity::validity_processor::ValidityProcessor,
        withdrawal::single_withdrawal_circuit::SingleWithdrawalCircuit,
    },
    common::{
        deposit::{get_pubkey_salt_hash, Deposit},
        private_state::FullPrivateState,
        salt::Salt,
        signature_content::key_set::KeySet,
        transfer::Transfer,
        witness::{
            deposit_witness::DepositWitness, private_transition_witness::PrivateTransitionWitness,
            receive_deposit_witness::ReceiveDepositWitness,
            receive_transfer_witness::ReceiveTransferWitness,
        },
    },
    ethereum_types::{address::Address, u256::U256, u32limb_trait::U32LimbTrait},
    utils::hash_chain::hash_chain_processor::HashChainProcessor,
};

type F = GoldilocksField;
type C = PoseidonGoldilocksConfig;
const D: usize = 2;

#[test]
fn test_e2e() {
    let mut rng = rand::thread_rng();
    let validity_processor = Arc::new(ValidityProcessor::<F, C, D>::new());
    let balance_processor = BalanceProcessor::new(&validity_processor.get_verifier_data());
    let mut validity_state_manager =
        ValidityStateManager::new(validity_processor.clone(), Address::default());
    let validity_vd = validity_processor.get_verifier_data();
    let balance_vd = balance_processor.get_verifier_data();

    let single_withdrawal_circuit = SingleWithdrawalCircuit::<F, C, D>::new(&balance_vd);
    let hash_chain_processor =
        HashChainProcessor::new(&single_withdrawal_circuit.data.verifier_data());

    let alice_key = KeySet::rand(&mut rng);
    let mut alice_private_state = FullPrivateState::new();
    let mut alice_balance_proof = None;

    let bob_key = KeySet::rand(&mut rng);
    let mut bob_private_state = FullPrivateState::new();
    let mut bob_balance_proof = None;

    // alice deposits 1 ETH
    let deposit_salt = Salt::rand(&mut rng);
    let deposit = Deposit {
        depositor: Address::rand(&mut rng),
        pubkey_salt_hash: get_pubkey_salt_hash(alice_key.pubkey, deposit_salt),
        amount: BigUint::from(10u32).pow(18).try_into().unwrap(),
        token_index: 0, // 0 is ETH
        is_eligible: true,
    };
    let deposit_index = validity_state_manager.deposit(&deposit).unwrap();

    // post empty block to sync the deposit tree
    validity_state_manager.tick(false, &[], 0, 0).unwrap();
    let receive_deposit_block_number = validity_state_manager.get_block_number();

    // update the public state to receive_deposit_block_number
    let alice_pis = get_balance_pis(alice_key.pubkey, &alice_balance_proof);
    let update_witness = validity_state_manager
        .get_update_witness(
            alice_key.pubkey,
            receive_deposit_block_number,
            alice_pis.public_state.block_number,
            false,
        )
        .unwrap();
    alice_balance_proof = Some(
        balance_processor
            .prove_update(
                &validity_vd,
                alice_key.pubkey,
                &update_witness,
                &alice_balance_proof,
            )
            .unwrap(),
    );

    // alice incorporates the deposit
    let alice_pis = get_balance_pis(alice_key.pubkey, &alice_balance_proof);
    let deposit_merkle_proof = validity_state_manager
        .get_deposit_merkle_proof(alice_pis.public_state.block_number, deposit_index)
        .unwrap();
    let deposit_witness = DepositWitness {
        deposit_salt,
        deposit_index,
        deposit: deposit.clone(),
        deposit_merkle_proof,
    };
    let private_transition_witness = PrivateTransitionWitness::from_deposit(
        &mut alice_private_state,
        &deposit,
        Salt::rand(&mut rng),
    )
    .unwrap();
    let receive_deposit_witness = ReceiveDepositWitness {
        deposit_witness,
        private_transition_witness,
    };
    alice_balance_proof = Some(
        balance_processor
            .prove_receive_deposit(
                alice_key.pubkey,
                &receive_deposit_witness,
                &alice_balance_proof,
            )
            .unwrap(),
    );

    // alice send 0.5 ETH to bob
    let transfer = Transfer {
        recipient: bob_key.pubkey.into(),
        token_index: 0,
        amount: BigUint::from(5u32).pow(17).try_into().unwrap(),
        salt: Salt::rand(&mut rng),
    };
    let (spent_witness, transfer_witnesses) =
        construct_spent_and_transfer_witness(&mut alice_private_state, &[transfer]).unwrap();
    let transfer_witness = transfer_witnesses[0].clone();
    let spent_proof = balance_processor.prove_spent(&spent_witness).unwrap();
    let tx_request = MockTxRequest {
        tx: spent_witness.tx,
        sender_key: alice_key,
        will_return_sig: true,
    };
    let tx_witnesses = validity_state_manager
        .tick(
            true, // since it's the first time to send a tx for alice, we use a registration block
            &[tx_request],
            0,
            0,
        )
        .unwrap();
    let tx_witness = tx_witnesses[0].clone();
    let transfer_block_number = validity_state_manager.get_block_number();

    // update alice's public state to transfer_block_number
    let alice_pis = get_balance_pis(alice_key.pubkey, &alice_balance_proof);
    let update_witness = validity_state_manager
        .get_update_witness(
            alice_key.pubkey,
            transfer_block_number,
            alice_pis.public_state.block_number,
            true,
        )
        .unwrap();
    alice_balance_proof = Some(
        balance_processor
            .prove_send(
                &validity_vd,
                alice_key.pubkey,
                &tx_witness,
                &update_witness,
                &spent_proof,
                &alice_balance_proof,
            )
            .unwrap(),
    );

    // bob update his public state to transfer_block_number
    let bob_pis = get_balance_pis(bob_key.pubkey, &bob_balance_proof);
    let update_witness = validity_state_manager
        .get_update_witness(
            bob_key.pubkey,
            transfer_block_number,
            bob_pis.public_state.block_number,
            false,
        )
        .unwrap();
    bob_balance_proof = Some(
        balance_processor
            .prove_update(
                &validity_vd,
                bob_key.pubkey,
                &update_witness,
                &bob_balance_proof,
            )
            .unwrap(),
    );

    // bob receives the transfer
    let private_transition_witness = PrivateTransitionWitness::from_transfer(
        &mut bob_private_state,
        transfer,
        Salt::rand(&mut rng),
    )
    .unwrap();
    let block_merkle_proof = validity_state_manager
        .get_block_merkle_proof(transfer_block_number, transfer_block_number)
        .unwrap();
    let receive_transfer_witness = ReceiveTransferWitness {
        transfer_witness,
        private_transition_witness,
        sender_balance_proof: alice_balance_proof.clone().unwrap(),
        block_merkle_proof,
    };
    let _bob_balance_proof = Some(
        balance_processor
            .prove_receive_transfer(
                bob_key.pubkey,
                &receive_transfer_witness,
                &bob_balance_proof,
            )
            .unwrap(),
    );

    // alice send withdrawal transfer of 0.1 ETH
    let withdrawal_transfer = Transfer {
        recipient: Address::rand(&mut rng).into(),
        token_index: 0,
        amount: BigUint::from(1u32).pow(17).try_into().unwrap(),
        salt: Salt::rand(&mut rng),
    };
    let (spent_witness, transfer_witnesses) =
        construct_spent_and_transfer_witness(&mut alice_private_state, &[withdrawal_transfer])
            .unwrap();
    let transfer_witness = transfer_witnesses[0].clone();
    let spent_proof = balance_processor.prove_spent(&spent_witness).unwrap();
    let tx_request = MockTxRequest {
        tx: spent_witness.tx,
        sender_key: alice_key,
        will_return_sig: true,
    };
    let tx_witnesses = validity_state_manager
        .tick(
            false, /* since it's the second time to send a tx for alice, we use a non
                    * registration block */
            &[tx_request],
            0,
            0,
        )
        .unwrap();
    let tx_witness = tx_witnesses[0].clone();
    let withdrawal_block_number = validity_state_manager.get_block_number();

    // update alice's public state to withdrawal_block_number
    let alice_pis = get_balance_pis(alice_key.pubkey, &alice_balance_proof);
    let update_witness = validity_state_manager
        .get_update_witness(
            alice_key.pubkey,
            withdrawal_block_number,
            alice_pis.public_state.block_number,
            true,
        )
        .unwrap();
    alice_balance_proof = Some(
        balance_processor
            .prove_send(
                &validity_vd,
                alice_key.pubkey,
                &tx_witness,
                &update_witness,
                &spent_proof,
                &alice_balance_proof,
            )
            .unwrap(),
    );

    // alice generates a single withdrawal proof
    let transfer_inclusion_value = TransferInclusionValue::new(
        &balance_vd,
        &transfer_witness.transfer,
        transfer_witness.transfer_index,
        &transfer_witness.transfer_merkle_proof,
        &transfer_witness.tx,
        &alice_balance_proof.unwrap(),
    )
    .unwrap();
    let single_withdrawal_proof = single_withdrawal_circuit
        .prove(&transfer_inclusion_value)
        .unwrap();

    // generate a withdrawal chain
    let chain_withdrawal_proof = hash_chain_processor
        .prove_chain(&single_withdrawal_proof, &None)
        .unwrap();
    let end_withdrawal_proof = hash_chain_processor
        .prove_end(&chain_withdrawal_proof, Address::rand(&mut rng))
        .unwrap();
    hash_chain_processor
        .chain_end_circuit
        .data
        .verify(end_withdrawal_proof)
        .unwrap();
}

fn get_balance_pis(
    pubkey: U256,
    proof: &Option<ProofWithPublicInputs<F, C, D>>,
) -> BalancePublicInputs {
    proof
        .as_ref()
        .map(|p| BalancePublicInputs::from_pis(&p.public_inputs).unwrap())
        .unwrap_or(BalancePublicInputs::new(pubkey))
}
