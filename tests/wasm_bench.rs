use intmax2_zkp::{
    circuits::{
        balance::balance_processor::BalanceProcessor,
        claim::{
            determine_lock_time::LockTimeConfig, single_claim_processor::SingleClaimProcessor,
        },
        withdrawal::single_withdrawal_circuit::SingleWithdrawalCircuit,
    },
    types::{
        ProveReceiveDepositRequest, ProveReceiveTransferRequest, ProveSendRequest,
        ProveSingleClaimRequest, ProveSingleWithdrawalRequest, ProveSpentRequest,
        ProveUpdateRequest,
    },
    utils::circuit_verifiers::CircuitVerifiers,
};
use serde::de::DeserializeOwned;
use wasm_bindgen_test::wasm_bindgen_test;
use web_sys::console;

wasm_bindgen_test::wasm_bindgen_test_configure!(run_in_browser);

const SPENT_DATA: &str = include_str!("../test_data/spent.json");
const SEND_DATA: &str = include_str!("../test_data/send.json");
const UPDATE_DATA: &str = include_str!("../test_data/update.json");
const RECEIVE_TRANSFER_DATA: &str = include_str!("../test_data/receive_transfer.json");
const RECEIVE_DEPOSIT_DATA: &str = include_str!("../test_data/receive_deposit.json");
const WITHDRAWAL: &str = include_str!("../test_data/withdrawal.json");
const CLAIM: &str = include_str!("../test_data/single_claim.json");

fn read_proof_request<R: DeserializeOwned>(content: &str) -> R {
    serde_json::from_str(content).unwrap()
}

#[wasm_bindgen_test]
async fn prove_test() {
    console::time_with_label("setup processor");
    let verifiers = CircuitVerifiers::load();
    let validity_vd = verifiers.get_validity_vd();
    let balance_processor = BalanceProcessor::new(&validity_vd);
    let balance_vd = verifiers.get_balance_vd();
    assert_eq!(balance_vd, balance_processor.get_verifier_data());
    console::time_end_with_label("setup processor");

    let spent_request: ProveSpentRequest = read_proof_request(SPENT_DATA);
    let send_request: ProveSendRequest = read_proof_request(SEND_DATA);
    let update_request: ProveUpdateRequest = read_proof_request(UPDATE_DATA);
    let receive_transfer_request: ProveReceiveTransferRequest =
        read_proof_request(RECEIVE_TRANSFER_DATA);
    let deposit_request: ProveReceiveDepositRequest = read_proof_request(RECEIVE_DEPOSIT_DATA);

    console::time_with_label("prove spent");
    balance_processor
        .prove_spent(&spent_request.spent_witness)
        .unwrap();
    console::time_end_with_label("prove spent");

    console::time_with_label("prove send");
    balance_processor
        .prove_send(
            &validity_vd,
            send_request.pubkey,
            &send_request.tx_witness,
            &send_request.update_witness,
            &send_request.spent_proof,
            &send_request.prev_proof,
        )
        .unwrap();
    console::time_end_with_label("prove send");

    console::time_with_label("prove update");
    balance_processor
        .prove_update(
            &validity_vd,
            update_request.pubkey,
            &update_request.update_witness,
            &update_request.prev_proof,
        )
        .unwrap();
    console::time_end_with_label("prove update");

    console::time_with_label("prove receive transfer");
    balance_processor
        .prove_receive_transfer(
            receive_transfer_request.pubkey,
            &receive_transfer_request.receive_transfer_witness,
            &receive_transfer_request.prev_proof,
        )
        .unwrap();
    console::time_end_with_label("prove receive transfer");

    console::time_with_label("prove receive deposit");
    balance_processor
        .prove_receive_deposit(
            deposit_request.pubkey,
            &deposit_request.receive_deposit_witness,
            &deposit_request.prev_proof,
        )
        .unwrap();
    console::time_end_with_label("prove receive deposit");
}

#[wasm_bindgen_test]
async fn prove_singles() {
    console::time_with_label("setup processor");
    let verifiers = CircuitVerifiers::load();
    let validity_vd = verifiers.get_validity_vd();
    let balance_vd = verifiers.get_balance_vd();
    let single_withdrawal_circuit = SingleWithdrawalCircuit::new(&balance_vd);
    let single_claim_processor = SingleClaimProcessor::new(&validity_vd, &LockTimeConfig::normal());
    console::time_end_with_label("setup processor");

    let single_withdrawal_request: ProveSingleWithdrawalRequest = read_proof_request(WITHDRAWAL);
    let single_claim_request: ProveSingleClaimRequest = read_proof_request(CLAIM);

    console::time_with_label("prove single withdrawal");
    single_withdrawal_circuit
        .prove(
            &single_withdrawal_request
                .withdrawal_witness
                .to_transition_inclusion_value(&balance_vd)
                .unwrap(),
        )
        .unwrap();
    console::time_end_with_label("prove single withdrawal");

    console::time_with_label("prove single claim");
    single_claim_processor
        .prove(&single_claim_request.claim_witness)
        .unwrap();
    console::time_end_with_label("prove single claim");
}
