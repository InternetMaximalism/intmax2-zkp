use std::sync::Arc;

use intmax2_zkp::{
    circuits::{
        balance::balance_processor::BalanceProcessor,
        test_utils::state_manager::ValidityStateManager,
        validity::validity_processor::ValidityProcessor,
    },
    ethereum_types::address::Address,
};
use plonky2::{field::goldilocks_field::GoldilocksField, plonk::config::PoseidonGoldilocksConfig};
use wasm_bindgen_test::wasm_bindgen_test;
use web_sys::console;

wasm_bindgen_test::wasm_bindgen_test_configure!(run_in_browser);

type F = GoldilocksField;
type C = PoseidonGoldilocksConfig;
const D: usize = 2;

#[wasm_bindgen_test]
fn heavy_loop() {
    console::time_with_label("heavy_loop");
    let mut _sum = 0;
    for i in 0..1_000 {
        _sum += i;
        if i % 100 == 0 {
            console::log_1(&format!("Progress: {}/1,000", i).into());
        }
    }
    console::time_end_with_label("heavy_loop");
}

#[wasm_bindgen_test]
fn prove_test() {
    console::time_with_label("prove_test");
    let validity_processor = Arc::new(ValidityProcessor::<F, C, D>::new());
    // let balance_processor = BalanceProcessor::new(&validity_processor.get_verifier_data());
    // let mut validity_state_manager =
    //     ValidityStateManager::new(validity_processor.clone(), Address::default());
    // let validity_vd = validity_processor.get_verifier_data();
    // let balance_vd = balance_processor.get_verifier_data();
    console::time_end_with_label("prove_test");
}
