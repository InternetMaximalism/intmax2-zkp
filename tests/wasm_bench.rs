use intmax2_zkp::{
    circuits::balance::balance_processor::BalanceProcessor,
    utils::circuit_verifiers::CircuitVerifiers,
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
    console::time_with_label("setup processor");

    let mut rng = rand::thread_rng();

    let verifiers = CircuitVerifiers::load();
    let balance_processor = BalanceProcessor::new(&verifiers.get_validity_vd());

    console::time_end_with_label("setup processor");
}
