use intmax2_zkp::{
    circuits::validity::transition::processor::TransitionProcessor,
    common::witness::validity_witness::ValidityWitness,
};
use plonky2::{field::goldilocks_field::GoldilocksField, plonk::config::PoseidonGoldilocksConfig};
use serde::{Deserialize, Serialize};

type F = GoldilocksField;
type C = PoseidonGoldilocksConfig;
const D: usize = 2;

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct GetValidityWitnessResponse {
    pub validity_witness: ValidityWitness,
}

fn main() {
    // load ../validity_witness_464.bin
    let prev_content = std::fs::read("../validity_witness_463.txt").unwrap();
    let prev_validity_witness_res: GetValidityWitnessResponse =
        serde_json::from_slice(&prev_content).unwrap();
    let prev_validity_pis = prev_validity_witness_res
        .validity_witness
        .to_validity_pis()
        .unwrap();

    let content = std::fs::read("../validity_witness_464.txt").unwrap();
    let validity_witness_res: GetValidityWitnessResponse =
        serde_json::from_slice(&content).unwrap();

    let validity_witness = validity_witness_res.validity_witness;
    let _validity_pis = validity_witness.to_validity_pis().unwrap();

    let transition_processor = TransitionProcessor::<F, C, D>::new();
    transition_processor
        .prove(&prev_validity_pis, &validity_witness)
        .unwrap();
}
