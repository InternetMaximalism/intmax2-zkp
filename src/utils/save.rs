use anyhow::Result;
use plonky2::{
    field::extension::Extendable,
    hash::hash_types::RichField,
    plonk::{circuit_data::CircuitData, config::GenericConfig, proof::ProofWithPublicInputs},
};
use serde::Serialize;
use std::fs::File;

pub fn save_circuit_data<
    F: RichField + Extendable<D>,
    C: GenericConfig<D, F = F> + Serialize,
    const D: usize,
    P: AsRef<std::path::Path>,
>(
    path: P,
    data: &CircuitData<F, C, D>,
) -> Result<()> {
    create_dir_if_not_exists(&path)?;
    let common_data_file = File::create(path.as_ref().join("common_circuit_data.json"))?;
    serde_json::to_writer(&common_data_file, &data.common)?;
    let verifier_data_file = File::create(path.as_ref().join("verifier_only_circuit_data.json"))?;
    serde_json::to_writer(&verifier_data_file, &data.verifier_only)?;
    Ok(())
}

pub fn save_proof<
    F: RichField + Extendable<D>,
    C: GenericConfig<D, F = F>,
    const D: usize,
    P: AsRef<std::path::Path>,
>(
    path: P,
    proof: &ProofWithPublicInputs<F, C, D>,
) -> Result<()> {
    create_dir_if_not_exists(&path)?;
    let proof_file = File::create(path.as_ref().join("proof_with_public_inputs.json"))?;
    serde_json::to_writer(&proof_file, proof)?;
    Ok(())
}

fn create_dir_if_not_exists<P: AsRef<std::path::Path>>(path: P) -> Result<()> {
    if !path.as_ref().exists() {
        std::fs::create_dir_all(path)?;
    }
    Ok(())
}
