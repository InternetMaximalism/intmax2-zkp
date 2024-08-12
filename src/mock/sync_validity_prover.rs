use std::io::Write;

use hashbrown::HashMap;
use plonky2::{
    field::extension::Extendable,
    hash::hash_types::RichField,
    plonk::{
        config::{AlgebraicHasher, GenericConfig},
        proof::ProofWithPublicInputs,
    },
};

use crate::{
    circuits::validity::{
        validity_circuit::ValidityCircuit, validity_processor::ValidityProcessor,
    },
    common::witness::update_witness::UpdateWitness,
    ethereum_types::u256::U256,
};

use super::block_builder::MockBlockBuilder;

pub struct SyncValidityProver<F, C, const D: usize>
where
    F: RichField + Extendable<D>,
    C: GenericConfig<D, F = F>,
{
    pub validity_processor: ValidityProcessor<F, C, D>,
    pub last_block_number: u32,
    pub validity_proofs: HashMap<u32, ProofWithPublicInputs<F, C, D>>,
}

impl<F, C, const D: usize> SyncValidityProver<F, C, D>
where
    F: RichField + Extendable<D>,
    C: GenericConfig<D, F = F> + 'static,
    <C as GenericConfig<D>>::Hasher: AlgebraicHasher<F>,
{
    pub fn new() -> Self {
        Self {
            validity_processor: ValidityProcessor::new(),
            validity_proofs: HashMap::new(),
            last_block_number: 0,
        }
    }

    pub fn sync(&mut self, block_builder: &MockBlockBuilder) {
        let current_block_number = block_builder.last_block_number();
        for block_number in (self.last_block_number + 1)..=current_block_number {
            let prev_validity_proof = self.validity_proofs.get(&(block_number - 1)).cloned();
            assert!(prev_validity_proof.is_some() || block_number == 1);
            let aux_info = block_builder
                .aux_info
                .get(&block_number)
                .expect("aux info not found");

            let max_account_id = block_builder.account_tree.len();
            let validity_witness = serde_json::to_vec(&aux_info.validity_witness.compress(max_account_id)).expect("serialize validity witness failed");
            let mut f = std::fs::File::create("validity_witness.json").unwrap();
            f.write_all(&validity_witness).unwrap();
            if let Some(prev_validity_proof) = prev_validity_proof.clone() {
                let compressed_prev_validity_proof = prev_validity_proof.clone().compress(
                    &self.validity_processor.validity_circuit.data.verifier_only.circuit_digest,
                    &self.validity_processor.validity_circuit.data.common
                ).unwrap();
                let mut f = std::fs::File::create("prev_validity_proof.bin").unwrap();
                f.write_all(&compressed_prev_validity_proof.to_bytes()).unwrap();
            } else {
                println!("prev validity proof is None");
            }

            let validity_proof = self
                .validity_processor
                .prove(&prev_validity_proof, &aux_info.validity_witness)
                .unwrap();
            self.validity_proofs.insert(block_number, validity_proof);
        }
        self.last_block_number = current_block_number;
    }

    pub fn get_update_witness(
        &self,
        block_builder: &MockBlockBuilder,
        pubkey: U256,
        current_block_number: u32,
        target_block_number: u32,
        is_prev_account_tree: bool,
    ) -> UpdateWitness<F, C, D> {
        let validity_proof = self
            .validity_proofs
            .get(&current_block_number)
            .unwrap()
            .clone();
        let block_merkle_proof =
            block_builder.get_block_merkle_proof(current_block_number, target_block_number);
        let account_membership_proof = if !is_prev_account_tree {
            block_builder.get_account_membership_proof(current_block_number, pubkey)
        } else {
            block_builder.get_account_membership_proof(current_block_number - 1, pubkey)
        };
        UpdateWitness {
            validity_proof,
            block_merkle_proof,
            account_membership_proof,
        }
    }

    pub fn validity_circuit(&self) -> &ValidityCircuit<F, C, D> {
        &self.validity_processor.validity_circuit
    }
}
