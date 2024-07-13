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
    circuits::validity::validity_processor::ValidityProcessor,
    common::witness::update_public_state_witness::UpdatePublicStateWitness,
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
            let validity_proof = self
                .validity_processor
                .prove(
                    &aux_info.prev_block_witness,
                    &prev_validity_proof,
                    &aux_info.validity_witness,
                )
                .unwrap();
            self.validity_proofs.insert(block_number, validity_proof);
        }
        self.last_block_number = current_block_number;
    }

    pub fn get_update_public_state_witness(
        &self,
        block_builder: &MockBlockBuilder,
        current_block_number: u32,
        target_block_number: u32,
    ) -> UpdatePublicStateWitness<F, C, D> {
        assert!(current_block_number <= self.last_block_number, "sync first");
        let validity_proof = self
            .validity_proofs
            .get(&current_block_number)
            .unwrap()
            .clone();
        let block_merkle_proof =
            block_builder.get_block_merkle_proof(current_block_number, target_block_number);
        UpdatePublicStateWitness {
            validity_proof,
            block_merkle_proof,
        }
    }
}
