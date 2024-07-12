use plonky2::{
    field::extension::Extendable,
    hash::hash_types::RichField,
    plonk::{
        config::{AlgebraicHasher, GenericConfig},
        proof::ProofWithPublicInputs,
    },
};
use rand::Rng;

use crate::{
    circuits::validity::validity_processor::ValidityProcessor,
    mock::{block_builder::MockBlockBuilder, db::MockDB},
};

pub fn generate_random_validity_proofs<F, C, const D: usize, R: Rng>(
    validity_processor: &ValidityProcessor<F, C, D>,
    rng: &mut R,
    n: usize,
) -> Vec<ProofWithPublicInputs<F, C, D>>
where
    F: RichField + Extendable<D>,
    C: GenericConfig<D, F = F> + 'static,
    <C as GenericConfig<D>>::Hasher: AlgebraicHasher<F>,
{
    let mut db = MockDB::new();
    let block_builder = MockBlockBuilder;

    let mut proofs = Vec::with_capacity(n);
    let mut prev_proof = None;
    for _ in 0..n {
        let prev_block_witness = db.get_last_block_witness();
        let validity_witness = block_builder.post_dummy_block(rng, &mut db);
        prev_proof = validity_processor
            .prove(&prev_block_witness, &prev_proof, &validity_witness)
            .map_or(None, Some);
        proofs.push(prev_proof.clone().unwrap());
    }
    proofs
}

#[cfg(test)]
mod tests {
    use crate::circuits::validity::validity_processor::ValidityProcessor;
    use plonky2::{
        field::goldilocks_field::GoldilocksField, plonk::config::PoseidonGoldilocksConfig,
    };

    use super::*;

    type F = GoldilocksField;
    type C = PoseidonGoldilocksConfig;
    const D: usize = 2;

    #[test]
    fn test_generate_random_validity_proofs() {
        let mut rng = rand::thread_rng();
        let validity_processor = ValidityProcessor::<F, C, D>::new();
        let _proofs = generate_random_validity_proofs(&validity_processor, &mut rng, 2);
    }
}
