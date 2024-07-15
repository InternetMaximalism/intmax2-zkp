use anyhow::Result;
use plonky2::{
    field::extension::Extendable,
    hash::hash_types::RichField,
    plonk::{
        config::{AlgebraicHasher, GenericConfig},
        proof::ProofWithPublicInputs,
    },
};

use crate::{
    circuits::validity::block_validation::{
        account_exclusion::{AccountExclusionCircuit, AccountExclusionValue},
        account_inclusion::{AccountInclusionCircuit, AccountInclusionValue},
        aggregation::{AggregationCircuit, AggregationValue},
        format_validation::{FormatValidationCircuit, FormatValidationValue},
        main_validation::{MainValidationCircuit, MainValidationValue},
    },
    common::witness::block_witness::BlockWitness,
};

pub struct MainValidationProcessor<F, C, const D: usize>
where
    F: RichField + Extendable<D>,
    C: GenericConfig<D, F = F>,
{
    pub account_inclusion_circuit: AccountInclusionCircuit<F, C, D>,
    pub account_exclusion_circuit: AccountExclusionCircuit<F, C, D>,
    pub aggregation_circuit: AggregationCircuit<F, C, D>,
    pub format_validation_circuit: FormatValidationCircuit<F, C, D>,
    pub main_validation_circuit: MainValidationCircuit<F, C, D>,
}

impl<F, C, const D: usize> MainValidationProcessor<F, C, D>
where
    F: RichField + Extendable<D>,
    C: GenericConfig<D, F = F> + 'static,
    <C as GenericConfig<D>>::Hasher: AlgebraicHasher<F>,
{
    pub fn new() -> Self {
        let account_inclusion_circuit = AccountInclusionCircuit::new();
        let account_exclusion_circuit = AccountExclusionCircuit::new();
        let aggregation_circuit = AggregationCircuit::new();
        let format_validation_circuit = FormatValidationCircuit::new();
        let main_validation_circuit = MainValidationCircuit::new(
            &account_inclusion_circuit,
            &account_exclusion_circuit,
            &format_validation_circuit,
            &aggregation_circuit,
        );

        Self {
            account_exclusion_circuit,
            account_inclusion_circuit,
            aggregation_circuit,
            format_validation_circuit,
            main_validation_circuit,
        }
    }

    pub fn prove(&self, block_witness: &BlockWitness) -> Result<ProofWithPublicInputs<F, C, D>> {
        let (account_exclusion_proof, account_inclusion_proof) =
            if block_witness.signature.is_registoration_block {
                let account_exclusion_value = AccountExclusionValue::new(
                    block_witness.prev_account_tree_root,
                    block_witness
                        .account_membership_proofs
                        .clone()
                        .expect("Account membership proofs are missing"),
                    block_witness.pubkeys.clone(),
                );
                let account_exclusion_proof = self
                    .account_exclusion_circuit
                    .prove(&account_exclusion_value)?;
                (Some(account_exclusion_proof), None)
            } else {
                let value = AccountInclusionValue::new(
                    block_witness.prev_account_tree_root,
                    block_witness
                        .account_id_packed
                        .clone()
                        .expect("Account ID is missing"),
                    block_witness
                        .account_merkle_proofs
                        .clone()
                        .expect("Account merkle proofs are missing"),
                    block_witness.pubkeys.clone(),
                );
                let account_inclusion_proof = self.account_inclusion_circuit.prove(&value)?;
                (None, Some(account_inclusion_proof))
            };
        let format_validation_value = FormatValidationValue::new(
            block_witness.pubkeys.clone(),
            block_witness.signature.clone(),
        );
        let format_validation_proof = self
            .format_validation_circuit
            .prove(&format_validation_value)
            .unwrap();
        let aggregation_proof = if format_validation_value.is_valid {
            let aggregation_value = AggregationValue::new(
                block_witness.pubkeys.clone(),
                block_witness.signature.clone(),
            );
            let aggregation_proof = self.aggregation_circuit.prove(&aggregation_value)?;
            Some(aggregation_proof)
        } else {
            None
        };
        let main_validation_value = MainValidationValue::new(
            &self.account_inclusion_circuit,
            &self.account_exclusion_circuit,
            &self.format_validation_circuit,
            &self.aggregation_circuit,
            block_witness.block.clone(),
            block_witness.signature.clone(),
            block_witness.pubkeys.clone(),
            block_witness.prev_account_tree_root,
            account_inclusion_proof,
            account_exclusion_proof,
            format_validation_proof,
            aggregation_proof,
        );
        let main_validation_proof = self.main_validation_circuit.prove(
            self.account_inclusion_circuit.dummy_proof.clone(),
            self.account_exclusion_circuit.dummy_proof.clone(),
            self.aggregation_circuit.dummy_proof.clone(),
            &main_validation_value,
        )?;
        Ok(main_validation_proof)
    }
}

#[cfg(test)]
mod tests {
    use plonky2::{
        field::goldilocks_field::GoldilocksField, plonk::config::PoseidonGoldilocksConfig,
    };

    use crate::{
        circuits::validity::block_validation::processor::MainValidationProcessor,
        mock::block_builder::MockBlockBuilder, test_utils::tx::generate_random_tx_requests,
    };

    type F = GoldilocksField;
    const D: usize = 2;
    type C = PoseidonGoldilocksConfig;

    #[test]
    fn main_validation_processor() {
        let main_validation_processor = MainValidationProcessor::<F, C, D>::new();
        let mut rng = rand::thread_rng();
        let mut block_builder = MockBlockBuilder::new();
        let txs = generate_random_tx_requests(&mut rng);
        let validity_witness = block_builder.post_block(true, txs);
        let instant = std::time::Instant::now();
        let _main_validation_proof = main_validation_processor
            .prove(&validity_witness.block_witness)
            .unwrap();
        println!(
            "main validation proof generation time: {:?}",
            instant.elapsed()
        );
    }
}
