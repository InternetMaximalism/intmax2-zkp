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
    common::{signature::utils::get_pubkey_hash, witness::block_witness::BlockWitness},
};

#[derive(Debug)]
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

impl<F, C, const D: usize> Default for MainValidationProcessor<F, C, D>
where
    F: RichField + Extendable<D>,
    C: GenericConfig<D, F = F> + 'static,
    <C as GenericConfig<D>>::Hasher: AlgebraicHasher<F>,
{
    fn default() -> Self {
        Self::new()
    }
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
            &account_inclusion_circuit.data.verifier_data(),
            &account_exclusion_circuit.data.verifier_data(),
            &format_validation_circuit.data.verifier_data(),
            &aggregation_circuit.data.verifier_data(),
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
        let mut result = true;
        if !block_witness
            .signature
            .block_sign_payload
            .is_registration_block
        {
            let pubkey_hash = get_pubkey_hash(&block_witness.pubkeys);
            let is_pubkey_eq = block_witness.signature.pubkey_hash == pubkey_hash;
            result = result && is_pubkey_eq;
        }
        let sender_leaves = block_witness.get_sender_tree().leaves();
        let (account_exclusion_proof, account_inclusion_proof) = if block_witness
            .signature
            .block_sign_payload
            .is_registration_block
        {
            let account_exclusion_value = AccountExclusionValue::new(
                block_witness.prev_account_tree_root,
                block_witness
                    .account_membership_proofs
                    .clone()
                    .expect("Account membership proofs are missing"),
                sender_leaves,
            );
            let account_exclusion_proof = self
                .account_exclusion_circuit
                .prove(&account_exclusion_value)?;
            result = result && account_exclusion_value.is_valid;
            (Some(account_exclusion_proof), None)
        } else {
            let value = AccountInclusionValue::new(
                block_witness.prev_account_tree_root,
                block_witness
                    .account_id_packed
                    .expect("Account ID is missing"),
                block_witness
                    .account_merkle_proofs
                    .clone()
                    .expect("Account merkle proofs are missing"),
                block_witness.pubkeys.clone(),
            );
            let account_inclusion_proof = self.account_inclusion_circuit.prove(&value)?;
            result = result && value.is_valid;
            (None, Some(account_inclusion_proof))
        };
        let format_validation_value = FormatValidationValue::new(
            block_witness.pubkeys.clone(),
            block_witness.signature.clone(),
        );
        result = result && format_validation_value.is_valid;
        let format_validation_proof = self
            .format_validation_circuit
            .prove(&format_validation_value)
            .unwrap();
        let aggregation_proof = if result {
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
    use rand::Rng;

    use crate::{
        circuits::{
            test_utils::witness_generator::{construct_validity_and_tx_witness, MockTxRequest},
            validity::{
                block_validation::processor::MainValidationProcessor,
                validity_pis::ValidityPublicInputs,
            },
        },
        common::{
            signature::key_set::KeySet,
            trees::{
                account_tree::AccountTree, block_hash_tree::BlockHashTree,
                deposit_tree::DepositTree,
            },
            tx::Tx,
        },
        constants::NUM_SENDERS_IN_BLOCK,
        ethereum_types::address::Address,
    };

    type F = GoldilocksField;
    const D: usize = 2;
    type C = PoseidonGoldilocksConfig;

    #[test]
    fn main_validation_processor() -> anyhow::Result<()> {
        let main_validation_processor = MainValidationProcessor::<F, C, D>::new();
        let mut rng = rand::thread_rng();

        let mut account_tree = AccountTree::initialize();
        let mut block_tree = BlockHashTree::initialize();
        let deposit_tree = DepositTree::initialize();

        let prev_validity_pis = ValidityPublicInputs::genesis();
        let tx_requests = (0..NUM_SENDERS_IN_BLOCK)
            .map(|_| MockTxRequest {
                tx: Tx::rand(&mut rng),
                sender_key: KeySet::rand(&mut rng),
                will_return_sig: rng.gen_bool(0.5),
            })
            .collect::<Vec<_>>();
        let (validity_witness, _) = construct_validity_and_tx_witness(
            prev_validity_pis,
            &mut account_tree,
            &mut block_tree,
            &deposit_tree,
            true,
            0,
            Address::default(),
            0,
            &tx_requests,
            0,
        )?;
        let instant = std::time::Instant::now();
        let _main_validation_proof = main_validation_processor
            .prove(&validity_witness.block_witness)
            .unwrap();
        println!(
            "main validation proof generation time: {:?}",
            instant.elapsed()
        );
        Ok(())
    }
}
