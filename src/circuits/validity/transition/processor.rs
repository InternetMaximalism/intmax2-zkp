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
        block_validation::processor::MainValidationProcessor,
        transition::{
            account_registoration::AccountRegistorationValue, account_update::AccountUpdateValue,
            transition::ValidityTransitionValue,
        },
        validity_pis::ValidityPublicInputs,
    },
    common::{trees::sender_tree::get_sender_leaves, witness::validity_witness::ValidityWitness},
};

use super::{
    account_registoration::AccountRegistorationCircuit, account_update::AccountUpdateCircuit,
    wrapper::TransitionWrapperCircuit,
};
use anyhow::Result;

pub struct TransitionProcessor<F, C, const D: usize>
where
    F: RichField + Extendable<D>,
    C: GenericConfig<D, F = F>,
{
    pub main_validation_processor: MainValidationProcessor<F, C, D>,
    pub account_registoration_circuit: AccountRegistorationCircuit<F, C, D>,
    pub account_update_circuit: AccountUpdateCircuit<F, C, D>,
    pub transition_wrapper_circuit: TransitionWrapperCircuit<F, C, D>,
}

impl<F, C, const D: usize> TransitionProcessor<F, C, D>
where
    F: RichField + Extendable<D>,
    C: GenericConfig<D, F = F> + 'static,
    <C as GenericConfig<D>>::Hasher: AlgebraicHasher<F>,
{
    pub fn new() -> Self {
        let main_validation_processor = MainValidationProcessor::new();
        let account_registoration_circuit = AccountRegistorationCircuit::new();
        let account_update_circuit = AccountUpdateCircuit::new();
        let transition_wrapper_circuit = TransitionWrapperCircuit::new(
            &main_validation_processor.main_validation_circuit,
            &account_registoration_circuit,
            &account_update_circuit,
        );
        Self {
            main_validation_processor,
            account_registoration_circuit,
            account_update_circuit,
            transition_wrapper_circuit,
        }
    }

    pub fn prove(
        &self,
        prev_pis: &ValidityPublicInputs,
        validity_witness: &ValidityWitness,
    ) -> Result<ProofWithPublicInputs<F, C, D>> {
        let prev_account_tree_root = validity_witness.block_witness.prev_account_tree_root;
        let prev_block_tree_root = validity_witness.block_witness.prev_block_tree_root;

        let block_pis = validity_witness.block_witness.to_main_validation_pis();

        let account_registoration_proof = if block_pis.is_valid && block_pis.is_registoration_block
        {
            let account_registoration_proofs = validity_witness
                .validity_transition_witness
                .account_registoration_proofs
                .clone()
                .expect("Account registoration proofs are missing");
            let sender_leaves = get_sender_leaves(
                &validity_witness.block_witness.pubkeys,
                validity_witness.block_witness.signature.sender_flag,
            );
            let value = AccountRegistorationValue::new(
                prev_account_tree_root,
                block_pis.block_number,
                sender_leaves.clone(),
                account_registoration_proofs,
            );
            let proof = self.account_registoration_circuit.prove(&value)?;
            Some(proof)
        } else {
            None
        };
        let account_update_proof = if block_pis.is_valid && (!block_pis.is_registoration_block) {
            let account_update_proofs = validity_witness
                .validity_transition_witness
                .account_update_proofs
                .clone()
                .expect("Account update proofs are missing");
            let prev_sender_leaves = get_sender_leaves(
                &validity_witness.block_witness.pubkeys,
                validity_witness.block_witness.signature.sender_flag,
            );
            let value = AccountUpdateValue::new(
                prev_account_tree_root,
                block_pis.block_number,
                prev_sender_leaves.clone(),
                account_update_proofs,
            );
            let proof = self.account_update_circuit.prove(&value)?;
            Some(proof)
        } else {
            None
        };
        let transition_value = ValidityTransitionValue::new(
            &self.account_registoration_circuit,
            &self.account_update_circuit,
            validity_witness.block_witness.to_main_validation_pis(),
            prev_account_tree_root,
            prev_block_tree_root,
            account_registoration_proof,
            account_update_proof,
            validity_witness
                .validity_transition_witness
                .block_merkle_proof
                .clone(),
        );
        let main_validation_proof = self
            .main_validation_processor
            .prove(&validity_witness.block_witness)?;
        let proof = self.transition_wrapper_circuit.prove(
            &main_validation_proof,
            &transition_value,
            &prev_pis,
            self.account_registoration_circuit.dummy_proof.clone(),
            self.account_update_circuit.dummy_proof.clone(),
        )?;
        Ok(proof)
    }
}

#[cfg(test)]
mod tests {
    use crate::{
        mock::block_builder::MockBlockBuilder, test_utils::tx::generate_random_tx_requests,
    };
    use plonky2::{
        field::goldilocks_field::GoldilocksField, plonk::config::PoseidonGoldilocksConfig,
    };

    use super::TransitionProcessor;

    type F = GoldilocksField;
    type C = PoseidonGoldilocksConfig;
    const D: usize = 2;

    #[test]
    fn test_transition_processor() {
        let mut rng = rand::thread_rng();
        let mut block_builder = MockBlockBuilder::new();
        block_builder.post_block(true, generate_random_tx_requests(&mut rng));

        let transition_processor = TransitionProcessor::<F, C, D>::new();
        let txs = generate_random_tx_requests(&mut rng);
        let validity_witness = block_builder.post_block(true, txs);

        let prev_block_number = validity_witness.get_block_number() - 1;
        let prev_pis = block_builder
            .aux_info
            .get(&prev_block_number)
            .unwrap()
            .validity_witness
            .to_validity_pis();

        let _proof = transition_processor
            .prove(&prev_pis, &validity_witness)
            .unwrap();
    }
}
