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
    },
    common::{
        trees::sender_tree::get_sender_leaves,
        witness::{block_witness::BlockWitness, validity_witness::ValidityWitness},
    },
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
        prev_block_witness: &BlockWitness,
        validity_witness: &ValidityWitness,
    ) -> Result<ProofWithPublicInputs<F, C, D>> {
        let prev_pis = prev_block_witness.to_validity_pis();
        let prev_block_pis = prev_block_witness.to_main_validation_pis();
        let account_registoration_proof =
            if prev_pis.is_valid_block && prev_pis.is_registoration_block {
                let account_registoration_proofs = validity_witness
                    .validity_transition_witness
                    .account_registoration_proofs
                    .clone()
                    .expect("Account registoration proofs are missing");
                let prev_sender_leaves = get_sender_leaves(
                    &prev_block_witness.pubkeys,
                    prev_block_witness.signature.sender_flag,
                );
                let value = AccountRegistorationValue::new(
                    prev_pis.public_state.account_tree_root,
                    prev_pis.public_state.block_number,
                    prev_sender_leaves.clone(),
                    account_registoration_proofs,
                );
                let proof = self.account_registoration_circuit.prove(&value)?;
                Some(proof)
            } else {
                None
            };
        let account_update_proof = if prev_pis.is_valid_block && (!prev_pis.is_registoration_block)
        {
            let account_update_proofs = validity_witness
                .validity_transition_witness
                .account_update_proofs
                .clone()
                .expect("Account update proofs are missing");
            let prev_sender_leaves = get_sender_leaves(
                &prev_block_witness.pubkeys,
                prev_block_witness.signature.sender_flag,
            );
            let value = AccountUpdateValue::new(
                prev_pis.public_state.account_tree_root,
                prev_pis.public_state.block_number,
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
            prev_block_pis,
            prev_pis.public_state.block_tree_root,
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
    use plonky2::{
        field::goldilocks_field::GoldilocksField, plonk::config::PoseidonGoldilocksConfig,
    };
    use rand::Rng;

    use crate::{
        common::{signature::key_set::KeySet, tx::Tx},
        constants::NUM_SENDERS_IN_BLOCK,
        mock::{
            block_builder::{MockBlockBuilder, TxResuest},
            db::MockDB,
        },
    };

    use super::TransitionProcessor;

    type F = GoldilocksField;
    type C = PoseidonGoldilocksConfig;
    const D: usize = 2;

    #[test]
    fn test_transition_processor() {
        let mut rng = rand::thread_rng();
        let mut mock_db = MockDB::new();
        let block_builder = MockBlockBuilder;
        block_builder.post_dummy_block(&mut rng, &mut mock_db);

        let transition_processor = TransitionProcessor::<F, C, D>::new();
        let txs = (0..NUM_SENDERS_IN_BLOCK)
            .map(|_| {
                let sender = KeySet::rand(&mut rng);
                TxResuest {
                    tx: Tx::rand(&mut rng),
                    sender,
                    will_return_signature: rng.gen_bool(0.5),
                }
            })
            .collect::<Vec<_>>();
        let validity_witness = block_builder.generate_block_and_witness(&mut mock_db, true, txs);
        let prev_block_witness = mock_db.get_last_block_witness();

        let _proof = transition_processor
            .prove(&prev_block_witness, &validity_witness)
            .unwrap();
    }
}
