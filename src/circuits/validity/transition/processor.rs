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
            account_registration::AccountRegistrationValue, account_update::AccountUpdateValue,
            error::ValidityTransitionError, transition::ValidityTransitionValue,
        },
        validity_pis::ValidityPublicInputs,
    },
    common::{trees::sender_tree::get_sender_leaves, witness::validity_witness::ValidityWitness},
};

use super::{
    account_registration::AccountRegistrationCircuit, account_update::AccountUpdateCircuit,
    wrapper::ValidityTransitionWrapperCircuit,
};

#[derive(Debug)]
pub struct ValidityTransitionProcessor<F, C, const D: usize>
where
    F: RichField + Extendable<D>,
    C: GenericConfig<D, F = F>,
{
    pub main_validation_processor: MainValidationProcessor<F, C, D>,
    pub account_registration_circuit: AccountRegistrationCircuit<F, C, D>,
    pub account_update_circuit: AccountUpdateCircuit<F, C, D>,
    pub transition_wrapper_circuit: ValidityTransitionWrapperCircuit<F, C, D>,
}

impl<F, C, const D: usize> Default for ValidityTransitionProcessor<F, C, D>
where
    F: RichField + Extendable<D>,
    C: GenericConfig<D, F = F> + 'static,
    <C as GenericConfig<D>>::Hasher: AlgebraicHasher<F>,
{
    fn default() -> Self {
        Self::new()
    }
}

impl<F, C, const D: usize> ValidityTransitionProcessor<F, C, D>
where
    F: RichField + Extendable<D>,
    C: GenericConfig<D, F = F> + 'static,
    <C as GenericConfig<D>>::Hasher: AlgebraicHasher<F>,
{
    pub fn new() -> Self {
        let main_validation_processor = MainValidationProcessor::new();
        let account_registration_circuit = AccountRegistrationCircuit::new();
        let account_update_circuit = AccountUpdateCircuit::new();
        let transition_wrapper_circuit = ValidityTransitionWrapperCircuit::new(
            &main_validation_processor
                .main_validation_circuit
                .data
                .verifier_data(),
            &account_registration_circuit.data.verifier_data(),
            &account_update_circuit.data.verifier_data(),
        );
        Self {
            main_validation_processor,
            account_registration_circuit,
            account_update_circuit,
            transition_wrapper_circuit,
        }
    }

    pub fn prove(
        &self,
        prev_pis: &ValidityPublicInputs,
        validity_witness: &ValidityWitness,
    ) -> Result<ProofWithPublicInputs<F, C, D>, ValidityTransitionError> {
        let prev_account_tree_root = validity_witness.block_witness.prev_account_tree_root;
        let prev_block_tree_root = validity_witness.block_witness.prev_block_tree_root;
        let prev_next_account_id = validity_witness.block_witness.prev_next_account_id;

        let main_validation_pis = validity_witness
            .block_witness
            .to_main_validation_pis()
            .map_err(|e| {
                ValidityTransitionError::InvalidValidityWitness(format!(
                    "Failed to convert block witness to main validation pis: {}",
                    e
                ))
            })?;

        let account_registration_proof =
            if main_validation_pis.is_valid && main_validation_pis.is_registration_block {
                let account_registration_proofs = validity_witness
                    .validity_transition_witness
                    .account_registration_proofs
                    .clone()
                    .ok_or(ValidityTransitionError::MissingAccountRegistrationProof)?;

                let sender_leaves = get_sender_leaves(
                    &validity_witness.block_witness.pubkeys,
                    validity_witness.block_witness.signature.sender_flag,
                );

                let value = AccountRegistrationValue::new(
                    prev_account_tree_root,
                    prev_next_account_id,
                    main_validation_pis.block_number,
                    sender_leaves.clone(),
                    account_registration_proofs,
                )?;

                let proof = self
                    .account_registration_circuit
                    .prove(&value)
                    .map_err(|e| {
                        ValidityTransitionError::InvalidAccountRegistrationProofVerification(
                            format!("Failed to prove account registration: {}", e),
                        )
                    })?;

                Some(proof)
            } else {
                None
            };

        let account_update_proof =
            if main_validation_pis.is_valid && (!main_validation_pis.is_registration_block) {
                let account_update_proofs = validity_witness
                    .validity_transition_witness
                    .account_update_proofs
                    .clone()
                    .ok_or(ValidityTransitionError::MissingAccountUpdateProof)?;

                let prev_sender_leaves = get_sender_leaves(
                    &validity_witness.block_witness.pubkeys,
                    validity_witness.block_witness.signature.sender_flag,
                );

                let value = AccountUpdateValue::new(
                    prev_account_tree_root,
                    prev_next_account_id,
                    main_validation_pis.block_number,
                    prev_sender_leaves.clone(),
                    account_update_proofs,
                )?;

                let proof = self.account_update_circuit.prove(&value).map_err(|e| {
                    ValidityTransitionError::InvalidAccountUpdateProofVerification(format!(
                        "Failed to prove account update: {}",
                        e
                    ))
                })?;

                Some(proof)
            } else {
                None
            };

        let transition_value = ValidityTransitionValue::new(
            &self.account_registration_circuit,
            &self.account_update_circuit,
            main_validation_pis,
            prev_account_tree_root,
            prev_next_account_id,
            prev_block_tree_root,
            account_registration_proof,
            account_update_proof,
            validity_witness
                .validity_transition_witness
                .block_merkle_proof
                .clone(),
        )?;

        let main_validation_proof = self
            .main_validation_processor
            .prove(&validity_witness.block_witness)
            .map_err(|e| {
                ValidityTransitionError::ProofGenerationError(format!(
                    "Failed to prove main validation: {}",
                    e
                ))
            })?;

        let proof = self
            .transition_wrapper_circuit
            .prove(
                &main_validation_proof,
                &transition_value,
                prev_pis,
                self.account_registration_circuit.dummy_proof.clone(),
                self.account_update_circuit.dummy_proof.clone(),
            )
            .map_err(|e| {
                ValidityTransitionError::ProofGenerationError(format!(
                    "Failed to prove transition wrapper: {}",
                    e
                ))
            })?;

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
        circuits::{
            test_utils::witness_generator::{construct_validity_and_tx_witness, MockTxRequest},
            validity::validity_pis::ValidityPublicInputs,
        },
        common::{
            signature_content::key_set::KeySet,
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
    type C = PoseidonGoldilocksConfig;
    const D: usize = 2;

    #[test]
    fn test_transition_processor() {
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
            prev_validity_pis.clone(),
            &mut account_tree,
            &mut block_tree,
            &deposit_tree,
            true,
            0,
            Address::default(),
            0,
            &tx_requests,
            0,
        )
        .unwrap();

        let validity_transition_processor = super::ValidityTransitionProcessor::<F, C, D>::new();

        let proof = validity_transition_processor
            .prove(&prev_validity_pis, &validity_witness)
            .unwrap();

        validity_transition_processor
            .transition_wrapper_circuit
            .data
            .verify(proof)
            .unwrap();
    }
}
