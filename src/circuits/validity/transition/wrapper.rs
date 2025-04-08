use super::error::ValidityTransitionError;
use plonky2::{
    field::extension::Extendable,
    hash::hash_types::RichField,
    iop::witness::{PartialWitness, WitnessWrite},
    plonk::{
        circuit_builder::CircuitBuilder,
        circuit_data::{CircuitConfig, CircuitData, VerifierCircuitData},
        config::{AlgebraicHasher, GenericConfig},
        proof::{ProofWithPublicInputs, ProofWithPublicInputsTarget},
    },
};

use crate::{
    circuits::validity::{
        block_validation::main_validation::MainValidationPublicInputsTarget,
        validity_pis::{ValidityPublicInputs, ValidityPublicInputsTarget},
    },
    common::public_state::PublicStateTarget,
    ethereum_types::u32limb_trait::U32LimbTargetTrait,
    utils::{dummy::DummyProof, recursively_verifiable::add_proof_target_and_verify},
};

use super::transition::{ValidityTransitionTarget, ValidityTransitionValue};

/// Circuit to prove the transition from old validity pis to new validity pis.
#[derive(Debug)]
pub struct TransitionWrapperCircuit<F, C, const D: usize>
where
    F: RichField + Extendable<D>,
    C: GenericConfig<D, F = F>,
{
    pub data: CircuitData<F, C, D>,
    pub(crate) main_validation_proof: ProofWithPublicInputsTarget<D>,
    pub(crate) transition_target: ValidityTransitionTarget<D>,
    pub(crate) prev_pis: ValidityPublicInputsTarget,
}

impl<F, C, const D: usize> TransitionWrapperCircuit<F, C, D>
where
    F: RichField + Extendable<D>,
    C: GenericConfig<D, F = F> + 'static,
    C::Hasher: AlgebraicHasher<F>,
{
    pub fn new(
        main_validation_vd: &VerifierCircuitData<F, C, D>,
        account_registration_vd: &VerifierCircuitData<F, C, D>,
        account_update_vd: &VerifierCircuitData<F, C, D>,
    ) -> Self {
        let mut builder = CircuitBuilder::<F, D>::new(CircuitConfig::default());
        let main_validation_proof = add_proof_target_and_verify(main_validation_vd, &mut builder);
        let main_validation_pis =
            MainValidationPublicInputsTarget::from_slice(&main_validation_proof.public_inputs);
        let transition_target =
            ValidityTransitionTarget::new(account_registration_vd, account_update_vd, &mut builder);
        let prev_pis = ValidityPublicInputsTarget::new(&mut builder, false);

        prev_pis
            .public_state
            .block_tree_root
            .connect(&mut builder, transition_target.prev_block_tree_root);
        prev_pis
            .public_state
            .account_tree_root
            .connect(&mut builder, transition_target.prev_account_tree_root);
        builder.connect(
            prev_pis.public_state.next_account_id,
            transition_target.prev_next_account_id,
        );

        // connect main_validation_pis to transition_target
        main_validation_pis
            .account_tree_root
            .connect(&mut builder, prev_pis.public_state.account_tree_root);
        main_validation_pis
            .prev_block_hash
            .connect(&mut builder, prev_pis.public_state.block_hash);

        // connect main_validation_pis to transition_target
        main_validation_pis.connect(&mut builder, &transition_target.main_validation_pis);

        let new_pis = ValidityPublicInputsTarget {
            public_state: PublicStateTarget {
                prev_account_tree_root: transition_target.prev_account_tree_root,
                account_tree_root: transition_target.new_account_tree_root,
                next_account_id: transition_target.new_next_account_id,
                block_tree_root: transition_target.new_block_tree_root,
                block_hash: main_validation_pis.block_hash,
                block_number: main_validation_pis.block_number,
                timestamp: main_validation_pis.timestamp,
                deposit_tree_root: main_validation_pis.deposit_tree_root,
            },
            tx_tree_root: main_validation_pis.tx_tree_root,
            sender_tree_root: main_validation_pis.sender_tree_root,
            is_valid_block: main_validation_pis.is_valid,
        };

        let concat_pis = [prev_pis.to_vec(), new_pis.to_vec()].concat();
        builder.register_public_inputs(&concat_pis);

        let data = builder.build::<C>();

        Self {
            data,
            main_validation_proof,
            transition_target,
            prev_pis,
        }
    }
}

impl<F, C, const D: usize> TransitionWrapperCircuit<F, C, D>
where
    F: RichField + Extendable<D>,
    C: GenericConfig<D, F = F> + 'static,
    C::Hasher: AlgebraicHasher<F>,
{
    pub(crate) fn prove(
        &self,
        main_validation_proof: &ProofWithPublicInputs<F, C, D>,
        transition_value: &ValidityTransitionValue<F, C, D>,
        prev_pis: &ValidityPublicInputs,
        account_registration_proof_dummy: DummyProof<F, C, D>,
        account_update_proof_dummy: DummyProof<F, C, D>,
    ) -> Result<ProofWithPublicInputs<F, C, D>, ValidityTransitionError> {
        // Validate inputs
        if prev_pis.public_state.block_tree_root != transition_value.prev_block_tree_root {
            return Err(ValidityTransitionError::BlockTreeRootMismatch {
                expected: prev_pis.public_state.block_tree_root,
                actual: transition_value.prev_block_tree_root,
            });
        }

        if prev_pis.public_state.account_tree_root != transition_value.prev_account_tree_root {
            return Err(ValidityTransitionError::PrevAccountTreeRootMismatch {
                expected: prev_pis.public_state.account_tree_root,
                actual: transition_value.prev_account_tree_root,
            });
        }

        let mut pw = PartialWitness::<F>::new();
        self.transition_target.set_witness(
            &mut pw,
            account_registration_proof_dummy,
            account_update_proof_dummy,
            transition_value,
        );
        self.prev_pis.set_witness(&mut pw, prev_pis);
        pw.set_proof_with_pis_target(&self.main_validation_proof, main_validation_proof);
        self.data
            .prove(pw)
            .map_err(|e| ValidityTransitionError::ProofGenerationError(format!("{:?}", e)))
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
                transition::{
                    account_registration::{AccountRegistrationCircuit, AccountRegistrationValue},
                    account_update::AccountUpdateCircuit,
                    transition::ValidityTransitionValue,
                },
                validity_pis::ValidityPublicInputs,
            },
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

    use super::TransitionWrapperCircuit;

    type F = GoldilocksField;
    const D: usize = 2;
    type C = PoseidonGoldilocksConfig;

    #[test]
    fn test_transition_wrapper_circuit() {
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
        let block_witness = validity_witness.block_witness.clone();
        let validity_transition_witness = validity_witness.validity_transition_witness.clone();

        let main_validation_processor = MainValidationProcessor::<F, C, D>::new();
        let main_validation_proof = main_validation_processor.prove(&block_witness).unwrap();

        let account_registration_circuit = AccountRegistrationCircuit::<F, C, D>::new();
        let account_update_circuit = AccountUpdateCircuit::<F, C, D>::new();

        let account_registration_value = AccountRegistrationValue::new(
            block_witness.prev_account_tree_root,
            block_witness.prev_next_account_id,
            block_witness.block.block_number,
            block_witness.get_sender_tree().leaves(),
            validity_transition_witness
                .account_registration_proofs
                .clone()
                .unwrap(),
        )
        .unwrap();
        let account_registration_proof = account_registration_circuit
            .prove(&account_registration_value)
            .unwrap();

        let validity_transition_value = ValidityTransitionValue::new(
            &account_registration_circuit,
            &account_update_circuit,
            validity_witness
                .block_witness
                .to_main_validation_pis()
                .unwrap(),
            block_witness.prev_account_tree_root,
            block_witness.prev_next_account_id,
            block_witness.prev_block_tree_root,
            Some(account_registration_proof),
            None,
            validity_transition_witness.block_merkle_proof.clone(),
        )
        .unwrap();

        let transition_wrapper_circuit = TransitionWrapperCircuit::<F, C, D>::new(
            &main_validation_processor
                .main_validation_circuit
                .data
                .verifier_data(),
            &account_registration_circuit.data.verifier_data(),
            &account_update_circuit.data.verifier_data(),
        );
        let transition_wrapper_proof = transition_wrapper_circuit
            .prove(
                &main_validation_proof,
                &validity_transition_value,
                &prev_validity_pis,
                account_registration_circuit.dummy_proof,
                account_update_circuit.dummy_proof,
            )
            .unwrap();

        transition_wrapper_circuit
            .data
            .verify(transition_wrapper_proof)
            .unwrap();
    }
}
