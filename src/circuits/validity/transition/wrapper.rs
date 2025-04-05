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
        let block_pis =
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

        // connect block_pis to transition_target
        block_pis
            .account_tree_root
            .connect(&mut builder, prev_pis.public_state.account_tree_root);
        block_pis
            .prev_block_hash
            .connect(&mut builder, prev_pis.public_state.block_hash);

        // connect block_pis to transition_target
        block_pis.connect(&mut builder, &transition_target.block_pis);

        let new_pis = ValidityPublicInputsTarget {
            public_state: PublicStateTarget {
                prev_account_tree_root: transition_target.prev_account_tree_root,
                account_tree_root: transition_target.new_account_tree_root,
                next_account_id: transition_target.new_next_account_id,
                block_tree_root: transition_target.new_block_tree_root,
                block_hash: block_pis.block_hash,
                block_number: block_pis.block_number,
                timestamp: block_pis.timestamp,
                deposit_tree_root: block_pis.deposit_tree_root,
            },
            tx_tree_root: block_pis.tx_tree_root,
            sender_tree_root: block_pis.sender_tree_root,
            is_valid_block: block_pis.is_valid,
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
        self.data.prove(pw)
            .map_err(|e| ValidityTransitionError::ProofGenerationError(format!("{:?}", e)))
    }
}
