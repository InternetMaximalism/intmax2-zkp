use anyhow::Result;
use plonky2::{
    field::extension::Extendable,
    hash::hash_types::RichField,
    iop::witness::{PartialWitness, WitnessWrite},
    plonk::{
        circuit_builder::CircuitBuilder,
        circuit_data::{CircuitConfig, CircuitData},
        config::{AlgebraicHasher, GenericConfig},
        proof::{ProofWithPublicInputs, ProofWithPublicInputsTarget},
    },
};

use crate::{
    circuits::validity::{
        block_validation::main_validation::{
            MainValidationCircuit, MainValidationPublicInputsTarget,
        },
        validity_pis::{ValidityPublicInputs, ValidityPublicInputsTarget},
    },
    ethereum_types::u32limb_trait::U32LimbTargetTrait,
    utils::{dummy::DummyProof, recursivable::Recursivable},
};

use super::{
    account_registoration::AccountRegistorationCircuit,
    account_update::AccountUpdateCircuit,
    transition::{ValidityTransitionTarget, ValidityTransitionValue},
};

pub struct TransitionWrapperCircuit<F, C, const D: usize>
where
    F: RichField + Extendable<D>,
    C: GenericConfig<D, F = F>,
{
    pub data: CircuitData<F, C, D>,
    pub main_validation_proof: ProofWithPublicInputsTarget<D>,
    pub transition_target: ValidityTransitionTarget<D>,
    pub prev_pis: ValidityPublicInputsTarget,
    pub new_pis: ValidityPublicInputsTarget,
}

impl<F, C, const D: usize> TransitionWrapperCircuit<F, C, D>
where
    F: RichField + Extendable<D>,
    C: GenericConfig<D, F = F> + 'static,
    C::Hasher: AlgebraicHasher<F>,
{
    pub fn new(
        main_validation_circut: &MainValidationCircuit<F, C, D>,
        account_registoration_circuit: &AccountRegistorationCircuit<F, C, D>,
        account_update_circuit: &AccountUpdateCircuit<F, C, D>,
    ) -> Self {
        let mut builder = CircuitBuilder::<F, D>::new(CircuitConfig::default());
        let main_validation_proof =
            main_validation_circut.add_proof_target_and_verify(&mut builder);
        let block_pis =
            MainValidationPublicInputsTarget::from_vec(&main_validation_proof.public_inputs);
        let transition_target = ValidityTransitionTarget::new(
            account_registoration_circuit,
            account_update_circuit,
            &mut builder,
        );
        let prev_pis = ValidityPublicInputsTarget::new(&mut builder, false);

        // connect prev_pis to transition_target.prev_block_pis
        let prev_block_pis = transition_target.prev_block_pis.clone();
        prev_pis
            .account_tree_root
            .connect(&mut builder, prev_block_pis.account_tree_root);
        prev_pis
            .block_hash_tree_root
            .connect(&mut builder, transition_target.prev_block_tree_root);
        prev_pis
            .block_hash
            .connect(&mut builder, prev_block_pis.block_hash);
        prev_pis
            .tx_tree_root
            .connect(&mut builder, prev_block_pis.tx_tree_root);
        prev_pis
            .sender_tree_root
            .connect(&mut builder, prev_block_pis.sender_tree_root);
        builder.connect(prev_pis.block_number, prev_block_pis.block_number);
        builder.connect(
            prev_pis.is_registoration_block.target,
            prev_block_pis.is_registoration_block.target,
        );
        builder.connect(
            prev_pis.is_valid_block.target,
            prev_block_pis.is_valid.target,
        );

        // connect block_pis to transition_target
        block_pis
            .account_tree_root
            .connect(&mut builder, transition_target.new_account_tree_root);
        block_pis
            .prev_block_hash
            .connect(&mut builder, prev_pis.block_hash);

        let new_pis = ValidityPublicInputsTarget {
            account_tree_root: transition_target.new_account_tree_root,
            block_hash_tree_root: transition_target.new_block_tree_root,
            block_hash: block_pis.block_hash,
            tx_tree_root: block_pis.tx_tree_root,
            sender_tree_root: block_pis.sender_tree_root,
            block_number: block_pis.block_number,
            is_registoration_block: block_pis.is_registoration_block,
            is_valid_block: block_pis.is_valid,
        };

        let concat_pis = vec![prev_pis.to_vec(), new_pis.to_vec()].concat();
        builder.register_public_inputs(&concat_pis);

        let data = builder.build::<C>();

        Self {
            data,
            main_validation_proof,
            transition_target,
            prev_pis,
            new_pis,
        }
    }
}

impl<F, C, const D: usize> TransitionWrapperCircuit<F, C, D>
where
    F: RichField + Extendable<D>,
    C: GenericConfig<D, F = F> + 'static,
    C::Hasher: AlgebraicHasher<F>,
{
    pub fn prove(
        &self,
        main_validation_proof: &ProofWithPublicInputs<F, C, D>,
        transition_value: &ValidityTransitionValue<F, C, D>,
        prev_pis: &ValidityPublicInputs,
        account_registoration_proof_dummy: DummyProof<F, C, D>,
        account_update_proof_dummy: DummyProof<F, C, D>,
    ) -> Result<ProofWithPublicInputs<F, C, D>> {
        let mut pw = PartialWitness::<F>::new();
        self.transition_target.set_witness(
            &mut pw,
            account_registoration_proof_dummy,
            account_update_proof_dummy,
            transition_value,
        );
        self.prev_pis.set_witness(&mut pw, prev_pis);
        pw.set_proof_with_pis_target(&self.main_validation_proof, main_validation_proof);
        self.data.prove(pw)
    }
}

impl<F, C, const D: usize> Recursivable<F, C, D> for TransitionWrapperCircuit<F, C, D>
where
    F: RichField + Extendable<D>,
    C: GenericConfig<D, F = F> + 'static,
    C::Hasher: AlgebraicHasher<F>,
{
    fn circuit_data(&self) -> &CircuitData<F, C, D> {
        &self.data
    }
}
