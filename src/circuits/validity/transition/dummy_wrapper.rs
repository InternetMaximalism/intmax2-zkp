//! Dummy wrapper circuit for validity transition.
//!
//! This module provides a dummy implementation of the transition wrapper circuit that is
//! primarily used for testing purposes. It creates a simplified proof circuit that skips
//! the constraints of validity proof when you don't need the full validation for testing.

use crate::circuits::validity::transition::error::ValidityTransitionError;
use plonky2::{
    field::extension::Extendable,
    hash::hash_types::RichField,
    iop::witness::PartialWitness,
    plonk::{
        circuit_builder::CircuitBuilder,
        circuit_data::{CircuitConfig, CircuitData},
        config::{AlgebraicHasher, GenericConfig},
        proof::ProofWithPublicInputs,
    },
};

use crate::{
    circuits::validity::validity_pis::{ValidityPublicInputs, ValidityPublicInputsTarget},
    common::witness::validity_witness::ValidityWitness,
};

/// A dummy implementation of the transition wrapper circuit used for testing balance proof.
///
/// This circuit is mainly used for testing purposes when you want to use a simplified proof
/// circuit that skips the constraints of validity proof. It provides a lightweight alternative
/// to the full transition wrapper circuit when full validation is not needed for testing.
#[derive(Debug)]
pub struct DummyValidityTransitionWrapperCircuit<F, C, const D: usize>
where
    F: RichField + Extendable<D>,
    C: GenericConfig<D, F = F>,
{
    pub(crate) data: CircuitData<F, C, D>,
    pub prev_pis: ValidityPublicInputsTarget,
    pub new_pis: ValidityPublicInputsTarget,
}

impl<F, C, const D: usize> Default for DummyValidityTransitionWrapperCircuit<F, C, D>
where
    F: RichField + Extendable<D>,
    C: GenericConfig<D, F = F> + 'static,
    C::Hasher: AlgebraicHasher<F>,
{
    fn default() -> Self {
        Self::new()
    }
}

impl<F, C, const D: usize> DummyValidityTransitionWrapperCircuit<F, C, D>
where
    F: RichField + Extendable<D>,
    C: GenericConfig<D, F = F> + 'static,
    C::Hasher: AlgebraicHasher<F>,
{
    pub fn new() -> Self {
        let mut builder = CircuitBuilder::<F, D>::new(CircuitConfig::default());
        let prev_pis = ValidityPublicInputsTarget::new(&mut builder, false);
        let new_pis = ValidityPublicInputsTarget::new(&mut builder, false);
        let concat_pis = [prev_pis.to_vec(), new_pis.to_vec()].concat();
        builder.register_public_inputs(&concat_pis);
        let data = builder.build::<C>();
        Self {
            data,
            prev_pis,
            new_pis,
        }
    }
}

impl<F, C, const D: usize> DummyValidityTransitionWrapperCircuit<F, C, D>
where
    F: RichField + Extendable<D>,
    C: GenericConfig<D, F = F> + 'static,
    C::Hasher: AlgebraicHasher<F>,
{
    /// Generates a proof using the dummy transition wrapper circuit.
    ///
    /// This method creates a simplified proof that skips the constraints of validity proof,
    /// while still performing basic validation of the inputs. It's useful for testing
    /// balance proofs without the overhead of full validity constraints.
    ///
    /// # Arguments
    /// * `prev_pis` - The previous validity public inputs
    /// * `validity_witness` - The validity witness containing the transition data
    ///
    /// # Returns
    /// A proof that can be used for testing purposes
    pub fn prove(
        &self,
        prev_pis: &ValidityPublicInputs,
        validity_witness: &ValidityWitness,
    ) -> Result<ProofWithPublicInputs<F, C, D>, ValidityTransitionError> {
        let new_pis = validity_witness.to_validity_pis().map_err(|e| {
            ValidityTransitionError::InvalidValidityWitness(format!(
                "Failed to convert validity witness to validity public inputs: {}",
                e
            ))
        })?;

        // Validate inputs
        if prev_pis.public_state.account_tree_root
            != validity_witness.block_witness.prev_account_tree_root
        {
            return Err(ValidityTransitionError::PrevAccountTreeRootMismatch {
                expected: prev_pis.public_state.account_tree_root,
                actual: validity_witness.block_witness.prev_account_tree_root,
            });
        }

        if prev_pis.public_state.block_tree_root
            != validity_witness.block_witness.prev_block_tree_root
        {
            return Err(ValidityTransitionError::BlockTreeRootMismatch {
                expected: prev_pis.public_state.block_tree_root,
                actual: validity_witness.block_witness.prev_block_tree_root,
            });
        }

        let mut pw = PartialWitness::<F>::new();
        self.prev_pis.set_witness(&mut pw, prev_pis);
        self.new_pis.set_witness(&mut pw, &new_pis);
        self.data.prove(pw).map_err(|e| {
            ValidityTransitionError::ProofGenerationError(format!("Failed to prove: {}", e))
        })
    }
}
