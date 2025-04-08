use plonky2::{
    field::extension::Extendable,
    hash::hash_types::RichField,
    iop::{target::Target, witness::Witness},
    plonk::{
        circuit_builder::CircuitBuilder,
        circuit_data::VerifierCircuitData,
        config::{AlgebraicHasher, GenericConfig},
        proof::{ProofWithPublicInputs, ProofWithPublicInputsTarget},
    },
};

use crate::{
    circuits::validity::{
        block_validation::main_validation::{
            MainValidationPublicInputs, MainValidationPublicInputsTarget,
        },
        transition::account_transition_pis::AccountTransitionPublicInputs,
    },
    common::trees::block_hash_tree::{BlockHashMerkleProof, BlockHashMerkleProofTarget},
    constants::BLOCK_HASH_TREE_HEIGHT,
    ethereum_types::{
        bytes32::{Bytes32, Bytes32Target},
        u32limb_trait::U32LimbTargetTrait as _,
    },
    utils::{
        conversion::ToU64,
        dummy::DummyProof,
        poseidon_hash_out::{PoseidonHashOut, PoseidonHashOutTarget},
        recursively_verifiable::add_proof_target_and_conditionally_verify,
    },
};

use super::{
    account_registration::AccountRegistrationCircuit,
    account_transition_pis::AccountTransitionPublicInputsTarget,
    account_update::AccountUpdateCircuit, error::ValidityTransitionError,
};

pub(crate) struct ValidityTransitionValue<
    F: RichField + Extendable<D>,
    C: GenericConfig<D, F = F>,
    const D: usize,
> {
    pub(crate) main_validation_pis: MainValidationPublicInputs,
    pub(crate) prev_block_tree_root: PoseidonHashOut,
    pub(crate) new_block_tree_root: PoseidonHashOut,
    pub(crate) prev_account_tree_root: PoseidonHashOut,
    pub(crate) prev_next_account_id: u64,
    pub(crate) new_account_tree_root: PoseidonHashOut,
    pub(crate) new_next_account_id: u64,
    pub(crate) account_registration_proof: Option<ProofWithPublicInputs<F, C, D>>,
    pub(crate) account_update_proof: Option<ProofWithPublicInputs<F, C, D>>,
    pub(crate) block_merkle_proof: BlockHashMerkleProof,
}

impl<F: RichField + Extendable<D>, C: GenericConfig<D, F = F>, const D: usize>
    ValidityTransitionValue<F, C, D>
{
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn new(
        account_registration_circuit: &AccountRegistrationCircuit<F, C, D>,
        account_update_circuit: &AccountUpdateCircuit<F, C, D>,
        main_validation_pis: MainValidationPublicInputs,
        prev_account_tree_root: PoseidonHashOut,
        prev_next_account_id: u64,
        prev_block_tree_root: PoseidonHashOut,
        account_registration_proof: Option<ProofWithPublicInputs<F, C, D>>,
        account_update_proof: Option<ProofWithPublicInputs<F, C, D>>,
        block_merkle_proof: BlockHashMerkleProof,
    ) -> Result<Self, ValidityTransitionError> {
        // account registration
        let is_account_registration =
            main_validation_pis.is_registration_block && main_validation_pis.is_valid;
        let mut new_account_tree_root = prev_account_tree_root;
        let mut new_next_account_id = prev_next_account_id;
        if is_account_registration {
            let account_registration_proof = account_registration_proof
                .clone()
                .ok_or(ValidityTransitionError::MissingAccountRegistrationProof)?;

            account_registration_circuit
                .data
                .verify(account_registration_proof.clone())
                .map_err(|e| {
                    ValidityTransitionError::InvalidAccountRegistrationProof(format!(
                        "Account registration proof verification failed: {}",
                        e
                    ))
                })?;

            let pis = AccountTransitionPublicInputs::from_u64_slice(
                &account_registration_proof.public_inputs.to_u64_vec(),
            )
            .map_err(|e| {
                ValidityTransitionError::InvalidAccountRegistrationProof(format!(
                    "Failed to parse account registration public inputs: {}",
                    e
                ))
            })?;

            if pis.prev_account_tree_root != prev_account_tree_root {
                return Err(ValidityTransitionError::PrevAccountTreeRootMismatch {
                    expected: prev_account_tree_root,
                    actual: pis.prev_account_tree_root,
                });
            }

            if pis.prev_next_account_id != new_next_account_id {
                return Err(ValidityTransitionError::AccountIdMismatch {
                    expected: new_next_account_id,
                    actual: pis.prev_next_account_id,
                });
            }

            if pis.sender_tree_root != main_validation_pis.sender_tree_root {
                return Err(ValidityTransitionError::SenderTreeRootMismatch {
                    expected: main_validation_pis.sender_tree_root,
                    actual: pis.sender_tree_root,
                });
            }

            if pis.block_number != main_validation_pis.block_number {
                return Err(ValidityTransitionError::BlockNumberMismatch {
                    expected: main_validation_pis.block_number,
                    actual: pis.block_number,
                });
            }

            new_account_tree_root = pis.new_account_tree_root;
            new_next_account_id = pis.new_next_account_id;
        }

        let is_account_update =
            (!main_validation_pis.is_registration_block) && main_validation_pis.is_valid;
        if is_account_update {
            let account_update_proof = account_update_proof
                .clone()
                .ok_or(ValidityTransitionError::MissingAccountUpdateProof)?;

            account_update_circuit
                .data
                .verify(account_update_proof.clone())
                .map_err(|e| {
                    ValidityTransitionError::InvalidAccountUpdateProof(format!(
                        "Account update proof verification failed: {}",
                        e
                    ))
                })?;

            let pis = AccountTransitionPublicInputs::from_u64_slice(
                &account_update_proof
                    .public_inputs
                    .iter()
                    .map(|x| x.to_canonical_u64())
                    .collect::<Vec<_>>(),
            )
            .map_err(|e| {
                ValidityTransitionError::InvalidAccountUpdateProof(format!(
                    "Failed to parse account update public inputs: {}",
                    e
                ))
            })?;

            if pis.prev_account_tree_root != prev_account_tree_root {
                return Err(ValidityTransitionError::PrevAccountTreeRootMismatch {
                    expected: prev_account_tree_root,
                    actual: pis.prev_account_tree_root,
                });
            }

            if pis.prev_next_account_id != new_next_account_id {
                return Err(ValidityTransitionError::AccountIdMismatch {
                    expected: new_next_account_id,
                    actual: pis.prev_next_account_id,
                });
            }

            if pis.sender_tree_root != main_validation_pis.sender_tree_root {
                return Err(ValidityTransitionError::SenderTreeRootMismatch {
                    expected: main_validation_pis.sender_tree_root,
                    actual: pis.sender_tree_root,
                });
            }

            if pis.block_number != main_validation_pis.block_number {
                return Err(ValidityTransitionError::BlockNumberMismatch {
                    expected: main_validation_pis.block_number,
                    actual: pis.block_number,
                });
            }

            new_account_tree_root = pis.new_account_tree_root;
            new_next_account_id = pis.new_next_account_id;
        }

        // block hash tree update
        let block_number = main_validation_pis.block_number;
        block_merkle_proof
            .verify(
                &Bytes32::default(),
                block_number as u64,
                prev_block_tree_root,
            )
            .map_err(|e| {
                ValidityTransitionError::InvalidBlockHashMerkleProof(format!(
                    "Block hash merkle proof verification failed: {}",
                    e
                ))
            })?;

        let new_block_tree_root =
            block_merkle_proof.get_root(&main_validation_pis.block_hash, block_number as u64);

        Ok(Self {
            main_validation_pis,
            prev_block_tree_root,
            prev_next_account_id,
            new_block_tree_root,
            new_next_account_id,
            prev_account_tree_root,
            new_account_tree_root,
            account_registration_proof,
            account_update_proof,
            block_merkle_proof,
        })
    }
}

#[derive(Debug, Clone)]
pub(crate) struct ValidityTransitionTarget<const D: usize> {
    pub(crate) main_validation_pis: MainValidationPublicInputsTarget,
    pub(crate) prev_block_tree_root: PoseidonHashOutTarget,
    pub(crate) new_block_tree_root: PoseidonHashOutTarget,
    pub(crate) prev_account_tree_root: PoseidonHashOutTarget,
    pub(crate) prev_next_account_id: Target,
    pub(crate) new_account_tree_root: PoseidonHashOutTarget,
    pub(crate) new_next_account_id: Target,
    pub(crate) account_registration_proof: ProofWithPublicInputsTarget<D>,
    pub(crate) account_update_proof: ProofWithPublicInputsTarget<D>,
    pub(crate) block_merkle_proof: BlockHashMerkleProofTarget,
}

impl<const D: usize> ValidityTransitionTarget<D> {
    pub(crate) fn new<F: RichField + Extendable<D>, C: GenericConfig<D, F = F> + 'static>(
        account_registration_verifier_data: &VerifierCircuitData<F, C, D>,
        account_update_verifier_data: &VerifierCircuitData<F, C, D>,
        builder: &mut CircuitBuilder<F, D>,
    ) -> Self
    where
        C::Hasher: AlgebraicHasher<F>,
    {
        // prev_pis already exists, so there is no need to check the ranges.
        let main_validation_pis = MainValidationPublicInputsTarget::new(builder, false);
        let prev_account_tree_root = PoseidonHashOutTarget::new(builder);
        let prev_next_account_id = builder.add_virtual_target();
        let prev_block_tree_root = PoseidonHashOutTarget::new(builder);
        let block_merkle_proof = BlockHashMerkleProofTarget::new(builder, BLOCK_HASH_TREE_HEIGHT);

        let mut new_account_tree_root = prev_account_tree_root;
        let mut new_next_account_id = prev_next_account_id;
        // account registration
        let is_account_registration = builder.and(
            main_validation_pis.is_registration_block,
            main_validation_pis.is_valid,
        );
        let account_registration_proof = add_proof_target_and_conditionally_verify(
            account_registration_verifier_data,
            builder,
            is_account_registration,
        );
        let account_registration_pis = AccountTransitionPublicInputsTarget::from_slice(
            &account_registration_proof.public_inputs,
        )
        .expect("Failed to parse account registration public inputs target");

        account_registration_pis
            .prev_account_tree_root
            .conditional_assert_eq(builder, prev_account_tree_root, is_account_registration);
        builder.conditional_assert_eq(
            is_account_registration.target,
            account_registration_pis.prev_next_account_id,
            prev_next_account_id,
        );
        account_registration_pis
            .sender_tree_root
            .conditional_assert_eq(
                builder,
                main_validation_pis.sender_tree_root,
                is_account_registration,
            );
        builder.conditional_assert_eq(
            is_account_registration.target,
            account_registration_pis.block_number,
            main_validation_pis.block_number,
        );
        new_account_tree_root = PoseidonHashOutTarget::select(
            builder,
            is_account_registration,
            account_registration_pis.new_account_tree_root,
            new_account_tree_root,
        );
        new_next_account_id = builder.select(
            is_account_registration,
            account_registration_pis.new_next_account_id,
            new_next_account_id,
        );
        // account update
        let is_not_prev_registration_block = builder.not(main_validation_pis.is_registration_block);
        let is_account_update =
            builder.and(is_not_prev_registration_block, main_validation_pis.is_valid);
        let account_update_proof = add_proof_target_and_conditionally_verify(
            account_update_verifier_data,
            builder,
            is_account_update,
        );
        let account_update_pis =
            AccountTransitionPublicInputsTarget::from_slice(&account_update_proof.public_inputs)
                .expect("Failed to parse account update public inputs target");

        account_update_pis
            .prev_account_tree_root
            .conditional_assert_eq(builder, prev_account_tree_root, is_account_update);
        builder.conditional_assert_eq(
            is_account_update.target,
            account_update_pis.prev_next_account_id,
            prev_next_account_id,
        );
        account_update_pis.sender_tree_root.conditional_assert_eq(
            builder,
            main_validation_pis.sender_tree_root,
            is_account_update,
        );
        builder.conditional_assert_eq(
            is_account_update.target,
            account_update_pis.block_number,
            main_validation_pis.block_number,
        );
        new_account_tree_root = PoseidonHashOutTarget::select(
            builder,
            is_account_update,
            account_update_pis.new_account_tree_root,
            new_account_tree_root,
        );
        new_next_account_id = builder.select(
            is_account_update,
            account_update_pis.new_next_account_id,
            new_next_account_id,
        );

        let block_number = main_validation_pis.block_number;
        let empty_leaf = Bytes32Target::zero::<F, D, Bytes32>(builder);
        block_merkle_proof.verify::<F, C, D>(
            builder,
            &empty_leaf,
            block_number,
            prev_block_tree_root,
        );
        let new_block_tree_root = block_merkle_proof.get_root::<F, C, D>(
            builder,
            &main_validation_pis.block_hash,
            block_number,
        );

        Self {
            main_validation_pis,
            prev_account_tree_root,
            prev_next_account_id,
            prev_block_tree_root,
            new_block_tree_root,
            new_account_tree_root,
            new_next_account_id,
            account_registration_proof,
            account_update_proof,
            block_merkle_proof,
        }
    }

    pub(crate) fn set_witness<
        F: RichField + Extendable<D>,
        C: GenericConfig<D, F = F>,
        W: Witness<F>,
    >(
        &self,
        witness: &mut W,
        account_registration_proof_dummy: DummyProof<F, C, D>,
        account_update_proof_dummy: DummyProof<F, C, D>,
        value: &ValidityTransitionValue<F, C, D>,
    ) where
        <C as GenericConfig<D>>::Hasher: AlgebraicHasher<F>,
    {
        self.main_validation_pis
            .set_witness(witness, &value.main_validation_pis);
        self.prev_account_tree_root
            .set_witness(witness, value.prev_account_tree_root);
        witness.set_target(
            self.prev_next_account_id,
            F::from_canonical_u64(value.prev_next_account_id),
        );
        self.prev_block_tree_root
            .set_witness(witness, value.prev_block_tree_root);
        self.new_account_tree_root
            .set_witness(witness, value.new_account_tree_root);
        witness.set_target(
            self.new_next_account_id,
            F::from_canonical_u64(value.new_next_account_id),
        );
        self.new_block_tree_root
            .set_witness(witness, value.new_block_tree_root);
        let account_registration_proof = value
            .account_registration_proof
            .clone()
            .unwrap_or(account_registration_proof_dummy.proof);
        witness.set_proof_with_pis_target(
            &self.account_registration_proof,
            &account_registration_proof,
        );
        let account_update_proof = value
            .account_update_proof
            .clone()
            .unwrap_or(account_update_proof_dummy.proof);
        witness.set_proof_with_pis_target(&self.account_update_proof, &account_update_proof);
        self.block_merkle_proof
            .set_witness(witness, &value.block_merkle_proof);
    }
}

#[cfg(test)]
mod tests {
    use plonky2::{
        field::goldilocks_field::GoldilocksField,
        iop::witness::PartialWitness,
        plonk::{
            circuit_builder::CircuitBuilder, circuit_data::CircuitConfig,
            config::PoseidonGoldilocksConfig,
        },
    };
    use rand::Rng as _;

    use crate::{
        circuits::{
            test_utils::witness_generator::{construct_validity_and_tx_witness, MockTxRequest},
            validity::{
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

    use super::ValidityTransitionTarget;

    type F = GoldilocksField;
    const D: usize = 2;
    type C = PoseidonGoldilocksConfig;

    #[test]
    fn test_validity_transition_circuit_registration_block() {
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
        )
        .unwrap();
        let block_witness = validity_witness.block_witness.clone();
        let validity_transition_witness = validity_witness.validity_transition_witness.clone();

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

        let mut builder = CircuitBuilder::<F, D>::new(CircuitConfig::default());
        let target = ValidityTransitionTarget::new(
            &account_registration_circuit.data.verifier_data(),
            &account_update_circuit.data.verifier_data(),
            &mut builder,
        );

        let data = builder.build::<C>();
        let mut pw = PartialWitness::new();
        target.set_witness(
            &mut pw,
            account_registration_circuit.dummy_proof.clone(),
            account_update_circuit.dummy_proof.clone(),
            &validity_transition_value,
        );
        let proof = data.prove(pw).unwrap();
        data.verify(proof.clone()).unwrap();
    }

    #[test]
    fn test_validity_transition_circuit_non_registration_block() {
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
        )
        .unwrap();
        let block_witness = validity_witness.block_witness.clone();
        let validity_transition_witness = validity_witness.validity_transition_witness.clone();

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

        let mut builder = CircuitBuilder::<F, D>::new(CircuitConfig::default());
        let target = ValidityTransitionTarget::new(
            &account_registration_circuit.data.verifier_data(),
            &account_update_circuit.data.verifier_data(),
            &mut builder,
        );

        let data = builder.build::<C>();
        let mut pw = PartialWitness::new();
        target.set_witness(
            &mut pw,
            account_registration_circuit.dummy_proof.clone(),
            account_update_circuit.dummy_proof.clone(),
            &validity_transition_value,
        );
        let proof = data.prove(pw).unwrap();
        data.verify(proof.clone()).unwrap();
    }
}
