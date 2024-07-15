use plonky2::{
    field::extension::Extendable,
    hash::hash_types::RichField,
    iop::{target::Target, witness::Witness},
    plonk::{
        circuit_builder::CircuitBuilder,
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
    ethereum_types::{bytes32::Bytes32, u32limb_trait::U32LimbTargetTrait as _},
    utils::{
        conversion::ToU64,
        dummy::DummyProof,
        poseidon_hash_out::{PoseidonHashOut, PoseidonHashOutTarget},
        recursivable::Recursivable,
    },
};

use super::{
    account_registoration::AccountRegistorationCircuit,
    account_transition_pis::AccountTransitionPublicInputsTarget,
    account_update::AccountUpdateCircuit,
};

pub struct ValidityTransitionValue<
    F: RichField + Extendable<D>,
    C: GenericConfig<D, F = F>,
    const D: usize,
> {
    pub block_pis: MainValidationPublicInputs,
    pub prev_block_tree_root: PoseidonHashOut,
    pub new_block_tree_root: PoseidonHashOut,
    pub prev_account_tree_root: PoseidonHashOut,
    pub new_account_tree_root: PoseidonHashOut,
    pub account_registoration_proof: Option<ProofWithPublicInputs<F, C, D>>,
    pub account_update_proof: Option<ProofWithPublicInputs<F, C, D>>,
    pub block_hash_merkle_proof: BlockHashMerkleProof,
}

impl<F: RichField + Extendable<D>, C: GenericConfig<D, F = F>, const D: usize>
    ValidityTransitionValue<F, C, D>
{
    pub fn new(
        account_registoration_circuit: &AccountRegistorationCircuit<F, C, D>,
        account_update_circuit: &AccountUpdateCircuit<F, C, D>,
        block_pis: MainValidationPublicInputs,
        prev_account_tree_root: PoseidonHashOut,
        prev_block_tree_root: PoseidonHashOut,
        account_registoration_proof: Option<ProofWithPublicInputs<F, C, D>>,
        account_update_proof: Option<ProofWithPublicInputs<F, C, D>>,
        block_hash_merkle_proof: BlockHashMerkleProof,
    ) -> Self {
        // account registoration
        let is_account_registoration = block_pis.is_registoration_block && block_pis.is_valid;
        let mut new_account_tree_root = prev_account_tree_root;
        if is_account_registoration {
            let account_registoration_proof = account_registoration_proof
                .clone()
                .expect("Account registoration proof is missing");
            account_registoration_circuit
                .data
                .verify(account_registoration_proof.clone())
                .expect("Account registoration proof is invalid");
            let pis = AccountTransitionPublicInputs::from_u64_vec(
                &account_registoration_proof.public_inputs.to_u64_vec(),
            );
            assert_eq!(pis.prev_account_tree_root, prev_account_tree_root);
            assert_eq!(pis.sender_tree_root, block_pis.sender_tree_root);
            assert_eq!(pis.block_number, block_pis.block_number);
            new_account_tree_root = pis.new_account_tree_root;
        }

        let is_account_update = (!block_pis.is_registoration_block) && block_pis.is_valid;
        if is_account_update {
            let account_update_proof = account_update_proof
                .clone()
                .expect("Account update proof is missing");
            account_update_circuit
                .data
                .verify(account_update_proof.clone())
                .expect("Account update proof is invalid");
            let pis = AccountTransitionPublicInputs::from_u64_vec(
                &account_update_proof
                    .public_inputs
                    .iter()
                    .map(|x| x.to_canonical_u64())
                    .collect::<Vec<_>>(),
            );
            assert_eq!(pis.prev_account_tree_root, prev_account_tree_root);
            assert_eq!(pis.sender_tree_root, block_pis.sender_tree_root);
            assert_eq!(pis.block_number, block_pis.block_number);
            new_account_tree_root = pis.new_account_tree_root;
        }

        // block hash tree update
        let block_number = block_pis.block_number;
        block_hash_merkle_proof
            .verify(
                &Bytes32::default(),
                block_number as usize,
                prev_block_tree_root,
            )
            .expect("Block hash merkle proof is invalid");
        let new_block_tree_root =
            block_hash_merkle_proof.get_root(&block_pis.block_hash, block_number as usize);

        Self {
            block_pis,
            prev_block_tree_root,
            new_block_tree_root,
            prev_account_tree_root,
            new_account_tree_root,
            account_registoration_proof,
            account_update_proof,
            block_hash_merkle_proof,
        }
    }
}

pub struct ValidityTransitionTarget<const D: usize> {
    pub block_pis: MainValidationPublicInputsTarget,
    pub prev_block_tree_root: PoseidonHashOutTarget,
    pub new_block_tree_root: PoseidonHashOutTarget,
    pub prev_account_tree_root: PoseidonHashOutTarget,
    pub new_account_tree_root: PoseidonHashOutTarget,
    pub account_registoration_proof: ProofWithPublicInputsTarget<D>,
    pub account_update_proof: ProofWithPublicInputsTarget<D>,
    pub block_hash_merkle_proof: BlockHashMerkleProofTarget,
}

impl<const D: usize> ValidityTransitionTarget<D> {
    pub fn new<F: RichField + Extendable<D>, C: GenericConfig<D, F = F> + 'static>(
        account_registoration_circuit: &AccountRegistorationCircuit<F, C, D>,
        account_update_circuit: &AccountUpdateCircuit<F, C, D>,
        builder: &mut CircuitBuilder<F, D>,
    ) -> Self
    where
        C::Hasher: AlgebraicHasher<F>,
    {
        // prev_pis already exists, so there is no need to check the ranges.
        let block_pis = MainValidationPublicInputsTarget::new(builder, false);
        let prev_account_tree_root = PoseidonHashOutTarget::new(builder);
        let prev_block_tree_root = PoseidonHashOutTarget::new(builder);
        let block_hash_merkle_proof =
            BlockHashMerkleProofTarget::new(builder, BLOCK_HASH_TREE_HEIGHT);

        let mut new_account_tree_root = prev_account_tree_root;
        // account registoration
        let is_account_registoration =
            builder.and(block_pis.is_registoration_block, block_pis.is_valid);
        let account_registoration_proof = account_registoration_circuit
            .add_proof_target_and_conditionally_verify(builder, is_account_registoration);
        let account_registoration_pis = AccountTransitionPublicInputsTarget::from_vec(
            &account_registoration_proof.public_inputs,
        );
        account_registoration_pis
            .prev_account_tree_root
            .conditional_assert_eq(builder, prev_account_tree_root, is_account_registoration);
        account_registoration_pis
            .sender_tree_root
            .conditional_assert_eq(
                builder,
                block_pis.sender_tree_root,
                is_account_registoration,
            );
        builder.conditional_assert_eq(
            is_account_registoration.target,
            account_registoration_pis.block_number,
            block_pis.block_number,
        );
        new_account_tree_root = PoseidonHashOutTarget::select(
            builder,
            is_account_registoration,
            account_registoration_pis.new_account_tree_root,
            new_account_tree_root,
        );
        // account update
        let is_not_prev_registoration_block = builder.not(block_pis.is_registoration_block);
        let is_account_update = builder.and(is_not_prev_registoration_block, block_pis.is_valid);
        let account_update_proof = account_update_circuit
            .add_proof_target_and_conditionally_verify(builder, is_account_update);
        let account_update_pis =
            AccountTransitionPublicInputsTarget::from_vec(&account_update_proof.public_inputs);
        account_update_pis
            .prev_account_tree_root
            .conditional_assert_eq(builder, prev_account_tree_root, is_account_update);
        account_update_pis.sender_tree_root.conditional_assert_eq(
            builder,
            block_pis.sender_tree_root,
            is_account_update,
        );
        builder.conditional_assert_eq(
            is_account_update.target,
            account_update_pis.block_number,
            block_pis.block_number,
        );
        new_account_tree_root = PoseidonHashOutTarget::select(
            builder,
            is_account_update,
            account_update_pis.new_account_tree_root,
            new_account_tree_root,
        );

        let prev_block_number = block_pis.block_number;
        let empty_leaf = Bytes32::<Target>::zero::<F, D, Bytes32<u32>>(builder);
        block_hash_merkle_proof.verify::<F, C, D>(
            builder,
            &empty_leaf,
            prev_block_number,
            prev_block_tree_root,
        );
        let new_block_tree_root = block_hash_merkle_proof.get_root::<F, C, D>(
            builder,
            &block_pis.block_hash,
            prev_block_number,
        );

        Self {
            block_pis,
            prev_account_tree_root,
            prev_block_tree_root,
            new_block_tree_root,
            new_account_tree_root,
            account_registoration_proof,
            account_update_proof,
            block_hash_merkle_proof,
        }
    }

    pub fn set_witness<F: RichField + Extendable<D>, C: GenericConfig<D, F = F>, W: Witness<F>>(
        &self,
        witness: &mut W,
        account_registoration_proof_dummy: DummyProof<F, C, D>,
        account_update_proof_dummy: DummyProof<F, C, D>,
        value: &ValidityTransitionValue<F, C, D>,
    ) where
        <C as GenericConfig<D>>::Hasher: AlgebraicHasher<F>,
    {
        self.block_pis.set_witness(witness, &value.block_pis);
        self.prev_account_tree_root
            .set_witness(witness, value.prev_account_tree_root);
        self.prev_block_tree_root
            .set_witness(witness, value.prev_block_tree_root);
        self.new_account_tree_root
            .set_witness(witness, value.new_account_tree_root);
        self.new_block_tree_root
            .set_witness(witness, value.new_block_tree_root);
        let account_registoration_proof = value
            .account_registoration_proof
            .clone()
            .unwrap_or(account_registoration_proof_dummy.proof);
        witness.set_proof_with_pis_target(
            &self.account_registoration_proof,
            &account_registoration_proof,
        );
        let account_update_proof = value
            .account_update_proof
            .clone()
            .unwrap_or(account_update_proof_dummy.proof);
        witness.set_proof_with_pis_target(&self.account_update_proof, &account_update_proof);
        self.block_hash_merkle_proof
            .set_witness(witness, &value.block_hash_merkle_proof);
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

    use crate::{
        circuits::validity::transition::{
            account_registoration::{AccountRegistorationCircuit, AccountRegistorationValue},
            account_update::AccountUpdateCircuit,
            transition::{ValidityTransitionTarget, ValidityTransitionValue},
        },
        mock::block_builder::MockBlockBuilder,
        test_utils::tx::generate_random_tx_requests,
    };

    type F = GoldilocksField;
    const D: usize = 2;
    type C = PoseidonGoldilocksConfig;

    #[test]
    fn validity_transition() {
        let mut rng = rand::thread_rng();
        let mut block_builder = MockBlockBuilder::new();
        let validity_witness =
            block_builder.post_block(true, generate_random_tx_requests(&mut rng));

        let account_registoration_circuit = AccountRegistorationCircuit::<F, C, D>::new();
        let account_update_circuit = AccountUpdateCircuit::<F, C, D>::new();

        let block_pis = validity_witness.block_witness.to_main_validation_pis();
        let prev_block_tree_root = validity_witness.block_witness.prev_block_tree_root;
        let prev_account_tree_root = validity_witness.block_witness.prev_account_tree_root;
        let transition_witness = validity_witness.validity_transition_witness.clone();
        let account_registoration_value = AccountRegistorationValue::new(
            prev_account_tree_root,
            block_pis.block_number,
            transition_witness.sender_leaves,
            transition_witness
                .account_registoration_proofs
                .clone()
                .unwrap(),
        );
        let account_registoration_proof = account_registoration_circuit
            .prove(&account_registoration_value)
            .unwrap();

        let value = ValidityTransitionValue::new(
            &account_registoration_circuit,
            &account_update_circuit,
            block_pis,
            prev_account_tree_root,
            prev_block_tree_root,
            Some(account_registoration_proof),
            None,
            transition_witness.block_merkle_proof,
        );

        let mut builder = CircuitBuilder::<F, D>::new(CircuitConfig::default());
        let target = ValidityTransitionTarget::new(
            &account_registoration_circuit,
            &account_update_circuit,
            &mut builder,
        );

        let data = builder.build::<C>();
        let mut pw = PartialWitness::new();
        target.set_witness(
            &mut pw,
            account_registoration_circuit.dummy_proof.clone(),
            account_update_circuit.dummy_proof.clone(),
            &value,
        );
        let _proof = data.prove(pw).unwrap();
    }
}
