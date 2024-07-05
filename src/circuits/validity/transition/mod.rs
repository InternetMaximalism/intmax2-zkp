use account_registoration::AccountRegistorationCircuit;
use account_transition_pis::{AccountTransitionPublicInputs, AccountTransitionPublicInputsTarget};
use plonky2::{
    field::extension::Extendable,
    hash::hash_types::RichField,
    iop::witness::{PartialWitness, Witness},
    plonk::{
        circuit_builder::CircuitBuilder,
        circuit_data::{CircuitConfig, CircuitData},
        config::{AlgebraicHasher, GenericConfig},
        proof::{ProofWithPublicInputs, ProofWithPublicInputsTarget},
    },
};

pub mod account_registoration;
pub mod account_transition_pis;
pub mod account_update;

// use crate::{
//     circuits::validity::block_validation::main_validation::MainValidationPublicInputsTarget,
//     common::trees::block_hash_tree::{BlockHashMerkleProof, BlockHashMerkleProofTarget},
//     constants::BLOCK_HASH_TREE_HEIGHT,
//     ethereum_types::{bytes32::Bytes32, u32limb_trait::U32LimbTargetTrait as _},
//     utils::{
//         dummy::DummyProof,
//         logic::BuilderLogic,
//         poseidon_hash_out::{PoseidonHashOut, PoseidonHashOutTarget},
//         recursivable::Recursivable,
//     },
// };

// use super::{
//     block_validation::main_validation::MainValidationPublicInputs,
//     validity_pis::{ValidityPublicInputs, ValidityPublicInputsTarget},
// };

// pub struct ValidityTransitionValue<
//     F: RichField + Extendable<D>,
//     C: GenericConfig<D, F = F>,
//     const D: usize,
// > {
//     pub prev_block_pis: MainValidationPublicInputs,
//     pub prev_block_tree_root: PoseidonHashOut,
//     pub new_block_tree_root: PoseidonHashOut,
//     pub prev_account_tree_root: PoseidonHashOut,
//     pub new_account_tree_root: PoseidonHashOut,
//     pub account_registoration_proof: Option<ProofWithPublicInputs<F, C, D>>,
//     pub account_update_proof: Option<ProofWithPublicInputs<F, C, D>>,
//     pub block_hash_merkle_proof: BlockHashMerkleProof,
// }

// impl<F: RichField + Extendable<D>, C: GenericConfig<D, F = F>, const D: usize>
//     ValidityTransitionValue<F, C, D>
// {
//     pub fn new(
//         account_registoration_circuit: &AccountRegistorationCircuit<F, C, D>,
//         account_update_circuit: &AccountRegistorationCircuit<F, C, D>,
//         prev_block_pis: MainValidationPublicInputs,
//         prev_block_tree_root: PoseidonHashOut,
//         prev_account_tree_root: PoseidonHashOut,
//         account_registoration_proof: Option<ProofWithPublicInputs<F, C, D>>,
//         account_update_proof: Option<ProofWithPublicInputs<F, C, D>>,
//         block_hash_merkle_proof: BlockHashMerkleProof,
//     ) -> Self {
//         // account registoration
//         let is_account_registoration =
//             prev_block_pis.is_registoration_block && prev_block_pis.is_valid;
//         let mut new_account_tree_root = prev_account_tree_root;
//         if is_account_registoration {
//             let account_registoration_proof = account_registoration_proof
//                 .clone()
//                 .expect("Account registoration proof is missing");
//             account_registoration_circuit
//                 .data
//                 .verify(account_registoration_proof.clone())
//                 .expect("Account registoration proof is invalid");
//             let pis = AccountTransitionPublicInputs::from_u64_vec(
//                 &account_registoration_proof
//                     .public_inputs
//                     .iter()
//                     .map(|x| x.to_canonical_u64())
//                     .collect::<Vec<_>>(),
//             );
//             assert_eq!(pis.prev_account_tree_root, prev_block_pis.account_tree_root);
//             assert_eq!(pis.sender_tree_root, prev_block_pis.sender_tree_root);
//             assert_eq!(pis.block_number, prev_block_pis.block_number);
//             new_account_tree_root = pis.new_account_tree_root;
//         }
//         let is_account_update = (!prev_pis.is_registoration_block) && prev_pis.is_valid_block;
//         if is_account_update {
//             let account_update_proof = account_update_proof
//                 .clone()
//                 .expect("Account update proof is missing");
//             account_update_circuit
//                 .data
//                 .verify(account_update_proof.clone())
//                 .expect("Account update proof is invalid");
//             let pis = AccountTransitionPublicInputs::from_u64_vec(
//                 &account_update_proof
//                     .public_inputs
//                     .iter()
//                     .map(|x| x.to_canonical_u64())
//                     .collect::<Vec<_>>(),
//             );
//             assert_eq!(pis.prev_account_tree_root, prev_pis.account_tree_root);
//             assert_eq!(pis.sender_tree_root, prev_pis.sender_tree_root);
//             assert_eq!(pis.block_number, prev_pis.block_number);
//             new_account_tree_root = pis.new_account_tree_root;
//         }

//         // block hash tree update
//         let prev_block_number = prev_pis.block_number;
//         let prev_block_hash_tree_root = prev_pis.block_hash_tree_root;
//         block_hash_merkle_proof
//             .verify(
//                 &Bytes32::default(),
//                 prev_block_number as usize,
//                 prev_block_hash_tree_root,
//             )
//             .expect("Block hash merkle proof is invalid");
//         let new_block_hash_tree_root =
//             block_hash_merkle_proof.get_root(&prev_pis.block_hash, prev_block_number as usize);

//         let new_pis = ValidityPublicInputs {
//             block_hash,
//             account_tree_root: new_account_tree_root,
//             tx_tree_root,
//             sender_tree_root,
//             is_registoration_block,
//             is_valid_block: is_valid,
//             block_hash_tree_root: new_block_hash_tree_root,
//             block_number: prev_pis.block_number + 1,
//         };

//         Self {
//             prev_pis,
//             new_pis,
//             account_registoration_proof,
//             account_update_proof,
//             block_hash_merkle_proof,
//         }
//     }
// }

// pub struct ValidityTransitionTarget<const D: usize> {
//     pub prev_pis: ValidityPublicInputsTarget,
//     pub new_pis: ValidityPublicInputsTarget,
//     pub account_registoration_proof: ProofWithPublicInputsTarget<D>,
//     pub account_update_proof: ProofWithPublicInputsTarget<D>,
//     pub block_hash_merkle_proof: BlockHashMerkleProofTarget,
// }

// impl<const D: usize> ValidityTransitionTarget<D> {
//     pub fn new<F: RichField + Extendable<D>, C: GenericConfig<D, F = F> + 'static>(
//         account_registoration_circuit: &AccountRegistorationCircuit<F, C, D>,
//         account_update_circuit: &AccountRegistorationCircuit<F, C, D>,
//         builder: &mut CircuitBuilder<F, D>,
//     ) -> Self
//     where
//         C::Hasher: AlgebraicHasher<F>,
//     {
//         // prev_pis already exists, so there is no need to check the ranges.
//         let prev_pis = ValidityPublicInputsTarget::new(builder, false);
//         let block_hash_merkle_proof =
//             BlockHashMerkleProofTarget::new(builder, BLOCK_HASH_TREE_HEIGHT);

//         let main_validation_pis =
//             MainValidationPublicInputsTarget::from_vec(&main_validation_proof.public_inputs);
//         main_validation_pis
//             .prev_block_hash
//             .connect(builder, prev_pis.block_hash);
//         let block_hash = main_validation_pis.block_hash;
//         let tx_tree_root = main_validation_pis.tx_tree_root;
//         let sender_tree_root = main_validation_pis.sender_tree_root;
//         let is_registoration_block = main_validation_pis.is_registoration_block;
//         let is_valid = main_validation_pis.is_valid;

//         let mut new_account_tree_root = prev_pis.account_tree_root.clone();
//         // account registoration
//         let is_account_registoration =
//             builder.and(prev_pis.is_registoration_block, prev_pis.is_valid_block);
//         let account_registoration_proof = account_registoration_circuit
//             .add_proof_target_and_conditionally_verify(builder, is_account_registoration);
//         let account_registoration_pis = AccountTransitionPublicInputsTarget::from_vec(
//             &account_registoration_proof.public_inputs,
//         );
//         builder.conditional_assert_eq_targets(
//             is_account_registoration,
//             &account_registoration_pis.prev_account_tree_root.elements,
//             &prev_pis.account_tree_root.elements,
//         );
//         builder.conditional_assert_eq_targets(
//             is_account_registoration,
//             &account_registoration_pis.sender_tree_root.elements,
//             &prev_pis.sender_tree_root.elements,
//         );
//         builder.conditional_assert_eq(
//             is_account_registoration.target,
//             account_registoration_pis.block_number,
//             prev_pis.block_number,
//         );
//         new_account_tree_root = PoseidonHashOutTarget::select(
//             builder,
//             is_account_registoration,
//             account_registoration_pis.new_account_tree_root,
//             new_account_tree_root,
//         );
//         // account update
//         let is_not_prev_registoration_block = builder.not(prev_pis.is_registoration_block);
//         let is_account_update =
//             builder.and(is_not_prev_registoration_block, prev_pis.is_valid_block);
//         let account_update_proof = account_update_circuit
//             .add_proof_target_and_conditionally_verify(builder, is_account_update);
//         let account_update_pis =
//             AccountTransitionPublicInputsTarget::from_vec(&account_update_proof.public_inputs);
//         builder.conditional_assert_eq_targets(
//             is_account_update,
//             &account_update_pis.prev_account_tree_root.elements,
//             &prev_pis.account_tree_root.elements,
//         );
//         builder.conditional_assert_eq_targets(
//             is_account_update,
//             &account_update_pis.sender_tree_root.elements,
//             &prev_pis.sender_tree_root.elements,
//         );
//         builder.conditional_assert_eq(
//             is_account_update.target,
//             account_update_pis.block_number,
//             prev_pis.block_number,
//         );
//         new_account_tree_root = PoseidonHashOutTarget::select(
//             builder,
//             is_account_update,
//             account_update_pis.new_account_tree_root,
//             new_account_tree_root,
//         );

//         main_validation_pis
//             .account_tree_root
//             .connect(builder, new_account_tree_root);

//         let prev_block_number = prev_pis.block_number;
//         let prev_block_hash_tree_root = prev_pis.block_hash_tree_root;
//         block_hash_merkle_proof.verify::<F, C, D>(
//             builder,
//             &Bytes32::default(),
//             prev_block_number,
//             prev_block_hash_tree_root,
//         );
//         let new_block_hash_tree_root = block_hash_merkle_proof.get_root::<F, C, D>(
//             builder,
//             &prev_pis.block_hash,
//             prev_block_number,
//         );
//         let block_number = builder.add_const(prev_pis.block_number, F::ONE);
//         let new_pis = ValidityPublicInputsTarget {
//             block_hash,
//             account_tree_root: new_account_tree_root,
//             tx_tree_root,
//             sender_tree_root,
//             is_registoration_block,
//             is_valid_block: is_valid,
//             block_hash_tree_root: new_block_hash_tree_root,
//             block_number,
//         };

//         Self {
//             prev_pis,
//             new_pis,
//             account_registoration_proof,
//             account_update_proof,
//             block_hash_merkle_proof,
//         }
//     }

//     pub fn set_witness<F: RichField + Extendable<D>, C: GenericConfig<D, F = F>, W: Witness<F>>(
//         &self,
//         witness: &mut W,
//         account_registoration_proof_dummy: DummyProof<F, C, D>,
//         account_update_proof_dummy: DummyProof<F, C, D>,
//         value: &ValidityTransitionValue<F, C, D>,
//     ) where
//         <C as GenericConfig<D>>::Hasher: AlgebraicHasher<F>,
//     {
//         self.prev_pis.set_witness(witness, &value.prev_pis);
//         self.new_pis.set_witness(witness, &value.new_pis);
//         let account_registoration_proof = value
//             .account_registoration_proof
//             .clone()
//             .unwrap_or(account_registoration_proof_dummy.proof);
//         witness.set_proof_with_pis_target(
//             &self.account_registoration_proof,
//             &account_registoration_proof,
//         );
//         let account_update_proof = value
//             .account_update_proof
//             .clone()
//             .unwrap_or(account_update_proof_dummy.proof);
//         witness.set_proof_with_pis_target(&self.account_update_proof, &account_update_proof);
//         self.block_hash_merkle_proof
//             .set_witness(witness, &value.block_hash_merkle_proof);
//     }
// }

// pub struct ValidityTransitionCircuit<F, C, const D: usize>
// where
//     F: RichField + Extendable<D>,
//     C: GenericConfig<D, F = F>,
// {
//     pub data: CircuitData<F, C, D>,
//     pub target: ValidityTransitionTarget<D>,
// }

// impl<F, C, const D: usize> ValidityTransitionCircuit<F, C, D>
// where
//     F: RichField + Extendable<D>,
//     C: GenericConfig<D, F = F> + 'static,
//     C::Hasher: AlgebraicHasher<F>,
// {
//     pub fn new(
//         account_registoration_circuit: &AccountRegistorationCircuit<F, C, D>,
//         account_update_circuit: &AccountRegistorationCircuit<F, C, D>,
//     ) -> Self {
//         let mut builder = CircuitBuilder::<F, D>::new(CircuitConfig::default());
//         let target = ValidityTransitionTarget::new::<F, C>(
//             account_registoration_circuit,
//             account_update_circuit,
//             &mut builder,
//         );
//         let pis = target
//             .prev_pis
//             .to_vec()
//             .into_iter()
//             .chain(target.new_pis.to_vec())
//             .collect::<Vec<_>>();
//         builder.register_public_inputs(&pis);
//         let data = builder.build();
//         Self { data, target }
//     }

//     pub fn prove(
//         &self,
//         account_registoration_proof_dummy: DummyProof<F, C, D>,
//         account_update_proof_dummy: DummyProof<F, C, D>,
//         value: &ValidityTransitionValue<F, C, D>,
//     ) -> anyhow::Result<ProofWithPublicInputs<F, C, D>> {
//         let mut pw = PartialWitness::<F>::new();
//         self.target.set_witness(
//             &mut pw,
//             account_registoration_proof_dummy,
//             account_update_proof_dummy,
//             value,
//         );
//         self.data.prove(pw)
//     }
// }

// impl<F, C, const D: usize> Recursivable<F, C, D> for ValidityTransitionCircuit<F, C, D>
// where
//     F: RichField + Extendable<D>,
//     C: GenericConfig<D, F = F> + 'static,
//     C::Hasher: AlgebraicHasher<F>,
// {
//     fn circuit_data(&self) -> &CircuitData<F, C, D> {
//         &self.data
//     }
// }

// #[cfg(test)]
// mod tests {
//     use plonky2::{
//         field::goldilocks_field::GoldilocksField, plonk::config::PoseidonGoldilocksConfig,
//     };
//     use rand::Rng;

//     use crate::{
//         circuits::validity::{
//             block_validation::{
//                 account_exclusion::{AccountExclusionCircuit, AccountExclusionValue},
//                 account_inclusion::AccountInclusionCircuit,
//                 aggregation::{AggregationCircuit, AggregationValue},
//                 format_validation::{FormatValidationCircuit, FormatValidationValue},
//                 main_validation::{MainValidationCircuit, MainValidationValue},
//             },
//             transition::{
//                 account_registoration::{AccountRegistorationCircuit, AccountRegistorationValue},
//                 ValidityTransitionValue,
//             },
//         },
//         common::{signature::key_set::KeySet, trees::sender_tree::get_sender_leaves, tx::Tx},
//         constants::NUM_SENDERS_IN_BLOCK,
//         mock::{
//             block_builder::{MockBlockBuilder, TxResuest},
//             db::MockDB,
//         },
//     };

//     type F = GoldilocksField;
//     const D: usize = 2;
//     type C = PoseidonGoldilocksConfig;

//     #[test]
//     fn validity_transition() {
//         let account_inclusion_circuit = AccountInclusionCircuit::<F, C, D>::new();
//         let account_exclusion_circuit = AccountExclusionCircuit::<F, C, D>::new();
//         let format_validation_circuit = FormatValidationCircuit::<F, C, D>::new();
//         let aggregation_circuit = AggregationCircuit::<F, C, D>::new();

//         let mut rng = rand::thread_rng();
//         let mut mock_db = MockDB::new();
//         let block_builder = MockBlockBuilder {};
//         block_builder.post_dummy_block(&mut rng, &mut mock_db);
//         let prev_block_witness = mock_db.get_last_block_witness();

//         let txs = (0..NUM_SENDERS_IN_BLOCK)
//             .map(|_| {
//                 let sender = KeySet::rand(&mut rng);
//                 TxResuest {
//                     tx: Tx::rand(&mut rng),
//                     sender,
//                     will_return_signature: rng.gen_bool(0.5),
//                 }
//             })
//             .collect::<Vec<_>>();
//         let block_info = block_builder.generate_block(&mut mock_db, true, txs);
//         let block_witness = block_info.block_witness;

//         // generate account exclusion proof
//         let account_exclusion_value = AccountExclusionValue::new(
//             block_witness.account_tree_root,
//             block_witness.account_membership_proofs.unwrap(),
//             block_witness.pubkeys.clone(),
//         );
//         let account_exclusion_proof = account_exclusion_circuit
//             .prove(&account_exclusion_value)
//             .unwrap();

//         let format_validation_value = FormatValidationValue::new(
//             block_witness.pubkeys.clone(),
//             block_witness.signature.clone(),
//         );
//         let format_validation_proof = format_validation_circuit
//             .prove(&format_validation_value)
//             .unwrap();

//         let aggregation_value = AggregationValue::new(
//             block_witness.pubkeys.clone(),
//             block_witness.signature.clone(),
//         );
//         let aggregation_proof = aggregation_circuit.prove(&aggregation_value).unwrap();

//         let instant = std::time::Instant::now();
//         let main_validation_value = MainValidationValue::new(
//             &account_inclusion_circuit,
//             &account_exclusion_circuit,
//             &format_validation_circuit,
//             &aggregation_circuit,
//             block_witness.block.clone(),
//             block_witness.signature,
//             block_witness.pubkeys,
//             block_witness.account_tree_root,
//             None,
//             Some(account_exclusion_proof),
//             format_validation_proof,
//             Some(aggregation_proof),
//         );

//         let account_registoration_circuit = AccountRegistorationCircuit::<F, C, D>::new();
//         let account_update_circuit = AccountRegistorationCircuit::<F, C, D>::new();

//         // it's not a registoration block
//         let prev_pis = prev_block_witness.to_validity_pis();
//         let block_merkle_proof = mock_db
//             .prev_block_hash_tree
//             .clone()
//             .unwrap()
//             .prove(prev_block_witness.block.block_number as usize);

//         let account_registoration_proof = {
//             let sender_leaves = get_sender_leaves(
//                 &prev_block_witness.pubkeys,
//                 prev_block_witness.signature.sender_flag,
//             );
//             let block_number = prev_pis.block_number;
//             let mut account_registoration_proofs = Vec::new();
//             for sender_leaf in &sender_leaves {
//                 let last_block_number = if sender_leaf.is_valid {
//                     block_number
//                 } else {
//                     0
//                 };
//                 let proof = mock_db
//                     .prev_account_tree
//                     .clone()
//                     .unwrap()
//                     .prove_and_insert(sender_leaf.sender, last_block_number as u64)
//                     .unwrap();
//                 account_registoration_proofs.push(proof);
//             }
//             let account_registoration_value = AccountRegistorationValue::new(
//                 prev_pis.account_tree_root,
//                 prev_pis.block_number,
//                 sender_leaves,
//                 account_registoration_proofs,
//             );
//             account_registoration_circuit
//                 .prove(&account_registoration_value)
//                 .unwrap()
//         };

//         let _value = ValidityTransitionValue::new(
//             &account_registoration_circuit,
//             &account_update_circuit,
//             prev_pis,
//             Some(account_registoration_proof),
//             None,
//             block_merkle_proof,
//         );
//         // let validity_transition_circuit = ValidityTransitionCircuit::<F, C, D>::new(
//         //     &main_validation_circuit,
//         //     &account_registoration_circuit,
//         //     &account_update_circuit,
//         // );
//         // let _validity_transition_proof = validity_transition_circuit
//         //     .prove(
//         //         account_registoration_circuit.dummy_proof,
//         //         account_update_circuit.dummy_proof,
//         //         &value,
//         //     )
//         //     .unwrap();
//     }
// }
