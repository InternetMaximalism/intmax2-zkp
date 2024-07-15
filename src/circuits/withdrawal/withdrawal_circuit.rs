use anyhow::Result;
use hashbrown::HashMap;
use plonky2::{
    field::extension::Extendable,
    gates::{noop::NoopGate, random_access::RandomAccessGate},
    hash::hash_types::RichField,
    iop::{
        target::{BoolTarget, Target},
        witness::{PartialWitness, WitnessWrite as _},
    },
    plonk::{
        circuit_builder::CircuitBuilder,
        circuit_data::{CircuitConfig, CircuitData, CommonCircuitData, VerifierCircuitTarget},
        config::{AlgebraicHasher, GenericConfig},
        proof::{ProofWithPublicInputs, ProofWithPublicInputsTarget},
    },
    recursion::dummy_circuit::cyclic_base_proof,
};

use crate::{
    circuits::{
        balance::{
            balance_circuit::BalanceCircuit,
            receive::receive_targets::transfer_inclusion::{
                TransferInclusionTarget, TransferInclusionValue,
            },
        },
        utils::cyclic::vd_vec_len,
    },
    common::withdrawal::{get_withdrawal_nullifier_circuit, WithdrawalTarget},
    constants::WITHDRAWAL_CIRCUIT_PADDING_DEGREE,
    ethereum_types::{
        bytes32::{Bytes32, BYTES32_LEN},
        u32limb_trait::U32LimbTargetTrait,
    },
    utils::recursivable::Recursivable,
};

#[derive(Debug)]
pub struct WithdrawalCircuit<F, C, const D: usize>
where
    F: RichField + Extendable<D>,
    C: GenericConfig<D, F = F>,
{
    data: CircuitData<F, C, D>,
    is_first_step: BoolTarget,
    transfer_inclusion_target: TransferInclusionTarget<D>,
    prev_proof: ProofWithPublicInputsTarget<D>,
    verifier_data_target: VerifierCircuitTarget,
}

impl<F, C, const D: usize> WithdrawalCircuit<F, C, D>
where
    F: RichField + Extendable<D>,
    C: GenericConfig<D, F = F> + 'static,
    C::Hasher: AlgebraicHasher<F>,
{
    pub fn new(balance_circuit: &BalanceCircuit<F, C, D>) -> Self {
        let mut builder = CircuitBuilder::<F, D>::new(CircuitConfig::default());
        let is_first_step = builder.add_virtual_bool_target_safe();
        let is_not_first_step = builder.not(is_first_step);

        let transfer_inclusion_target = TransferInclusionTarget::new::<F, C>(
            &balance_circuit.get_verifier_data().common,
            &mut builder,
            true,
        );
        let transfer = transfer_inclusion_target.transfer.clone();
        let nullifier = get_withdrawal_nullifier_circuit(&mut builder, &transfer);
        let recipient = transfer.recipient.to_address(&mut builder);
        let prev_withdral_hash = Bytes32::<Target>::new(&mut builder, true); // connect later
        let withdrawal = WithdrawalTarget {
            prev_withdral_hash,
            recipient,
            token_index: transfer.token_index,
            amount: transfer.amount,
            nullifier,
            block_hash: transfer_inclusion_target.public_state.block_hash,
        };
        let withdrawal_hash = withdrawal.hash::<F, C, D>(&mut builder);
        builder.register_public_inputs(&withdrawal_hash.to_vec());

        let common_data = common_data_for_withdrawal_circuit::<F, C, D>();
        let verifier_data_target = builder.add_verifier_data_public_inputs();

        let prev_proof = builder.add_virtual_proof_with_pis(&common_data);
        builder
            .conditionally_verify_cyclic_proof_or_dummy::<C>(
                is_not_first_step,
                &prev_proof,
                &common_data,
            )
            .unwrap();
        let prev_pis = Bytes32::<Target>::from_limbs(&prev_proof.public_inputs[0..BYTES32_LEN]);
        prev_pis.connect(&mut builder, prev_withdral_hash);
        // initial condition
        let zero = Bytes32::<Target>::zero::<F, D, Bytes32<u32>>(&mut builder);
        prev_pis.conditional_assert_eq(&mut builder, zero, is_first_step);

        let (data, success) = builder.try_build_with_options::<C>(true);
        assert_eq!(data.common, common_data);
        assert!(success);
        Self {
            data,
            is_first_step,
            transfer_inclusion_target,
            prev_proof,
            verifier_data_target,
        }
    }

    pub fn prove(
        &self,
        transition_inclusion_value: &TransferInclusionValue<F, C, D>,
        prev_proof: &Option<ProofWithPublicInputs<F, C, D>>,
    ) -> Result<ProofWithPublicInputs<F, C, D>> {
        let mut pw = PartialWitness::<F>::new();
        pw.set_verifier_data_target(&self.verifier_data_target, &self.data.verifier_only);
        self.transfer_inclusion_target
            .set_witness(&mut pw, transition_inclusion_value);
        if prev_proof.is_none() {
            let dummy_proof =
                cyclic_base_proof(&self.data.common, &self.data.verifier_only, HashMap::new());
            pw.set_bool_target(self.is_first_step, true);
            pw.set_proof_with_pis_target(&self.prev_proof, &dummy_proof);
        } else {
            pw.set_bool_target(self.is_first_step, false);
            pw.set_proof_with_pis_target(&self.prev_proof, prev_proof.as_ref().unwrap());
        }
        self.data.prove(pw)
    }
}

// Generates `CommonCircuitData` usable for recursion.
pub fn common_data_for_withdrawal_circuit<
    F: RichField + Extendable<D>,
    C: GenericConfig<D, F = F>,
    const D: usize,
>() -> CommonCircuitData<F, D>
where
    C::Hasher: AlgebraicHasher<F>,
{
    let builder = CircuitBuilder::<F, D>::new(CircuitConfig::default());
    let data = builder.build::<C>();

    let mut builder = CircuitBuilder::<F, D>::new(CircuitConfig::default());
    let proof = builder.add_virtual_proof_with_pis(&data.common);
    let verifier_data = VerifierCircuitTarget {
        constants_sigmas_cap: builder.add_virtual_cap(data.common.config.fri_config.cap_height),
        circuit_digest: builder.add_virtual_hash(),
    };
    builder.verify_proof::<C>(&proof, &verifier_data, &data.common);
    let data = builder.build::<C>();

    let mut builder = CircuitBuilder::<F, D>::new(CircuitConfig::default());
    let proof = builder.add_virtual_proof_with_pis(&data.common);
    let verifier_data = VerifierCircuitTarget {
        constants_sigmas_cap: builder.add_virtual_cap(data.common.config.fri_config.cap_height),
        circuit_digest: builder.add_virtual_hash(),
    };
    let random_access_gate1 = RandomAccessGate::new_from_config(&CircuitConfig::default(), 1);
    let random_access_gate5 = RandomAccessGate::new_from_config(&CircuitConfig::default(), 5);
    builder.add_gate(random_access_gate5, vec![]);
    builder.add_gate(random_access_gate1, vec![]);
    builder.verify_proof::<C>(&proof, &verifier_data, &data.common);
    while builder.num_gates() < 1 << WITHDRAWAL_CIRCUIT_PADDING_DEGREE {
        builder.add_gate(NoopGate, vec![]);
    }
    let mut common = builder.build::<C>().common;
    common.num_public_inputs = BYTES32_LEN + vd_vec_len(&common.config);
    common
}

impl<F: RichField + Extendable<D>, C: GenericConfig<D, F = F> + 'static, const D: usize>
    Recursivable<F, C, D> for WithdrawalCircuit<F, C, D>
where
    <C as GenericConfig<D>>::Hasher: AlgebraicHasher<F>,
{
    fn circuit_data(&self) -> &CircuitData<F, C, D> {
        &self.data
    }
}

#[cfg(test)]
mod tests {
    use plonky2::{
        field::goldilocks_field::GoldilocksField, plonk::config::PoseidonGoldilocksConfig,
    };

    use crate::{
        circuits::balance::{
            balance_processor::BalanceProcessor,
            receive::receive_targets::transfer_inclusion::TransferInclusionValue,
        },
        common::transfer::Transfer,
        mock::{
            block_builder::MockBlockBuilder, local_manager::LocalManager,
            sync_balance_prover::SyncBalanceProver, sync_validity_prover::SyncValidityProver,
        },
    };

    use super::WithdrawalCircuit;

    type F = GoldilocksField;
    type C = PoseidonGoldilocksConfig;
    const D: usize = 2;

    #[test]
    fn withdawal_circuit() {
        let mut rng = &mut rand::thread_rng();
        let mut block_builder = MockBlockBuilder::new();
        let mut local_manager = LocalManager::new_rand(rng);
        let mut sync_validity_prover = SyncValidityProver::<F, C, D>::new();
        let mut sync_sender_prover = SyncBalanceProver::<F, C, D>::new();
        let balance_processor = BalanceProcessor::new(sync_validity_prover.validity_circuit());

        // withdraw transfer 1
        let transfer = Transfer::rand_withdrawal(rng);
        let send_witness =
            local_manager.send_tx_and_update(&mut rng, &mut block_builder, &[transfer]);
        sync_sender_prover.sync_send(
            &mut sync_validity_prover,
            &balance_processor,
            &block_builder,
            &local_manager,
        );
        let transfer_witness = &local_manager
            .get_transfer_witnesses(send_witness.get_included_block_number())
            .unwrap()[0];
        let balance_proof = sync_sender_prover.get_balance_proof();

        let transfer_inclusion_value = TransferInclusionValue::new(
            &balance_processor.get_verifier_data(),
            &transfer_witness.transfer,
            transfer_witness.transfer_index,
            &transfer_witness.transfer_merkle_proof,
            &transfer_witness.tx_witness.tx,
            &balance_proof,
        );

        let withdrawal_circuit = WithdrawalCircuit::new(&balance_processor.balance_circuit);
        let withdrawal_proof0 = withdrawal_circuit
            .prove(&transfer_inclusion_value, &None)
            .unwrap();
        let _withdrawal_proof1 = withdrawal_circuit
            .prove(&transfer_inclusion_value, &Some(withdrawal_proof0))
            .unwrap();
    }
}
