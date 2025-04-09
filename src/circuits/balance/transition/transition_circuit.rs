use super::error::TransitionError;
use plonky2::{
    field::extension::Extendable,
    hash::hash_types::{HashOutTarget, RichField},
    iop::{
        target::{BoolTarget, Target},
        witness::{PartialWitness, WitnessWrite},
    },
    plonk::{
        circuit_builder::CircuitBuilder,
        circuit_data::{
            CircuitConfig, CircuitData, VerifierCircuitData, VerifierCircuitTarget,
            VerifierOnlyCircuitData,
        },
        config::{AlgebraicHasher, GenericConfig},
        proof::{ProofWithPublicInputs, ProofWithPublicInputsTarget},
    },
};

use crate::{
    circuits::balance::{
        balance_pis::{BalancePublicInputs, BalancePublicInputsTarget},
        receive::{
            receive_deposit_circuit::{
                ReceiveDepositCircuit, ReceiveDepositPublicInputs, ReceiveDepositPublicInputsTarget,
            },
            receive_transfer_circuit::{
                ReceiveTransferCircuit, ReceiveTransferPublicInputs,
                ReceiveTransferPublicInputsTarget,
            },
            update_circuit::{UpdateCircuit, UpdatePublicInputs, UpdatePublicInputsTarget},
        },
        send::sender_circuit::{SenderCircuit, SenderPublicInputs, SenderPublicInputsTarget},
    },
    ethereum_types::u32limb_trait::U32LimbTargetTrait as _,
    utils::{
        conversion::ToU64,
        cyclic::conditionally_connect_vd,
        poseidon_hash_out::{PoseidonHashOut, PoseidonHashOutTarget},
        recursively_verifiable::add_proof_target_and_conditionally_verify,
    },
};

#[derive(Debug, Clone, Copy, PartialEq)]
pub enum BalanceTransitionType {
    ReceiveTransfer = 0,
    ReceiveDeposit = 1,
    Update = 2,
    Sender = 3,
}

#[derive(Debug, Clone)]
pub struct BalanceTransitionValue<
    F: RichField + Extendable<D>,
    C: GenericConfig<D, F = F>,
    const D: usize,
> {
    pub circuit_type: BalanceTransitionType,
    pub circuit_flags: [bool; 4],
    pub receive_transfer_proof: Option<ProofWithPublicInputs<F, C, D>>,
    pub receive_deposit_proof: Option<ProofWithPublicInputs<F, C, D>>,
    pub update_proof: Option<ProofWithPublicInputs<F, C, D>>,
    pub sender_proof: Option<ProofWithPublicInputs<F, C, D>>,
    pub prev_balance_pis: BalancePublicInputs,
    pub new_balance_pis: BalancePublicInputs, // witness for the `new_balance_pis_commitment`
    pub new_balance_pis_commitment: PoseidonHashOut, // selected by the circuit
    pub balance_circuit_vd: VerifierOnlyCircuitData<C, D>,
}

impl<F: RichField + Extendable<D>, C: GenericConfig<D, F = F>, const D: usize>
    BalanceTransitionValue<F, C, D>
where
    <C as GenericConfig<D>>::Hasher: AlgebraicHasher<F>,
{
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        config: &CircuitConfig,
        circuit_type: BalanceTransitionType,
        receive_transfer_circuit: &ReceiveTransferCircuit<F, C, D>,
        receive_deposit_circuit: &ReceiveDepositCircuit<F, C, D>,
        update_circuit: &UpdateCircuit<F, C, D>,
        sender_circuit: &SenderCircuit<F, C, D>,
        receive_transfer_proof: Option<ProofWithPublicInputs<F, C, D>>,
        receive_deposit_proof: Option<ProofWithPublicInputs<F, C, D>>,
        update_proof: Option<ProofWithPublicInputs<F, C, D>>,
        sender_proof: Option<ProofWithPublicInputs<F, C, D>>,
        prev_balance_pis: BalancePublicInputs,
        balance_circuit_vd: VerifierOnlyCircuitData<C, D>,
    ) -> Result<Self, TransitionError> {
        let mut circuit_flags = [false; 4];
        circuit_flags[circuit_type as usize] = true;

        let new_balance_pis = match circuit_type {
            BalanceTransitionType::ReceiveTransfer => {
                let receive_transfer_proof = receive_transfer_proof.clone().ok_or_else(|| {
                    TransitionError::InvalidValue("receive_transfer_proof is None".to_string())
                })?;

                receive_transfer_circuit
                    .data
                    .verify(receive_transfer_proof.clone())
                    .map_err(|e| {
                        TransitionError::VerificationFailed(format!(
                            "receive_transfer_proof is invalid: {}",
                            e
                        ))
                    })?;

                let pis = ReceiveTransferPublicInputs::<F, C, D>::from_slice(
                    config,
                    &receive_transfer_proof.public_inputs,
                );

                if pis.balance_circuit_vd != balance_circuit_vd {
                    return Err(TransitionError::VerificationFailed(
                        "balance_circuit_vd mismatch in receive_transfer_proof".to_string(),
                    ));
                }

                if pis.prev_private_commitment != prev_balance_pis.private_commitment {
                    return Err(TransitionError::VerificationFailed(
                        "prev_private_commitment mismatch in receive_transfer_proof".to_string(),
                    ));
                }

                if pis.pubkey != prev_balance_pis.pubkey {
                    return Err(TransitionError::VerificationFailed(
                        "pubkey mismatch in receive_transfer_proof".to_string(),
                    ));
                }

                if pis.public_state != prev_balance_pis.public_state {
                    return Err(TransitionError::VerificationFailed(
                        "public_state mismatch in receive_transfer_proof".to_string(),
                    ));
                }

                BalancePublicInputs {
                    pubkey: pis.pubkey,
                    private_commitment: pis.new_private_commitment,
                    ..prev_balance_pis.clone()
                }
            }
            BalanceTransitionType::ReceiveDeposit => {
                let receive_deposit_proof = receive_deposit_proof.clone().ok_or_else(|| {
                    TransitionError::InvalidValue("receive_deposit_proof is None".to_string())
                })?;

                receive_deposit_circuit
                    .data
                    .verify(receive_deposit_proof.clone())
                    .map_err(|e| {
                        TransitionError::VerificationFailed(format!(
                            "receive_deposit_proof is invalid: {}",
                            e
                        ))
                    })?;

                let pis = ReceiveDepositPublicInputs::from_u64_slice(
                    &receive_deposit_proof
                        .public_inputs
                        .iter()
                        .map(|x| x.to_canonical_u64())
                        .collect::<Vec<_>>(),
                )
                .map_err(|e| {
                    TransitionError::VerificationFailed(format!(
                        "Failed to parse receive_deposit_proof public inputs: {}",
                        e
                    ))
                })?;

                if pis.prev_private_commitment != prev_balance_pis.private_commitment {
                    return Err(TransitionError::VerificationFailed(
                        "prev_private_commitment mismatch in receive_deposit_proof".to_string(),
                    ));
                }

                if pis.pubkey != prev_balance_pis.pubkey {
                    return Err(TransitionError::VerificationFailed(
                        "pubkey mismatch in receive_deposit_proof".to_string(),
                    ));
                }

                if pis.public_state != prev_balance_pis.public_state {
                    return Err(TransitionError::VerificationFailed(
                        "public_state mismatch in receive_deposit_proof".to_string(),
                    ));
                }

                BalancePublicInputs {
                    pubkey: pis.pubkey,
                    private_commitment: pis.new_private_commitment,
                    ..prev_balance_pis.clone()
                }
            }
            BalanceTransitionType::Update => {
                let update_proof = update_proof.clone().ok_or_else(|| {
                    TransitionError::InvalidValue("update_proof is None".to_string())
                })?;

                update_circuit
                    .data
                    .verify(update_proof.clone())
                    .map_err(|e| {
                        TransitionError::VerificationFailed(format!(
                            "update_proof is invalid: {}",
                            e
                        ))
                    })?;

                let pis =
                    UpdatePublicInputs::from_u64_slice(&update_proof.public_inputs.to_u64_vec());

                if pis.prev_public_state != prev_balance_pis.public_state {
                    return Err(TransitionError::VerificationFailed(
                        "prev_public_state mismatch in update_proof".to_string(),
                    ));
                }

                BalancePublicInputs {
                    public_state: pis.new_public_state,
                    ..prev_balance_pis
                }
            }
            BalanceTransitionType::Sender => {
                let sender_proof = sender_proof.clone().ok_or_else(|| {
                    TransitionError::InvalidValue("sender_proof is None".to_string())
                })?;

                sender_circuit
                    .data
                    .verify(sender_proof.clone())
                    .map_err(|e| {
                        TransitionError::VerificationFailed(format!(
                            "sender_proof is invalid: {}",
                            e
                        ))
                    })?;

                let pis = SenderPublicInputs::from_u64_slice(
                    &sender_proof
                        .public_inputs
                        .iter()
                        .map(|x| x.to_canonical_u64())
                        .collect::<Vec<_>>(),
                )
                .map_err(|e| {
                    TransitionError::VerificationFailed(format!(
                        "Failed to parse sender_proof public inputs: {}",
                        e
                    ))
                })?;

                if pis.prev_balance_pis != prev_balance_pis {
                    return Err(TransitionError::VerificationFailed(
                        "prev_balance_pis mismatch".to_string(),
                    ));
                }

                pis.new_balance_pis
            }
        };

        let new_balance_pis_commitment = new_balance_pis.commitment();

        Ok(Self {
            circuit_type,
            circuit_flags,
            receive_transfer_proof,
            receive_deposit_proof,
            update_proof,
            sender_proof,
            prev_balance_pis,
            new_balance_pis,
            new_balance_pis_commitment,
            balance_circuit_vd,
        })
    }
}

#[derive(Debug, Clone)]
pub struct BalanceTransitionTarget<const D: usize> {
    pub circuit_type: Target,
    pub circuit_flags: [BoolTarget; 4],
    pub receive_transfer_proof: ProofWithPublicInputsTarget<D>,
    pub receive_deposit_proof: ProofWithPublicInputsTarget<D>,
    pub update_proof: ProofWithPublicInputsTarget<D>,
    pub sender_proof: ProofWithPublicInputsTarget<D>,
    pub prev_balance_pis: BalancePublicInputsTarget,
    pub new_balance_pis: BalancePublicInputsTarget, // witness for the `new_balance_pis_commitment`
    pub new_balance_pis_commitment: PoseidonHashOutTarget, // selected by the circuit
    pub balance_circuit_vd: VerifierCircuitTarget,
}

impl<const D: usize> BalanceTransitionTarget<D> {
    pub fn new<F: RichField + Extendable<D>, C: GenericConfig<D, F = F> + 'static>(
        receive_transfer_vd: &VerifierCircuitData<F, C, D>,
        receive_deposit_vd: &VerifierCircuitData<F, C, D>,
        update_vd: &VerifierCircuitData<F, C, D>,
        sender_vd: &VerifierCircuitData<F, C, D>,
        config: &CircuitConfig,
        builder: &mut CircuitBuilder<F, D>,
    ) -> Self
    where
        <C as GenericConfig<D>>::Hasher: AlgebraicHasher<F>,
    {
        let circuit_type = builder.add_virtual_target();
        let circuit_flags = [(); 4].map(|_| builder.add_virtual_bool_target_safe());
        let circuit_flags_target = circuit_flags.iter().map(|x| x.target).collect::<Vec<_>>();
        let one = builder.one();
        let bit_selected = builder.random_access(circuit_type, circuit_flags_target);
        builder.connect(bit_selected, one);
        // sum of circuit_flags should be 1
        let sum = circuit_flags
            .iter()
            .fold(builder.zero(), |acc, x| builder.add(acc, x.target));
        builder.connect(sum, one);

        let balance_circuit_vd = builder.add_virtual_verifier_data(config.fri_config.cap_height);
        let prev_balance_pis = BalancePublicInputsTarget::new(builder, false);

        let receive_transfer_proof = add_proof_target_and_conditionally_verify(
            receive_transfer_vd,
            builder,
            circuit_flags[0],
        );
        let new_balance_pis0 = {
            let condition = circuit_flags[0];
            let pis = ReceiveTransferPublicInputsTarget::from_slice(
                config,
                &receive_transfer_proof.public_inputs,
            );
            conditionally_connect_vd(
                builder,
                condition,
                &pis.balance_circuit_vd,
                &balance_circuit_vd,
            );
            pis.prev_private_commitment.conditional_assert_eq(
                builder,
                prev_balance_pis.private_commitment,
                condition,
            );
            pis.pubkey
                .conditional_assert_eq(builder, prev_balance_pis.pubkey, condition);
            pis.public_state.conditional_assert_eq(
                builder,
                &prev_balance_pis.public_state,
                condition,
            );
            BalancePublicInputsTarget {
                pubkey: pis.pubkey,
                private_commitment: pis.new_private_commitment,
                ..prev_balance_pis.clone()
            }
        };
        let receive_deposit_proof = add_proof_target_and_conditionally_verify(
            receive_deposit_vd,
            builder,
            circuit_flags[1],
        );
        let new_balance_pis1 = {
            let condition = circuit_flags[1];
            let pis =
                ReceiveDepositPublicInputsTarget::from_slice(&receive_deposit_proof.public_inputs)
                    .expect("Failed to parse receive_deposit_proof public inputs");
            pis.prev_private_commitment.conditional_assert_eq(
                builder,
                prev_balance_pis.private_commitment,
                condition,
            );
            pis.pubkey
                .conditional_assert_eq(builder, prev_balance_pis.pubkey, condition);
            pis.public_state.conditional_assert_eq(
                builder,
                &prev_balance_pis.public_state,
                condition,
            );
            BalancePublicInputsTarget {
                pubkey: pis.pubkey,
                private_commitment: pis.new_private_commitment,
                ..prev_balance_pis.clone()
            }
        };
        let update_proof =
            add_proof_target_and_conditionally_verify(update_vd, builder, circuit_flags[2]);
        let new_balance_pis2 = {
            let condition = circuit_flags[2];
            let pis = UpdatePublicInputsTarget::from_slice(&update_proof.public_inputs);
            pis.prev_public_state.conditional_assert_eq(
                builder,
                &prev_balance_pis.public_state,
                condition,
            );
            prev_balance_pis
                .pubkey
                .conditional_assert_eq(builder, pis.pubkey, condition);
            BalancePublicInputsTarget {
                pubkey: pis.pubkey,
                public_state: pis.new_public_state,
                ..prev_balance_pis.clone()
            }
        };
        let sender_proof =
            add_proof_target_and_conditionally_verify(sender_vd, builder, circuit_flags[3]);
        let new_balance_pis3 = {
            let condition = circuit_flags[3];
            let pis = SenderPublicInputsTarget::from_slice(&sender_proof.public_inputs);
            pis.prev_balance_pis
                .conditional_assert_eq(builder, &prev_balance_pis, condition);
            pis.new_balance_pis
        };

        let candidates = vec![
            new_balance_pis0.clone(),
            new_balance_pis1.clone(),
            new_balance_pis2.clone(),
            new_balance_pis3.clone(),
        ];
        let candidate_commitments = candidates
            .iter()
            .map(|pis| HashOutTarget {
                elements: pis.commitment(builder).elements,
            })
            .collect::<Vec<_>>();
        let selected_commitment = PoseidonHashOutTarget {
            elements: builder
                .random_access_hash(circuit_type, candidate_commitments)
                .elements,
        };
        let new_balance_pis = BalancePublicInputsTarget::new(builder, true);
        let new_balance_pis_commitment = new_balance_pis.commitment(builder);
        selected_commitment.connect(builder, new_balance_pis_commitment);

        Self {
            circuit_type,
            circuit_flags,
            receive_transfer_proof,
            receive_deposit_proof,
            update_proof,
            sender_proof,
            prev_balance_pis,
            new_balance_pis,
            new_balance_pis_commitment,
            balance_circuit_vd,
        }
    }

    pub fn set_witness<
        F: RichField + Extendable<D>,
        C: GenericConfig<D, F = F> + 'static,
        W: WitnessWrite<F>,
    >(
        &self,
        receive_transfer_circuit: &ReceiveTransferCircuit<F, C, D>,
        receive_deposit_circuit: &ReceiveDepositCircuit<F, C, D>,
        update_circuit: &UpdateCircuit<F, C, D>,
        sender_circuit: &SenderCircuit<F, C, D>,
        witness: &mut W,
        value: &BalanceTransitionValue<F, C, D>,
    ) where
        <C as GenericConfig<D>>::Hasher: AlgebraicHasher<F>,
    {
        witness.set_target(
            self.circuit_type,
            F::from_canonical_usize(value.circuit_type as usize),
        );
        self.circuit_flags
            .iter()
            .zip(value.circuit_flags.iter())
            .for_each(|(x, y)| witness.set_bool_target(*x, *y));

        if value.receive_transfer_proof.is_some() {
            witness.set_proof_with_pis_target(
                &self.receive_transfer_proof,
                &value.receive_transfer_proof.clone().unwrap(),
            );
        } else {
            witness.set_proof_with_pis_target(
                &self.receive_transfer_proof,
                &receive_transfer_circuit.dummy_proof.proof,
            );
        }
        if value.receive_deposit_proof.is_some() {
            witness.set_proof_with_pis_target(
                &self.receive_deposit_proof,
                &value.receive_deposit_proof.clone().unwrap(),
            );
        } else {
            witness.set_proof_with_pis_target(
                &self.receive_deposit_proof,
                &receive_deposit_circuit.dummy_proof.proof,
            );
        }
        if value.update_proof.is_some() {
            witness.set_proof_with_pis_target(
                &self.update_proof,
                &value.update_proof.clone().unwrap(),
            );
        } else {
            witness
                .set_proof_with_pis_target(&self.update_proof, &update_circuit.dummy_proof.proof);
        }
        if value.sender_proof.is_some() {
            witness.set_proof_with_pis_target(
                &self.sender_proof,
                &value.sender_proof.clone().unwrap(),
            );
        } else {
            witness
                .set_proof_with_pis_target(&self.sender_proof, &sender_circuit.dummy_proof.proof);
        }
        self.prev_balance_pis
            .set_witness(witness, &value.prev_balance_pis);
        self.new_balance_pis
            .set_witness(witness, &value.new_balance_pis);
        self.new_balance_pis_commitment
            .set_witness(witness, value.new_balance_pis_commitment);
        witness.set_verifier_data_target(&self.balance_circuit_vd, &value.balance_circuit_vd);
    }
}

pub struct BalanceTransitionCircuit<F, C, const D: usize>
where
    F: RichField + Extendable<D>,
    C: GenericConfig<D, F = F>,
{
    pub data: CircuitData<F, C, D>,
    pub target: BalanceTransitionTarget<D>,
    pub balance_circuit_vd: VerifierCircuitTarget,
}

impl<F, C, const D: usize> BalanceTransitionCircuit<F, C, D>
where
    F: RichField + Extendable<D>,
    C: GenericConfig<D, F = F> + 'static,
    C::Hasher: AlgebraicHasher<F>,
{
    pub fn new(
        receive_transfer_vd: &VerifierCircuitData<F, C, D>,
        receive_deposit_vd: &VerifierCircuitData<F, C, D>,
        update_vd: &VerifierCircuitData<F, C, D>,
        sender_vd: &VerifierCircuitData<F, C, D>,
    ) -> Self {
        let config = CircuitConfig::standard_recursion_zk_config();
        let mut builder = CircuitBuilder::<F, D>::new(config.clone());
        let target = BalanceTransitionTarget::new::<F, C>(
            receive_transfer_vd,
            receive_deposit_vd,
            update_vd,
            sender_vd,
            &config,
            &mut builder,
        );
        let pis = [
            target.prev_balance_pis.to_vec(),
            target.new_balance_pis.to_vec(),
        ]
        .concat();
        builder.register_public_inputs(&pis);
        let balance_circuit_vd = builder.add_verifier_data_public_inputs();
        builder.connect_verifier_data(&balance_circuit_vd, &target.balance_circuit_vd);
        let data = builder.build();

        Self {
            data,
            target,
            balance_circuit_vd,
        }
    }

    pub fn prove(
        &self,
        receive_transfer_circuit: &ReceiveTransferCircuit<F, C, D>,
        receive_deposit_circuit: &ReceiveDepositCircuit<F, C, D>,
        update_circuit: &UpdateCircuit<F, C, D>,
        sender_circuit: &SenderCircuit<F, C, D>,
        value: &BalanceTransitionValue<F, C, D>,
    ) -> Result<ProofWithPublicInputs<F, C, D>, TransitionError> {
        let mut pw = PartialWitness::<F>::new();
        self.target.set_witness(
            receive_transfer_circuit,
            receive_deposit_circuit,
            update_circuit,
            sender_circuit,
            &mut pw,
            value,
        );
        pw.set_verifier_data_target(&self.balance_circuit_vd, &value.balance_circuit_vd);
        self.data
            .prove(pw)
            .map_err(|e| TransitionError::ProofGenerationError(format!("{:?}", e)))
    }
}
