use super::error::SendError;
use plonky2::{
    field::extension::Extendable,
    gates::constant::ConstantGate,
    hash::hash_types::RichField,
    iop::{
        target::Target,
        witness::{PartialWitness, WitnessWrite},
    },
    plonk::{
        circuit_builder::CircuitBuilder,
        circuit_data::{CircuitConfig, CircuitData, VerifierCircuitData},
        config::{AlgebraicHasher, GenericConfig},
        proof::{ProofWithPublicInputs, ProofWithPublicInputsTarget},
    },
};

use crate::{
    circuits::balance::{
        balance_pis::{BalancePublicInputs, BalancePublicInputsTarget, BALANCE_PUBLIC_INPUTS_LEN},
        send::{
            spent_circuit::SpentPublicInputsTarget,
            tx_inclusion_circuit::TxInclusionPublicInputsTarget,
        },
    },
    common::insufficient_flags::InsufficientFlagsTarget,
    ethereum_types::u32limb_trait::U32LimbTargetTrait as _,
    utils::{
        conversion::ToU64,
        dummy::DummyProof,
        leafable::{Leafable as _, LeafableTarget},
        poseidon_hash_out::PoseidonHashOutTarget,
        recursively_verifiable::add_proof_target_and_verify,
    },
};

use super::{
    spent_circuit::{SpentCircuit, SpentPublicInputs},
    tx_inclusion_circuit::{TxInclusionCircuit, TxInclusionPublicInputs},
};

pub const SENDER_PUBLIC_INPUTS_LEN: usize = 2 * BALANCE_PUBLIC_INPUTS_LEN;

#[derive(Debug, Clone)]
pub struct SenderPublicInputs {
    pub prev_balance_pis: BalancePublicInputs,
    pub new_balance_pis: BalancePublicInputs,
}

impl SenderPublicInputs {
    pub fn to_u64_vec(&self) -> Vec<u64> {
        let mut vec = self.prev_balance_pis.to_u64_vec();
        vec.extend(self.new_balance_pis.to_u64_vec());
        assert_eq!(vec.len(), SENDER_PUBLIC_INPUTS_LEN);
        vec
    }

    pub fn from_u64_slice(vec: &[u64]) -> Result<Self, super::error::SendError> {
        if vec.len() != SENDER_PUBLIC_INPUTS_LEN {
            return Err(super::error::SendError::InvalidInput(format!(
                "Sender public inputs length mismatch: expected {}, got {}",
                SENDER_PUBLIC_INPUTS_LEN,
                vec.len()
            )));
        }

        let prev_balance_pis = BalancePublicInputs::from_u64_slice(
            &vec[..BALANCE_PUBLIC_INPUTS_LEN],
        )
        .map_err(|e| {
            super::error::SendError::InvalidInput(format!(
                "Invalid prev balance public inputs: {:?}",
                e
            ))
        })?;

        let new_balance_pis = BalancePublicInputs::from_u64_slice(
            &vec[BALANCE_PUBLIC_INPUTS_LEN..],
        )
        .map_err(|e| {
            super::error::SendError::InvalidInput(format!(
                "Invalid new balance public inputs: {:?}",
                e
            ))
        })?;

        Ok(Self {
            prev_balance_pis,
            new_balance_pis,
        })
    }
}

#[derive(Debug, Clone)]
pub struct SenderPublicInputsTarget {
    pub prev_balance_pis: BalancePublicInputsTarget,
    pub new_balance_pis: BalancePublicInputsTarget,
}

impl SenderPublicInputsTarget {
    pub fn to_vec(&self) -> Vec<Target> {
        let mut vec = self.prev_balance_pis.to_vec();
        vec.extend(self.new_balance_pis.to_vec());
        assert_eq!(vec.len(), SENDER_PUBLIC_INPUTS_LEN);
        vec
    }

    pub fn from_slice(vec: &[Target]) -> Self {
        assert_eq!(vec.len(), SENDER_PUBLIC_INPUTS_LEN);
        let prev_balance_pis =
            BalancePublicInputsTarget::from_slice(&vec[..BALANCE_PUBLIC_INPUTS_LEN]);
        let new_balance_pis =
            BalancePublicInputsTarget::from_slice(&vec[BALANCE_PUBLIC_INPUTS_LEN..]);
        Self {
            prev_balance_pis,
            new_balance_pis,
        }
    }
}

#[derive(Debug, Clone)]
pub struct SenderValue<F: RichField + Extendable<D>, C: GenericConfig<D, F = F>, const D: usize> {
    pub spent_proof: ProofWithPublicInputs<F, C, D>,
    pub tx_inclusion_proof: ProofWithPublicInputs<F, C, D>,
    pub prev_balance_pis: BalancePublicInputs,
    pub new_balance_pis: BalancePublicInputs,
}

impl<F: RichField + Extendable<D>, C: GenericConfig<D, F = F>, const D: usize>
    SenderValue<F, C, D>
{
    pub fn new(
        spent_circuit: &SpentCircuit<F, C, D>,
        tx_inclusion_circuit: &TxInclusionCircuit<F, C, D>,
        spent_proof: &ProofWithPublicInputs<F, C, D>,
        tx_inclusion_proof: &ProofWithPublicInputs<F, C, D>,
        prev_balance_pis: &BalancePublicInputs,
    ) -> Result<Self, SendError>
    where
        C::Hasher: AlgebraicHasher<F>,
    {
        // verify proof
        spent_circuit
            .data
            .verify(spent_proof.clone())
            .map_err(|e| SendError::VerificationFailed(format!("Invalid spent proof: {:?}", e)))?;

        tx_inclusion_circuit
            .data
            .verify(tx_inclusion_proof.clone())
            .map_err(|e| {
                SendError::VerificationFailed(format!("Invalid tx inclusion proof: {:?}", e))
            })?;

        let spent_pis = SpentPublicInputs::from_u64_slice(
            &spent_proof
                .public_inputs
                .iter()
                .map(|x| x.to_canonical_u64())
                .collect::<Vec<_>>(),
        );

        let tx_inclusion_pis =
            TxInclusionPublicInputs::from_u64_slice(&tx_inclusion_proof.public_inputs.to_u64_vec());

        // check tx equivalence
        if spent_pis.tx != tx_inclusion_pis.tx {
            return Err(SendError::VerificationFailed(
                "Tx mismatch between spent proof and tx inclusion proof".to_string(),
            ));
        }

        let is_valid = spent_pis.is_valid && tx_inclusion_pis.is_valid;
        let new_private_commitment = if is_valid {
            spent_pis.new_private_commitment
        } else {
            spent_pis.prev_private_commitment
        };

        let tx_hash = tx_inclusion_pis.tx.hash();
        let last_tx_hash = if is_valid {
            tx_hash
        } else {
            prev_balance_pis.last_tx_hash
        };

        let last_tx_insufficient_flags = if is_valid {
            spent_pis.insufficient_flags
        } else {
            prev_balance_pis.last_tx_insufficient_flags
        };

        // check prev balance pis
        if prev_balance_pis.pubkey != tx_inclusion_pis.pubkey {
            return Err(SendError::VerificationFailed(format!(
                "Invalid pubkey: expected {:?}, got {:?}",
                prev_balance_pis.pubkey, tx_inclusion_pis.pubkey
            )));
        }

        if prev_balance_pis.public_state != tx_inclusion_pis.prev_public_state {
            return Err(SendError::VerificationFailed(format!(
                "Invalid public state: expected {:?}, got {:?}",
                prev_balance_pis.public_state, tx_inclusion_pis.prev_public_state
            )));
        }

        let new_balance_pis = BalancePublicInputs {
            pubkey: tx_inclusion_pis.pubkey,
            private_commitment: new_private_commitment,
            last_tx_hash,
            last_tx_insufficient_flags,
            public_state: tx_inclusion_pis.new_public_state,
        };

        Ok(Self {
            spent_proof: spent_proof.clone(),
            tx_inclusion_proof: tx_inclusion_proof.clone(),
            prev_balance_pis: prev_balance_pis.clone(),
            new_balance_pis,
        })
    }
}

#[derive(Debug, Clone)]
pub struct SenderTarget<const D: usize> {
    pub spent_proof: ProofWithPublicInputsTarget<D>,
    pub tx_inclusion_proof: ProofWithPublicInputsTarget<D>,
    pub prev_balance_pis: BalancePublicInputsTarget,
    pub new_balance_pis: BalancePublicInputsTarget,
}

impl<const D: usize> SenderTarget<D> {
    pub fn new<F: RichField + Extendable<D>, C: GenericConfig<D, F = F> + 'static>(
        spent_vd: &VerifierCircuitData<F, C, D>,
        tx_inclusion_vd: &VerifierCircuitData<F, C, D>,
        builder: &mut CircuitBuilder<F, D>,
        is_checked: bool,
    ) -> Self
    where
        C::Hasher: AlgebraicHasher<F>,
    {
        // verify proof
        let spent_proof = add_proof_target_and_verify(spent_vd, builder);
        let tx_inclusion_proof = add_proof_target_and_verify(tx_inclusion_vd, builder);
        let spent_pis = SpentPublicInputsTarget::from_slice(&spent_proof.public_inputs);
        let tx_inclusion_pis =
            TxInclusionPublicInputsTarget::from_slice(&tx_inclusion_proof.public_inputs);

        let prev_balance_pis = BalancePublicInputsTarget::new(builder, is_checked);

        // check tx equivalence
        spent_pis.tx.connect(builder, &tx_inclusion_pis.tx);
        let is_valid = builder.and(spent_pis.is_valid, tx_inclusion_pis.is_valid);
        let new_private_commitment = PoseidonHashOutTarget::select(
            builder,
            is_valid,
            spent_pis.new_private_commitment,
            spent_pis.prev_private_commitment,
        );
        let tx_hash = tx_inclusion_pis.tx.hash::<F, C, D>(builder);
        let last_tx_hash = PoseidonHashOutTarget::select(
            builder,
            is_valid,
            tx_hash,
            prev_balance_pis.last_tx_hash,
        );
        let last_tx_insufficient_flags = InsufficientFlagsTarget::select(
            builder,
            is_valid,
            spent_pis.insufficient_flags,
            prev_balance_pis.last_tx_insufficient_flags,
        );

        // check prev balance pis
        prev_balance_pis
            .pubkey
            .connect(builder, tx_inclusion_pis.pubkey);
        prev_balance_pis
            .public_state
            .connect(builder, &tx_inclusion_pis.prev_public_state);
        let new_balance_pis = BalancePublicInputsTarget {
            pubkey: tx_inclusion_pis.pubkey,
            private_commitment: new_private_commitment,
            last_tx_hash,
            last_tx_insufficient_flags,
            public_state: tx_inclusion_pis.new_public_state,
        };
        Self {
            spent_proof: spent_proof.clone(),
            tx_inclusion_proof: tx_inclusion_proof.clone(),
            prev_balance_pis: prev_balance_pis.clone(),
            new_balance_pis,
        }
    }

    pub fn set_witness<
        W: WitnessWrite<F>,
        F: RichField + Extendable<D>,
        C: GenericConfig<D, F = F>,
    >(
        &self,
        witness: &mut W,
        value: &SenderValue<F, C, D>,
    ) where
        <C as GenericConfig<D>>::Hasher: AlgebraicHasher<F>,
    {
        witness.set_proof_with_pis_target(&self.spent_proof, &value.spent_proof);
        witness.set_proof_with_pis_target(&self.tx_inclusion_proof, &value.tx_inclusion_proof);
        self.prev_balance_pis
            .set_witness(witness, &value.prev_balance_pis);
        self.new_balance_pis
            .set_witness(witness, &value.new_balance_pis);
    }
}

pub struct SenderCircuit<F, C, const D: usize>
where
    F: RichField + Extendable<D>,
    C: GenericConfig<D, F = F>,
{
    pub data: CircuitData<F, C, D>,
    pub target: SenderTarget<D>,
    pub dummy_proof: DummyProof<F, C, D>,
}

impl<F, C, const D: usize> SenderCircuit<F, C, D>
where
    F: RichField + Extendable<D>,
    C: GenericConfig<D, F = F> + 'static,
    C::Hasher: AlgebraicHasher<F>,
{
    pub fn new(
        spent_vd: &VerifierCircuitData<F, C, D>,
        tx_inclusion_vd: &VerifierCircuitData<F, C, D>,
    ) -> Self {
        let config = CircuitConfig::default();
        let mut builder = CircuitBuilder::<F, D>::new(config.clone());
        let target = SenderTarget::new::<F, C>(spent_vd, tx_inclusion_vd, &mut builder, true);
        let pis = SenderPublicInputsTarget {
            prev_balance_pis: target.prev_balance_pis.clone(),
            new_balance_pis: target.new_balance_pis.clone(),
        };
        builder.register_public_inputs(&pis.to_vec());
        // add constant gate
        let constant_gate = ConstantGate::new(config.num_constants);
        builder.add_gate(constant_gate, vec![]);
        let data = builder.build();
        let dummy_proof = DummyProof::new(&data.common);
        Self {
            data,
            target,
            dummy_proof,
        }
    }

    pub fn prove(
        &self,
        value: &SenderValue<F, C, D>,
    ) -> Result<ProofWithPublicInputs<F, C, D>, SendError> {
        let mut pw = PartialWitness::<F>::new();
        self.target.set_witness(&mut pw, value);
        self.data
            .prove(pw)
            .map_err(|e| SendError::ProofGenerationError(format!("{:?}", e)))
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use plonky2::{
        field::goldilocks_field::GoldilocksField, plonk::config::PoseidonGoldilocksConfig,
    };

    use crate::{
        circuits::{
            balance::{
                balance_pis::BalancePublicInputs,
                send::{
                    spent_circuit::SpentCircuit,
                    tx_inclusion_circuit::{TxInclusionCircuit, TxInclusionValue},
                },
            },
            test_utils::{
                state_manager::ValidityStateManager,
                witness_generator::{construct_spent_and_transfer_witness, MockTxRequest},
            },
            validity::validity_processor::ValidityProcessor,
        },
        common::{
            private_state::FullPrivateState, public_state::PublicState,
            signature_content::key_set::KeySet, transfer::Transfer,
        },
        ethereum_types::address::Address,
    };

    use super::{SenderCircuit, SenderValue};

    type F = GoldilocksField;
    type C = PoseidonGoldilocksConfig;
    const D: usize = 2;

    #[test]
    fn test_sender_circuit() {
        let mut rng = rand::thread_rng();

        let key = KeySet::rand(&mut rng);
        let mut full_private_state = FullPrivateState::new();

        let validity_processor = Arc::new(ValidityProcessor::<F, C, D>::new());
        let mut validity_state_manager =
            ValidityStateManager::new(validity_processor.clone(), Address::default());

        let transfer = Transfer::rand(&mut rng);
        let (spent_witness, _) =
            construct_spent_and_transfer_witness(&mut full_private_state, &[transfer]).unwrap();

        let spent_circuit = SpentCircuit::<F, C, D>::new();
        let spent_proof = spent_circuit
            .prove(&spent_witness.to_value().unwrap())
            .unwrap();
        let tx_request = MockTxRequest {
            tx: spent_witness.tx,
            sender_key: key,
            will_return_sig: true,
        };
        let tx_witnesses = validity_state_manager
            .tick(true, &[tx_request], 0, 0)
            .unwrap();
        let block_number = validity_state_manager.get_block_number();

        let tx_witness = tx_witnesses[0].clone();
        let update_witness = validity_state_manager
            .get_update_witness(key.pubkey, block_number, 0, true)
            .unwrap();
        let sender_tree = tx_witness.get_sender_tree();
        let sender_leaf = sender_tree.get_leaf(tx_witness.tx_index as u64);
        let sender_merkle_proof = sender_tree.prove(tx_witness.tx_index as u64);
        let tx_inclusion_value = TxInclusionValue::new(
            &validity_processor.get_verifier_data(),
            key.pubkey,
            &PublicState::genesis(),
            &update_witness.validity_proof,
            &update_witness.block_merkle_proof,
            &update_witness.prev_account_membership_proof().unwrap(),
            tx_witness.tx_index,
            &tx_witness.tx,
            &tx_witness.tx_merkle_proof,
            &sender_leaf,
            &sender_merkle_proof,
        )
        .unwrap();
        let tx_inclusion_circuit =
            TxInclusionCircuit::<F, C, D>::new(&validity_processor.get_verifier_data());
        let tx_inclusion_proof = tx_inclusion_circuit.prove(&tx_inclusion_value).unwrap();

        let balance_pis = BalancePublicInputs::new(key.pubkey);
        let sender_value = SenderValue::new(
            &spent_circuit,
            &tx_inclusion_circuit,
            &spent_proof,
            &tx_inclusion_proof,
            &balance_pis,
        )
        .unwrap();

        let sender_circuit = SenderCircuit::<F, C, D>::new(
            &spent_circuit.data.verifier_data(),
            &tx_inclusion_circuit.data.verifier_data(),
        );
        let sender_proof = sender_circuit.prove(&sender_value).unwrap();
        sender_circuit.data.verify(sender_proof).unwrap();
    }
}
