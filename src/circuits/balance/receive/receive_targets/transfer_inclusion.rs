use crate::{
    circuits::balance::balance_pis::{BalancePublicInputs, BalancePublicInputsTarget},
    common::{
        public_state::{PublicState, PublicStateTarget},
        transfer::{Transfer, TransferTarget},
        trees::transfer_tree::{TransferMerkleProof, TransferMerkleProofTarget},
        tx::{Tx, TxTarget},
    },
    constants::TRANSFER_TREE_HEIGHT,
    utils::{
        cyclic::{vd_from_pis_slice, vd_from_pis_slice_target},
        leafable::{Leafable as _, LeafableTarget},
    },
};
use super::error::ReceiveTargetsError;
use plonky2::{
    field::extension::Extendable,
    hash::hash_types::RichField,
    iop::{target::Target, witness::WitnessWrite},
    plonk::{
        circuit_builder::CircuitBuilder,
        circuit_data::{
            CommonCircuitData, VerifierCircuitData, VerifierCircuitTarget, VerifierOnlyCircuitData,
        },
        config::{AlgebraicHasher, GenericConfig},
        proof::{ProofWithPublicInputs, ProofWithPublicInputsTarget},
    },
};

// Data to verify that the balance proof includes the transfer and that the transfer is valid
#[derive(Debug, Clone)]
pub struct TransferInclusionValue<
    F: RichField + Extendable<D>,
    C: GenericConfig<D, F = F> + 'static,
    const D: usize,
> {
    pub transfer: Transfer,  // transfer to be proved included
    pub transfer_index: u32, // the index of the transfer in the tranfer merkle tree
    pub transfer_merkle_proof: TransferMerkleProof, // transfer merkle proof that proves i
    pub tx: Tx,              // tx that includes the transfer
    pub balance_proof: ProofWithPublicInputs<F, C, D>, // balance proof that includes the tx
    pub balance_circuit_vd: VerifierOnlyCircuitData<C, D>, // balance circuit verifier data
    pub public_state: PublicState, // public state of the balance proof
}

impl<F: RichField + Extendable<D>, C: GenericConfig<D, F = F>, const D: usize>
    TransferInclusionValue<F, C, D>
where
    <C as GenericConfig<D>>::Hasher: AlgebraicHasher<F>,
{
    pub fn new(
        balance_verifier_data: &VerifierCircuitData<F, C, D>,
        transfer: &Transfer,
        transfer_index: u32,
        transfer_merkle_proof: &TransferMerkleProof,
        tx: &Tx,
        balance_proof: &ProofWithPublicInputs<F, C, D>,
    ) -> Result<Self, ReceiveTargetsError> {
        let balance_pis = BalancePublicInputs::from_pis(&balance_proof.public_inputs);
        let balance_circuit_vd = vd_from_pis_slice::<F, C, D>(
            &balance_proof.public_inputs,
            &balance_verifier_data.common.config,
        )
        .map_err(|e| ReceiveTargetsError::VerificationFailed(
            format!("Failed to parse balance vd: {}", e)
        ))?;
        
        if balance_circuit_vd != balance_verifier_data.verifier_only {
            return Err(ReceiveTargetsError::VerificationFailed(
                "Balance vd mismatch".to_string()
            ));
        }
        
        balance_verifier_data
            .verify(balance_proof.clone())
            .map_err(|e| ReceiveTargetsError::VerificationFailed(
                format!("Failed to verify balance proof: {}", e)
            ))?;
            
        if balance_pis.last_tx_hash != tx.hash() {
            return Err(ReceiveTargetsError::VerificationFailed(
                format!("Last tx hash mismatch: expected {:?}, got {:?}", 
                    tx.hash(), balance_pis.last_tx_hash)
            ));
        }
        
        let _is_insufficient = balance_pis
            .last_tx_insufficient_flags
            .random_access(transfer_index as usize);
            
        #[cfg(not(feature = "skip_insufficient_check"))]
        if _is_insufficient {
            return Err(ReceiveTargetsError::VerificationFailed(
                format!("Transfer is insufficient at index {}", transfer_index)
            ));
        }
        
        // check merkle proof
        transfer_merkle_proof
            .verify(transfer, transfer_index as u64, tx.transfer_tree_root)
            .map_err(|e| ReceiveTargetsError::VerificationFailed(
                format!("Invalid transfer merkle proof: {}", e)
            ))?;
            
        Ok(Self {
            transfer: *transfer,
            transfer_index,
            transfer_merkle_proof: transfer_merkle_proof.clone(),
            tx: *tx,
            balance_proof: balance_proof.clone(),
            balance_circuit_vd,
            public_state: balance_pis.public_state.clone(),
        })
    }
}

#[derive(Debug, Clone)]
pub struct TransferInclusionTarget<const D: usize> {
    pub transfer: TransferTarget,
    pub transfer_index: Target,
    pub transfer_merkle_proof: TransferMerkleProofTarget,
    pub tx: TxTarget,
    pub balance_proof: ProofWithPublicInputsTarget<D>,
    pub balance_circuit_vd: VerifierCircuitTarget,
    pub public_state: PublicStateTarget,
}

impl<const D: usize> TransferInclusionTarget<D> {
    pub fn new<F: RichField + Extendable<D>, C: GenericConfig<D, F = F> + 'static>(
        balance_common_data: &CommonCircuitData<F, D>,
        builder: &mut CircuitBuilder<F, D>,
        is_checked: bool,
    ) -> Self
    where
        <C as GenericConfig<D>>::Hasher: AlgebraicHasher<F>,
    {
        let transfer = TransferTarget::new(builder, is_checked);
        let transfer_index = builder.add_virtual_target();
        let transfer_merkle_proof = TransferMerkleProofTarget::new(builder, TRANSFER_TREE_HEIGHT);
        let tx = TxTarget::new(builder);

        let balance_proof = builder.add_virtual_proof_with_pis(balance_common_data);
        let balance_pis = BalancePublicInputsTarget::from_pis(&balance_proof.public_inputs);
        let balance_circuit_vd =
            vd_from_pis_slice_target(&balance_proof.public_inputs, &balance_common_data.config)
                .expect("Failed to parse balance vd");
        builder.verify_proof::<C>(&balance_proof, &balance_circuit_vd, balance_common_data);

        let tx_hash = tx.hash::<F, C, D>(builder);
        balance_pis.last_tx_hash.connect(builder, tx_hash);
        let _is_insufficient = balance_pis
            .last_tx_insufficient_flags
            .random_access(builder, transfer_index);
        #[cfg(not(feature = "skip_insufficient_check"))]
        builder.assert_zero(_is_insufficient.target);
        // check merkle proof
        transfer_merkle_proof.verify::<F, C, D>(
            builder,
            &transfer,
            transfer_index,
            tx.transfer_tree_root,
        );
        Self {
            transfer,
            transfer_index,
            transfer_merkle_proof,
            tx,
            balance_proof,
            balance_circuit_vd,
            public_state: balance_pis.public_state,
        }
    }

    pub fn set_witness<
        F: RichField + Extendable<D>,
        C: GenericConfig<D, F = F>,
        W: WitnessWrite<F>,
    >(
        &self,
        witness: &mut W,
        value: &TransferInclusionValue<F, C, D>,
    ) where
        <C as GenericConfig<D>>::Hasher: AlgebraicHasher<F>,
    {
        self.transfer.set_witness(witness, value.transfer);
        witness.set_target(
            self.transfer_index,
            F::from_canonical_u32(value.transfer_index),
        );
        self.transfer_merkle_proof
            .set_witness(witness, &value.transfer_merkle_proof);
        self.tx.set_witness(witness, value.tx);
        witness.set_proof_with_pis_target(&self.balance_proof, &value.balance_proof);
        witness.set_verifier_data_target(&self.balance_circuit_vd, &value.balance_circuit_vd);
        self.public_state.set_witness(witness, &value.public_state);
    }
}

#[cfg(test)]
#[cfg(feature = "skip_insufficient_check")]
mod tests {
    use std::sync::Arc;

    use plonky2::{
        field::goldilocks_field::GoldilocksField,
        iop::witness::PartialWitness,
        plonk::{
            circuit_builder::CircuitBuilder, circuit_data::CircuitConfig,
            config::PoseidonGoldilocksConfig,
        },
    };

    use crate::{
        circuits::{
            balance::{
                balance_processor::BalanceProcessor,
                receive::receive_targets::transfer_inclusion::TransferInclusionTarget,
                send::spent_circuit::SpentCircuit,
            },
            test_utils::{
                state_manager::ValidityStateManager,
                witness_generator::{construct_spent_and_transfer_witness, MockTxRequest},
            },
            validity::validity_processor::ValidityProcessor,
        },
        common::{private_state::FullPrivateState, signature::key_set::KeySet, transfer::Transfer},
    };

    use super::TransferInclusionValue;

    type F = GoldilocksField;
    type C = PoseidonGoldilocksConfig;
    const D: usize = 2;

    #[test]
    fn transfer_inclusion() -> Result<(), anyhow::Error> {
        let mut rng = rand::thread_rng();
        let validity_processor = Arc::new(ValidityProcessor::<F, C, D>::new());
        let balance_processor = BalanceProcessor::new(&validity_processor.get_verifier_data());
        let spent_circuit = SpentCircuit::new();
        let mut validity_state_manager = ValidityStateManager::new(validity_processor.clone());

        // local state
        let alice_key = KeySet::rand(&mut rng);
        let mut alice_state = FullPrivateState::new();

        // alice send transfer
        let transfer = Transfer::rand(&mut rng);

        let (spent_witness, transfer_witnesses) =
            construct_spent_and_transfer_witness(&mut alice_state, &[transfer])?;
        let spent_proof = spent_circuit.prove(&spent_witness.to_value()?)?;
        let tx_request = MockTxRequest {
            tx: spent_witness.tx,
            sender_key: alice_key,
            will_return_sig: true,
        };
        let transfer_witness = transfer_witnesses[0].clone();
        let tx_witnesses = validity_state_manager.tick(true, &[tx_request])?;
        let update_witness =
            validity_state_manager.get_update_witness(alice_key.pubkey, 1, 0, true)?;
        let alice_balance_proof = balance_processor.prove_send(
            &validity_processor.get_verifier_data(),
            alice_key.pubkey,
            &tx_witnesses[0],
            &update_witness,
            &spent_proof,
            &None,
        )?;

        let transfer_inclusion_value = TransferInclusionValue::new(
            &balance_processor.get_verifier_data(),
            &transfer,
            transfer_witness.transfer_index,
            &transfer_witness.transfer_merkle_proof,
            &transfer_witness.tx,
            &alice_balance_proof,
        )?;

        let mut builder = CircuitBuilder::new(CircuitConfig::default());
        let target = TransferInclusionTarget::new::<F, C>(
            &balance_processor.get_verifier_data().common,
            &mut builder,
            true,
        );
        let mut pw = PartialWitness::<F>::new();
        target.set_witness(&mut pw, &transfer_inclusion_value);

        let data = builder.build::<C>();
        let _ = data.prove(pw)?;

        Ok(())
    }
}
