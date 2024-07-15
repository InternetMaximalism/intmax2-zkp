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

use crate::{
    circuits::{
        balance::balance_pis::{BalancePublicInputs, BalancePublicInputsTarget},
        utils::cyclic::{vd_from_pis_slice, vd_from_pis_slice_target},
    },
    common::{
        public_state::{PublicState, PublicStateTarget},
        transfer::{Transfer, TransferTarget},
        trees::transfer_tree::{TransferMerkleProof, TransferMerkleProofTarget},
        tx::{Tx, TxTarget},
    },
    constants::TRANSFER_TREE_HEIGHT,
    utils::leafable::{Leafable as _, LeafableTarget},
};

// Data to verify that the balance proof includes the transfer and that the transfer is valid
#[derive(Debug, Clone)]
pub struct TransferInclusionValue<
    F: RichField + Extendable<D>,
    C: GenericConfig<D, F = F> + 'static,
    const D: usize,
> {
    pub transfer: Transfer,
    pub transfer_index: usize,
    pub transfer_merkle_proof: TransferMerkleProof,
    pub tx: Tx,
    pub balance_proof: ProofWithPublicInputs<F, C, D>,
    pub balance_circuit_vd: VerifierOnlyCircuitData<C, D>,
    pub public_state: PublicState,
}

impl<F: RichField + Extendable<D>, C: GenericConfig<D, F = F>, const D: usize>
    TransferInclusionValue<F, C, D>
where
    <C as GenericConfig<D>>::Hasher: AlgebraicHasher<F>,
{
    pub fn new(
        balance_verifier_data: &VerifierCircuitData<F, C, D>,
        transfer: &Transfer,
        transfer_index: usize,
        transfer_merkle_proof: &TransferMerkleProof,
        tx: &Tx,
        balance_proof: &ProofWithPublicInputs<F, C, D>,
    ) -> Self {
        let balance_pis = BalancePublicInputs::from_pis(&balance_proof.public_inputs);
        let balance_circuit_vd = vd_from_pis_slice::<F, C, D>(
            &balance_proof.public_inputs,
            &balance_verifier_data.common.config,
        )
        .expect("Failed to parse balance vd");
        assert_eq!(
            balance_circuit_vd, balance_verifier_data.verifier_only,
            "Balance vd mismatch"
        );
        balance_verifier_data
            .verify(balance_proof.clone())
            .expect("Balance proof is invalid");
        assert_eq!(balance_pis.last_tx_hash, tx.hash());
        let _is_insufficient = balance_pis
            .last_tx_insufficient_flags
            .random_access(transfer_index);
        #[cfg(not(feature = "skip_insufficient_check"))]
        assert!(!_is_insufficient, "Transfer is insufficient");
        // check merkle proof
        transfer_merkle_proof
            .verify(&transfer, transfer_index, tx.transfer_tree_root)
            .expect("Invalid transfer merkle proof");
        Self {
            transfer: transfer.clone(),
            transfer_index,
            transfer_merkle_proof: transfer_merkle_proof.clone(),
            tx: tx.clone(),
            balance_proof: balance_proof.clone(),
            balance_circuit_vd,
            public_state: balance_pis.public_state.clone(),
        }
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

        let balance_proof = builder.add_virtual_proof_with_pis(&balance_common_data);
        let balance_pis = BalancePublicInputsTarget::from_pis(&balance_proof.public_inputs);
        let balance_circuit_vd =
            vd_from_pis_slice_target(&balance_proof.public_inputs, &balance_common_data.config)
                .expect("Failed to parse balance vd");
        builder.verify_proof::<C>(&balance_proof, &balance_circuit_vd, &balance_common_data);

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
            F::from_canonical_usize(value.transfer_index),
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
    use plonky2::{
        field::goldilocks_field::GoldilocksField,
        iop::witness::PartialWitness,
        plonk::{
            circuit_builder::CircuitBuilder, circuit_data::CircuitConfig,
            config::PoseidonGoldilocksConfig,
        },
    };

    use crate::{
        circuits::balance::{
            balance_processor::BalanceProcessor,
            receive::receive_targets::transfer_inclusion::TransferInclusionTarget,
        },
        common::{generic_address::GenericAddress, salt::Salt, transfer::Transfer},
        ethereum_types::u256::U256,
        mock::{
            block_builder::MockBlockBuilder, local_manager::LocalManager,
            sync_balance_prover::SyncBalanceProver, sync_validity_prover::SyncValidityProver,
        },
    };

    use super::TransferInclusionValue;

    type F = GoldilocksField;
    type C = PoseidonGoldilocksConfig;
    const D: usize = 2;

    #[test]
    fn transfer_inclusion() {
        let mut rng = rand::thread_rng();
        let mut block_builder = MockBlockBuilder::new();
        let mut sync_validity_prover = SyncValidityProver::<F, C, D>::new();
        let balance_processor = BalanceProcessor::new(sync_validity_prover.validity_circuit());

        // personal data
        let mut alice = LocalManager::new_rand(&mut rng);
        let bob = LocalManager::new_rand(&mut rng);
        let mut alice_balance_prover = SyncBalanceProver::<F, C, D>::new();

        // send tx
        let transfer = Transfer {
            recipient: GenericAddress::from_pubkey(bob.get_pubkey()),
            token_index: 0,
            amount: U256::<u32>::rand_small(&mut rng),
            salt: Salt::rand(&mut rng),
        };
        let send_witness = alice.send_tx_and_update(&mut rng, &mut block_builder, &[transfer]);
        let included_block_number = send_witness.get_included_block_number();
        alice_balance_prover.sync_send(
            &mut sync_validity_prover,
            &balance_processor,
            &block_builder,
            &alice,
        );
        let alice_balance_proof = alice_balance_prover.last_balance_proof.clone().unwrap();

        let transfer_witness = &alice.get_transfer_witnesses(included_block_number).unwrap()[0];
        assert_eq!(transfer, transfer_witness.transfer);
        // receive tx
        let value = TransferInclusionValue::new(
            &balance_processor.get_verifier_data(),
            &transfer,
            transfer_witness.transfer_index,
            &transfer_witness.transfer_merkle_proof,
            &transfer_witness.tx_witness.tx,
            &alice_balance_proof,
        );

        let mut builder = CircuitBuilder::new(CircuitConfig::default());
        let target = TransferInclusionTarget::new::<F, C>(
            &balance_processor.get_verifier_data().common,
            &mut builder,
            true,
        );
        let mut pw = PartialWitness::<F>::new();
        target.set_witness(&mut pw, &value);

        let data = builder.build::<C>();
        let _ = data.prove(pw).unwrap();
    }
}
