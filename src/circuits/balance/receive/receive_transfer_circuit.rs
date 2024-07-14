use crate::{
    circuits::utils::cyclic::{
        vd_from_pis_slice, vd_from_pis_slice_target, vd_to_vec, vd_to_vec_target,
    },
    common::{
        public_state::{PublicState, PublicStateTarget, PUBLIC_STATE_LEN},
        trees::block_hash_tree::{BlockHashMerkleProof, BlockHashMerkleProofTarget},
    },
    constants::BLOCK_HASH_TREE_HEIGHT,
    ethereum_types::{
        bytes32::Bytes32,
        u256::U256,
        u32limb_trait::{U32LimbTargetTrait as _, U32LimbTrait},
    },
    utils::{
        conversion::ToU64 as _,
        dummy::DummyProof,
        poseidon_hash_out::{PoseidonHashOut, PoseidonHashOutTarget},
        recursivable::Recursivable,
    },
};
use plonky2::{
    field::extension::Extendable,
    hash::hash_types::RichField,
    iop::{
        target::Target,
        witness::{PartialWitness, WitnessWrite},
    },
    plonk::{
        circuit_builder::CircuitBuilder,
        circuit_data::{
            CircuitConfig, CircuitData, CommonCircuitData, VerifierCircuitTarget,
            VerifierOnlyCircuitData,
        },
        config::{AlgebraicHasher, GenericConfig},
        proof::ProofWithPublicInputs,
    },
};

use super::receive_targets::{
    private_state_transition::{PrivateStateTransitionTarget, PrivateStateTransitionValue},
    transfer_inclusion::{TransferInclusionTarget, TransferInclusionValue},
};

#[derive(Debug, Clone)]
pub struct ReceiveTransferPublicInputs<
    F: RichField + Extendable<D>,
    C: GenericConfig<D, F = F>,
    const D: usize,
> {
    pub prev_private_commitment: PoseidonHashOut,
    pub new_private_commitment: PoseidonHashOut,
    pub pubkey: U256<u32>,
    pub public_state: PublicState,
    pub balance_circuit_vd: VerifierOnlyCircuitData<C, D>,
}

impl<F: RichField + Extendable<D>, C: GenericConfig<D, F = F>, const D: usize>
    ReceiveTransferPublicInputs<F, C, D>
where
    <C as GenericConfig<D>>::Hasher: AlgebraicHasher<F>,
{
    pub fn to_vec(&self, config: &CircuitConfig) -> Vec<F> {
        let mut vec = vec![
            self.prev_private_commitment.to_u64_vec(),
            self.new_private_commitment.to_u64_vec(),
            self.pubkey.to_u64_vec(),
            self.public_state.to_u64_vec(),
        ]
        .concat()
        .into_iter()
        .map(|x| F::from_canonical_u64(x))
        .collect::<Vec<_>>();
        vec.extend(vd_to_vec(config, &self.balance_circuit_vd));
        vec
    }

    pub fn from_vec(config: &CircuitConfig, input: &[F]) -> Self {
        let non_vd = input[0..16 + PUBLIC_STATE_LEN].to_u64_vec();
        let prev_private_commitment = PoseidonHashOut::from_u64_vec(&non_vd[0..4]);
        let new_private_commitment = PoseidonHashOut::from_u64_vec(&non_vd[4..8]);
        let pubkey = U256::from_u64_vec(&non_vd[8..16]);
        let public_state = PublicState::from_u64_vec(&non_vd[16..16 + PUBLIC_STATE_LEN]);
        let balance_circuit_vd = vd_from_pis_slice(input, config).unwrap();
        ReceiveTransferPublicInputs {
            prev_private_commitment,
            new_private_commitment,
            pubkey,
            public_state,
            balance_circuit_vd,
        }
    }
}

#[derive(Debug, Clone)]
pub struct ReceiveTransferPublicInputsTarget {
    pub prev_private_commitment: PoseidonHashOutTarget,
    pub new_private_commitment: PoseidonHashOutTarget,
    pub pubkey: U256<Target>,
    pub public_state: PublicStateTarget,
    pub balance_circuit_vd: VerifierCircuitTarget,
}

impl ReceiveTransferPublicInputsTarget {
    pub fn to_vec(&self, config: &CircuitConfig) -> Vec<Target> {
        let mut vec = vec![
            self.prev_private_commitment.to_vec(),
            self.new_private_commitment.to_vec(),
            self.pubkey.to_vec(),
            self.public_state.to_vec(),
        ]
        .concat();
        vec.extend(vd_to_vec_target(config, &self.balance_circuit_vd));
        vec
    }

    pub fn from_vec(config: &CircuitConfig, input: &[Target]) -> Self {
        let prev_private_commitment = PoseidonHashOutTarget::from_vec(&input[0..4]);
        let new_private_commitment = PoseidonHashOutTarget::from_vec(&input[4..8]);
        let pubkey = U256::<Target>::from_limbs(&input[8..16]);
        let public_state = PublicStateTarget::from_vec(&input[16..16 + PUBLIC_STATE_LEN]);
        let balance_circuit_vd = vd_from_pis_slice_target(input, config).unwrap();
        ReceiveTransferPublicInputsTarget {
            prev_private_commitment,
            new_private_commitment,
            pubkey,
            public_state,
            balance_circuit_vd,
        }
    }
}

#[derive(Debug, Clone)]
pub struct ReceiveTransferValue<
    F: RichField + Extendable<D>,
    C: GenericConfig<D, F = F> + 'static,
    const D: usize,
> {
    pub pubkey: U256<u32>,
    pub public_state: PublicState,
    pub block_merkle_proof: BlockHashMerkleProof,
    pub transfer_inclusion: TransferInclusionValue<F, C, D>,
    pub private_state_transition: PrivateStateTransitionValue,
    pub prev_private_commitment: PoseidonHashOut,
    pub new_private_commitment: PoseidonHashOut,
    pub balance_circuit_vd: VerifierOnlyCircuitData<C, D>,
}

impl<F: RichField + Extendable<D>, C: GenericConfig<D, F = F>, const D: usize>
    ReceiveTransferValue<F, C, D>
{
    pub fn new(
        public_state: &PublicState,
        block_merkle_proof: &BlockHashMerkleProof,
        transfer_inclusion: &TransferInclusionValue<F, C, D>,
        private_state_transition: &PrivateStateTransitionValue,
    ) -> Self
    where
        C::Hasher: AlgebraicHasher<F>,
    {
        // verify public state inclusion
        block_merkle_proof
            .verify(
                &transfer_inclusion.public_state.block_hash,
                transfer_inclusion.public_state.block_number as usize,
                public_state.block_tree_root,
            )
            .expect("Invalid block merkle proof");

        let transfer = transfer_inclusion.transfer;
        let nullifier: Bytes32<u32> = transfer.commitment().into();
        let pubkey = transfer.recipient.to_pubkey().expect("Invalid recipient");
        assert_eq!(private_state_transition.token_index, transfer.token_index);
        assert_eq!(private_state_transition.amount, transfer.amount);
        assert_eq!(private_state_transition.nullifier, nullifier);
        let prev_private_commitment = private_state_transition.prev_private_state.commitment();
        let new_private_commitment = private_state_transition.new_private_state.commitment();
        let balance_circuit_vd = transfer_inclusion.balance_circuit_vd.clone();
        ReceiveTransferValue {
            pubkey,
            public_state: public_state.clone(),
            block_merkle_proof: block_merkle_proof.clone(),
            transfer_inclusion: transfer_inclusion.clone(),
            private_state_transition: private_state_transition.clone(),
            prev_private_commitment,
            new_private_commitment,
            balance_circuit_vd,
        }
    }
}

#[derive(Debug, Clone)]
pub struct ReceiveTransferTarget<const D: usize> {
    pub pubkey: U256<Target>,
    pub public_state: PublicStateTarget,
    pub block_merkle_proof: BlockHashMerkleProofTarget,
    pub transfer_inclusion: TransferInclusionTarget<D>,
    pub private_state_transition: PrivateStateTransitionTarget,
    pub prev_private_commitment: PoseidonHashOutTarget,
    pub new_private_commitment: PoseidonHashOutTarget,
    pub balance_circuit_vd: VerifierCircuitTarget,
}

impl<const D: usize> ReceiveTransferTarget<D> {
    pub fn new<F: RichField + Extendable<D>, C: GenericConfig<D, F = F> + 'static>(
        balance_common_data: &CommonCircuitData<F, D>,
        builder: &mut CircuitBuilder<F, D>,
        is_checked: bool,
    ) -> Self
    where
        <C as GenericConfig<D>>::Hasher: AlgebraicHasher<F>,
    {
        let public_state = PublicStateTarget::new(builder, is_checked);
        let block_merkle_proof = BlockHashMerkleProofTarget::new(builder, BLOCK_HASH_TREE_HEIGHT);
        let transfer_inclusion =
            TransferInclusionTarget::new::<F, C>(balance_common_data, builder, is_checked);
        let private_state_transition =
            PrivateStateTransitionTarget::new::<F, C, D>(builder, is_checked);
        block_merkle_proof.verify::<F, C, D>(
            builder,
            &transfer_inclusion.public_state.block_hash,
            transfer_inclusion.public_state.block_number,
            public_state.block_tree_root,
        );

        let transfer = transfer_inclusion.transfer.clone();
        let transfer_commitment = transfer.commitment(builder);
        let nullifier: Bytes32<Target> = Bytes32::from_hash_out(builder, transfer_commitment);
        let pubkey = transfer.recipient.to_pubkey(builder);
        builder.connect(private_state_transition.token_index, transfer.token_index);
        private_state_transition
            .amount
            .connect(builder, transfer.amount);
        private_state_transition
            .nullifier
            .connect(builder, nullifier);

        let prev_private_commitment = private_state_transition
            .prev_private_state
            .commitment(builder);
        let new_private_commitment = private_state_transition
            .new_private_state
            .commitment(builder);
        let balance_circuit_vd = transfer_inclusion.balance_circuit_vd.clone();
        ReceiveTransferTarget {
            pubkey,
            public_state,
            block_merkle_proof,
            transfer_inclusion,
            private_state_transition,
            prev_private_commitment,
            new_private_commitment,
            balance_circuit_vd,
        }
    }

    pub fn set_witness<
        F: RichField + Extendable<D>,
        C: GenericConfig<D, F = F>,
        W: WitnessWrite<F>,
    >(
        &self,
        witness: &mut W,
        value: &ReceiveTransferValue<F, C, D>,
    ) where
        <C as GenericConfig<D>>::Hasher: AlgebraicHasher<F>,
    {
        self.pubkey.set_witness(witness, value.pubkey);
        self.public_state.set_witness(witness, &value.public_state);
        self.block_merkle_proof
            .set_witness(witness, &value.block_merkle_proof);
        self.transfer_inclusion
            .set_witness(witness, &value.transfer_inclusion);
        self.private_state_transition
            .set_witness(witness, &value.private_state_transition);
        self.prev_private_commitment
            .set_witness(witness, value.prev_private_commitment);
        self.new_private_commitment
            .set_witness(witness, value.new_private_commitment);
        witness.set_verifier_data_target(&self.balance_circuit_vd, &value.balance_circuit_vd);
    }
}

pub struct ReceiveTransferCircuit<F, C, const D: usize>
where
    F: RichField + Extendable<D>,
    C: GenericConfig<D, F = F>,
{
    pub data: CircuitData<F, C, D>,
    pub target: ReceiveTransferTarget<D>,
    pub dummy_proof: DummyProof<F, C, D>,
}

impl<F, C, const D: usize> ReceiveTransferCircuit<F, C, D>
where
    F: RichField + Extendable<D>,
    C: GenericConfig<D, F = F> + 'static,
    C::Hasher: AlgebraicHasher<F>,
{
    pub fn new(balance_common_data: &CommonCircuitData<F, D>) -> Self {
        let config = CircuitConfig::default();
        let mut builder = CircuitBuilder::<F, D>::new(config.clone());
        let target =
            ReceiveTransferTarget::<D>::new::<F, C>(balance_common_data, &mut builder, true);
        let pis = ReceiveTransferPublicInputsTarget {
            pubkey: target.pubkey,
            prev_private_commitment: target.prev_private_commitment,
            new_private_commitment: target.new_private_commitment,
            public_state: target.public_state.clone(),
            balance_circuit_vd: target.balance_circuit_vd.clone(),
        };
        builder.register_public_inputs(&pis.to_vec(&config));
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
        value: &ReceiveTransferValue<F, C, D>,
    ) -> anyhow::Result<ProofWithPublicInputs<F, C, D>> {
        let mut pw = PartialWitness::<F>::new();
        self.target.set_witness(&mut pw, value);
        self.data.prove(pw)
    }
}

impl<F, C, const D: usize> Recursivable<F, C, D> for ReceiveTransferCircuit<F, C, D>
where
    F: RichField + Extendable<D>,
    C: GenericConfig<D, F = F> + 'static,
    C::Hasher: AlgebraicHasher<F>,
{
    fn circuit_data(&self) -> &CircuitData<F, C, D> {
        &self.data
    }
}
