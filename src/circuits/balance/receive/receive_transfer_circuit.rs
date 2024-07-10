use crate::{
    circuits::utils::cyclic::{
        vd_from_pis_slice, vd_from_pis_slice_target, vd_to_vec, vd_to_vec_target,
    },
    common::{
        private_state::PrivateState,
        public_state::{PublicState, PublicStateTarget, PUBLIC_STATE_LEN},
        transfer::Transfer,
        trees::{block_hash_tree::BlockHashMerkleProof, transfer_tree::TransferMerkleProof},
        tx::Tx,
    },
    ethereum_types::{
        bytes32::Bytes32,
        u256::U256,
        u32limb_trait::{U32LimbTargetTrait as _, U32LimbTrait},
    },
    utils::poseidon_hash_out::{PoseidonHashOut, PoseidonHashOutTarget},
};
use plonky2::{
    field::extension::Extendable,
    hash::hash_types::RichField,
    iop::target::Target,
    plonk::{
        circuit_data::{CircuitConfig, VerifierCircuitTarget, VerifierOnlyCircuitData},
        config::{AlgebraicHasher, GenericConfig},
        proof::ProofWithPublicInputs,
    },
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
    pub balance_cricuit_vd: VerifierOnlyCircuitData<C, D>,
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
        vec.extend(vd_to_vec(config, &self.balance_cricuit_vd));
        vec
    }

    pub fn from_vec(config: &CircuitConfig, input: &[F]) -> Self {
        let non_vd = input[0..16 + PUBLIC_STATE_LEN]
            .into_iter()
            .map(|x| x.to_canonical_u64())
            .collect::<Vec<_>>();
        let prev_private_commitment = PoseidonHashOut::from_u64_vec(&non_vd[0..4]);
        let new_private_commitment = PoseidonHashOut::from_u64_vec(&non_vd[4..8]);
        let pubkey = U256::from_u64_vec(&non_vd[8..16]);
        let public_state = PublicState::from_u64_vec(&non_vd[16..16 + PUBLIC_STATE_LEN]);
        let balance_cricuit_vd = vd_from_pis_slice(input, config).unwrap();
        ReceiveTransferPublicInputs {
            prev_private_commitment,
            new_private_commitment,
            pubkey,
            public_state,
            balance_cricuit_vd,
        }
    }
}

#[derive(Debug, Clone)]
pub struct ReceiveTransferPublicInputsTarget {
    pub prev_private_commitment: PoseidonHashOutTarget,
    pub new_private_commitment: PoseidonHashOutTarget,
    pub pubkey: Bytes32<Target>,
    pub public_state: PublicStateTarget,
    pub balance_cricuit_vd: VerifierCircuitTarget,
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
        vec.extend(vd_to_vec_target(config, &self.balance_cricuit_vd));
        vec
    }

    pub fn from_vec(config: &CircuitConfig, input: &[Target]) -> Self {
        let prev_private_commitment = PoseidonHashOutTarget::from_vec(&input[0..4]);
        let new_private_commitment = PoseidonHashOutTarget::from_vec(&input[4..8]);
        let pubkey = Bytes32::<Target>::from_limbs(&input[8..16]);
        let public_state = PublicStateTarget::from_vec(&input[16..16 + PUBLIC_STATE_LEN]);
        let balance_cricuit_vd = vd_from_pis_slice_target(input, config).unwrap();
        ReceiveTransferPublicInputsTarget {
            prev_private_commitment,
            new_private_commitment,
            pubkey,
            public_state,
            balance_cricuit_vd,
        }
    }
}

#[derive(Debug, Clone)]
pub struct ReceiveTransferValue<
    F: RichField + Extendable<D>,
    C: GenericConfig<D, F = F> + 'static,
    const D: usize,
> {
    pub tx: Tx,
    pub transfer_merkle_proof: TransferMerkleProof,
    pub transfer_index: usize,
    pub transfer: Transfer,
    pub balance_proof: ProofWithPublicInputs<F, C, D>,
    pub public_state: PublicState,
    pub prev_private_satet: PrivateState,
    pub new_private_state: PrivateState,
    pub prev_private_commitment: PoseidonHashOut,
    pub new_private_commitment: PoseidonHashOut,
    pub block_merkle_proof: BlockHashMerkleProof,
}
