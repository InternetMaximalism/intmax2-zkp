use crate::{
    circuits::utils::cyclic::{
        vd_from_pis_slice, vd_from_pis_slice_target, vd_to_vec, vd_to_vec_target,
    },
    common::{
        private_state::PrivateState,
        public_state::{PublicState, PublicStateTarget, PUBLIC_STATE_LEN},
        transfer::Transfer,
        trees::{
            asset_tree::{AssetLeaf, AssetMerkleProof},
            block_hash_tree::BlockHashMerkleProof,
            nullifier_tree::NullifierInsersionProof,
            transfer_tree::TransferMerkleProof,
        },
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
        circuit_data::{
            CircuitConfig, VerifierCircuitData, VerifierCircuitTarget, VerifierOnlyCircuitData,
        },
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
    pub balance_cricuit_vd: VerifierOnlyCircuitData<C, D>,
    pub balance_proof: ProofWithPublicInputs<F, C, D>,
    pub public_state: PublicState,
    pub prev_private_satet: PrivateState,
    pub new_private_state: PrivateState,
    pub prev_private_commitment: PoseidonHashOut,
    pub new_private_commitment: PoseidonHashOut,
    pub block_merkle_proof: BlockHashMerkleProof,
    pub nullifier_proof: NullifierInsersionProof,
    pub prev_asset_leaf: AssetLeaf,
    pub asset_merkle_proof: AssetMerkleProof,
}

impl<F: RichField + Extendable<D>, C: GenericConfig<D, F = F>, const D: usize>
    ReceiveTransferValue<F, C, D>
{
    pub fn new(
        tx: Tx,
        transfer_merkle_proof: TransferMerkleProof,
        transfer_index: usize,
        transfer: Transfer,
        balance_proof: ProofWithPublicInputs<F, C, D>,
        public_state: PublicState,
        prev_private_satet: PrivateState,
        block_merkle_proof: BlockHashMerkleProof,
        nullifier_proof: NullifierInsersionProof,
        prev_asset_leaf: AssetLeaf,
        asset_merkle_proof: AssetMerkleProof,
    ) -> Self {
        // verify balance proof
        // let balance_pis =

        // let balance_circuit_verifier_data = VerifierCircuitData {
        //     verifier_only: todo!(),
        //     common: todo!(),
        // };
        // balance_circuit_verifier_data.verify(proof_with_pis);

        // verify transfer inclusion

        // ReceiveTransferValue {
        //     tx,
        //     transfer_merkle_proof,
        //     transfer_index,
        //     transfer,
        //     balance_proof,
        //     public_state,
        //     prev_private_satet,
        //     new_private_state,
        //     prev_private_commitment,
        //     new_private_commitment,
        //     block_merkle_proof,
        //     nullifier_proof,
        //     prev_asset_leaf,
        //     asset_merkle_proof,
        // }

        todo!()
    }
}
