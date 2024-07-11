use plonky2::{
    field::{extension::Extendable, types::Field},
    hash::hash_types::RichField,
    iop::{target::Target, witness::WitnessWrite},
    plonk::circuit_builder::CircuitBuilder,
};

use crate::{
    common::public_state::{PublicState, PublicStateTarget, PUBLIC_STATE_LEN},
    ethereum_types::{
        u256::{U256, U256_LEN},
        u32limb_trait::{U32LimbTargetTrait as _, U32LimbTrait as _},
    },
    utils::poseidon_hash_out::{PoseidonHashOut, PoseidonHashOutTarget, POSEIDON_HASH_OUT_LEN},
};

pub const BALANCE_PUBLIC_INPUTS_LEN: usize =
    U256_LEN + POSEIDON_HASH_OUT_LEN * 2 + PUBLIC_STATE_LEN;

#[derive(Debug, Clone)]
pub struct BalancePublicInputs {
    pub pubkey: U256<u32>,
    pub private_commitment: PoseidonHashOut,
    pub last_tx_hash: PoseidonHashOut,
    pub public_state: PublicState,
}

impl BalancePublicInputs {
    pub fn to_u64_vec(&self) -> Vec<u64> {
        let vec = vec![
            self.pubkey.to_u64_vec(),
            self.private_commitment.to_u64_vec(),
            self.last_tx_hash.to_u64_vec(),
            self.public_state.to_u64_vec(),
        ]
        .concat();
        assert_eq!(vec.len(), BALANCE_PUBLIC_INPUTS_LEN);
        vec
    }

    pub fn from_u64_vec(input: &[u64]) -> Self {
        assert_eq!(input.len(), BALANCE_PUBLIC_INPUTS_LEN);
        let pubkey = U256::from_u64_vec(&input[0..U256_LEN]);
        let private_commitment =
            PoseidonHashOut::from_u64_vec(&input[U256_LEN..U256_LEN + POSEIDON_HASH_OUT_LEN]);
        let last_tx_hash = PoseidonHashOut::from_u64_vec(
            &input[U256_LEN + POSEIDON_HASH_OUT_LEN..U256_LEN + 2 * POSEIDON_HASH_OUT_LEN],
        );
        let public_state =
            PublicState::from_u64_vec(&input[U256_LEN + 2 * POSEIDON_HASH_OUT_LEN..]);
        Self {
            pubkey,
            private_commitment,
            last_tx_hash,
            public_state,
        }
    }
}

#[derive(Debug, Clone)]
pub struct BalancePublicInputsTarget {
    pub pubkey: U256<Target>,
    pub private_commitment: PoseidonHashOutTarget,
    pub last_tx_hash: PoseidonHashOutTarget,
    pub public_state: PublicStateTarget,
}

impl BalancePublicInputsTarget {
    pub fn new<F: RichField + Extendable<D>, const D: usize>(
        builder: &mut CircuitBuilder<F, D>,
        is_checked: bool,
    ) -> Self {
        Self {
            pubkey: U256::<Target>::new(builder, is_checked),
            private_commitment: PoseidonHashOutTarget::new(builder),
            last_tx_hash: PoseidonHashOutTarget::new(builder),
            public_state: PublicStateTarget::new(builder, is_checked),
        }
    }

    pub fn connect<F: RichField + Extendable<D>, const D: usize>(
        &self,
        builder: &mut CircuitBuilder<F, D>,
        other: &Self,
    ) {
        self.pubkey.connect(builder, other.pubkey);
        self.private_commitment
            .connect(builder, other.private_commitment);
        self.last_tx_hash.connect(builder, other.last_tx_hash);
        self.public_state.connect(builder, &other.public_state);
    }

    pub fn set_witness<W: WitnessWrite<F>, F: Field>(
        &self,
        witness: &mut W,
        value: &BalancePublicInputs,
    ) {
        self.pubkey.set_witness(witness, value.pubkey);
        self.private_commitment
            .set_witness(witness, value.private_commitment);
        self.last_tx_hash.set_witness(witness, value.last_tx_hash);
        self.public_state.set_witness(witness, &value.public_state);
    }

    pub fn to_vec(&self) -> Vec<Target> {
        let vec = vec![
            self.pubkey.to_vec(),
            self.private_commitment.to_vec(),
            self.last_tx_hash.to_vec(),
            self.public_state.to_vec(),
        ]
        .concat();
        assert_eq!(vec.len(), BALANCE_PUBLIC_INPUTS_LEN);
        vec
    }

    pub fn from_vec(input: &[Target]) -> Self {
        assert_eq!(input.len(), BALANCE_PUBLIC_INPUTS_LEN);
        let pubkey = U256::<Target>::from_limbs(&input[0..U256_LEN]);
        let private_commitment =
            PoseidonHashOutTarget::from_vec(&input[U256_LEN..U256_LEN + POSEIDON_HASH_OUT_LEN]);
        let last_tx_hash = PoseidonHashOutTarget::from_vec(
            &input[U256_LEN + POSEIDON_HASH_OUT_LEN..U256_LEN + 2 * POSEIDON_HASH_OUT_LEN],
        );
        let public_state =
            PublicStateTarget::from_vec(&input[U256_LEN + 2 * POSEIDON_HASH_OUT_LEN..]);
        Self {
            pubkey,
            private_commitment,
            last_tx_hash,
            public_state,
        }
    }
}
