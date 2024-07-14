use plonky2::{
    field::{
        extension::Extendable,
        types::{Field, PrimeField64},
    },
    hash::hash_types::RichField,
    iop::{
        target::{BoolTarget, Target},
        witness::WitnessWrite,
    },
    plonk::circuit_builder::CircuitBuilder,
};

use crate::{
    common::{
        insufficient_flags::{InsufficientFlags, InsufficientFlagsTarget, INSUFFICIENT_FLAGS_LEN},
        private_state::PrivateState,
        public_state::{PublicState, PublicStateTarget, PUBLIC_STATE_LEN},
    },
    ethereum_types::{
        u256::{U256, U256_LEN},
        u32limb_trait::{U32LimbTargetTrait as _, U32LimbTrait as _},
    },
    utils::{
        conversion::ToU64 as _,
        poseidon_hash_out::{PoseidonHashOut, PoseidonHashOutTarget, POSEIDON_HASH_OUT_LEN},
    },
};

pub const BALANCE_PUBLIC_INPUTS_LEN: usize =
    U256_LEN + POSEIDON_HASH_OUT_LEN * 2 + INSUFFICIENT_FLAGS_LEN + PUBLIC_STATE_LEN;

#[derive(Debug, Clone, PartialEq)]
pub struct BalancePublicInputs {
    pub pubkey: U256<u32>,
    pub private_commitment: PoseidonHashOut,
    pub last_tx_hash: PoseidonHashOut,
    pub last_tx_insufficient_flags: InsufficientFlags,
    pub public_state: PublicState,
}

impl BalancePublicInputs {
    pub fn new(pubkey: U256<u32>) -> Self {
        let private_commitment = PrivateState::new().commitment();
        let last_tx_hash = PoseidonHashOut::default();
        let last_tx_insufficient_flags = InsufficientFlags::default();
        let public_state = PublicState::genesis();
        Self {
            pubkey,
            private_commitment,
            last_tx_hash,
            last_tx_insufficient_flags,
            public_state,
        }
    }

    pub fn to_u64_vec(&self) -> Vec<u64> {
        let vec = vec![
            self.pubkey.to_u64_vec(),
            self.private_commitment.to_u64_vec(),
            self.last_tx_hash.to_u64_vec(),
            self.last_tx_insufficient_flags.to_u64_vec(),
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
        let last_tx_insufficient_flags = InsufficientFlags::from_u64_vec(
            &input[U256_LEN + 2 * POSEIDON_HASH_OUT_LEN
                ..U256_LEN + 2 * POSEIDON_HASH_OUT_LEN + INSUFFICIENT_FLAGS_LEN],
        );
        let public_state = PublicState::from_u64_vec(
            &input[U256_LEN + 2 * POSEIDON_HASH_OUT_LEN + INSUFFICIENT_FLAGS_LEN..],
        );
        Self {
            pubkey,
            private_commitment,
            last_tx_hash,
            last_tx_insufficient_flags,
            public_state,
        }
    }

    pub fn from_pis<F: PrimeField64>(pis: &[F]) -> Self {
        Self::from_u64_vec(&pis[0..BALANCE_PUBLIC_INPUTS_LEN].to_u64_vec())
    }

    pub fn commitment(&self) -> PoseidonHashOut {
        PoseidonHashOut::hash_inputs_u64(&self.to_u64_vec())
    }
}

#[derive(Debug, Clone)]
pub struct BalancePublicInputsTarget {
    pub pubkey: U256<Target>,
    pub private_commitment: PoseidonHashOutTarget,
    pub last_tx_hash: PoseidonHashOutTarget,
    pub last_tx_insufficient_flags: InsufficientFlagsTarget,
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
            last_tx_insufficient_flags: InsufficientFlagsTarget::new(builder, is_checked),
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
        self.last_tx_insufficient_flags
            .connect(builder, other.last_tx_insufficient_flags);
        self.public_state.connect(builder, &other.public_state);
    }

    pub fn conditional_assert_eq<F: RichField + Extendable<D>, const D: usize>(
        &self,
        builder: &mut CircuitBuilder<F, D>,
        other: &Self,
        condition: BoolTarget,
    ) {
        self.pubkey
            .conditional_assert_eq(builder, other.pubkey, condition);
        self.private_commitment
            .conditional_assert_eq(builder, other.private_commitment, condition);
        self.last_tx_hash
            .conditional_assert_eq(builder, other.last_tx_hash, condition);
        self.last_tx_insufficient_flags.conditional_assert_eq(
            builder,
            other.last_tx_insufficient_flags,
            condition,
        );
        self.public_state
            .conditional_assert_eq(builder, &other.public_state, condition);
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
        self.last_tx_insufficient_flags
            .set_witness(witness, value.last_tx_insufficient_flags);
        self.public_state.set_witness(witness, &value.public_state);
    }

    pub fn to_vec(&self) -> Vec<Target> {
        let vec = vec![
            self.pubkey.to_vec(),
            self.private_commitment.to_vec(),
            self.last_tx_hash.to_vec(),
            self.last_tx_insufficient_flags.to_vec(),
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
        let last_tx_insufficient_flags = InsufficientFlagsTarget::from_limbs(
            &input[U256_LEN + 2 * POSEIDON_HASH_OUT_LEN
                ..U256_LEN + 2 * POSEIDON_HASH_OUT_LEN + INSUFFICIENT_FLAGS_LEN],
        );
        let public_state = PublicStateTarget::from_vec(
            &input[U256_LEN + 2 * POSEIDON_HASH_OUT_LEN + INSUFFICIENT_FLAGS_LEN..],
        );
        Self {
            pubkey,
            private_commitment,
            last_tx_hash,
            last_tx_insufficient_flags,
            public_state,
        }
    }

    pub fn from_pis(pis: &[Target]) -> Self {
        Self::from_vec(&pis[0..BALANCE_PUBLIC_INPUTS_LEN])
    }

    pub fn commitment<F: RichField + Extendable<D>, const D: usize>(
        &self,
        builder: &mut CircuitBuilder<F, D>,
    ) -> PoseidonHashOutTarget {
        PoseidonHashOutTarget::hash_inputs(builder, &self.to_vec())
    }
}
