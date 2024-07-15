use plonky2::{
    field::{extension::Extendable, types::Field},
    hash::hash_types::RichField,
    iop::{target::Target, witness::WitnessWrite},
    plonk::{
        circuit_builder::CircuitBuilder,
        config::{AlgebraicHasher, GenericConfig},
    },
};
use rand::Rng;

use super::{
    generic_address::{GenericAddress, GenericAddressTarget, GENERIC_ADDRESS_LEN},
    salt::{Salt, SaltTarget, SALT_LEN},
};
use crate::{
    ethereum_types::{
        u256::{U256, U256_LEN},
        u32limb_trait::{U32LimbTargetTrait as _, U32LimbTrait as _},
    },
    utils::{
        leafable::{Leafable, LeafableTarget},
        leafable_hasher::PoseidonLeafableHasher,
        poseidon_hash_out::{PoseidonHashOut, PoseidonHashOutTarget},
    },
};

pub const TRANSFER_LEN: usize = GENERIC_ADDRESS_LEN + 1 + U256_LEN + SALT_LEN;

#[derive(Debug, Clone, Copy, Default, PartialEq)]
pub struct Transfer {
    pub recipient: GenericAddress,
    pub token_index: u32,
    pub amount: U256<u32>,
    pub salt: Salt,
}

#[derive(Debug, Clone)]
pub struct TransferTarget {
    pub recipient: GenericAddressTarget,
    pub token_index: Target,
    pub amount: U256<Target>,
    pub salt: SaltTarget,
}

impl Transfer {
    pub fn to_u64_vec(&self) -> Vec<u64> {
        let vec = self
            .recipient
            .to_u64_vec()
            .into_iter()
            .chain([self.token_index as u64].iter().copied())
            .chain(self.amount.to_u64_vec().into_iter())
            .chain(self.salt.to_u64_vec().into_iter())
            .collect::<Vec<_>>();
        assert_eq!(vec.len(), TRANSFER_LEN);
        vec
    }

    pub fn rand<R: Rng>(rng: &mut R) -> Self {
        Self {
            recipient: GenericAddress::rand_pubkey(rng),
            token_index: rng.gen(),
            amount: U256::rand_small(rng),
            salt: Salt::rand(rng),
        }
    }

    pub fn rand_to<R: Rng>(rng: &mut R, to: U256<u32>) -> Self {
        Self {
            recipient: GenericAddress::from_pubkey(to),
            token_index: rng.gen(),
            amount: U256::rand_small(rng),
            salt: Salt::rand(rng),
        }
    }

    pub fn rand_withdrawal<R: Rng>(rng: &mut R) -> Self {
        Self {
            recipient: GenericAddress::rand_address(rng),
            token_index: rng.gen(),
            amount: U256::rand_small(rng),
            salt: Salt::rand(rng),
        }
    }

    pub fn commitment(&self) -> PoseidonHashOut {
        PoseidonHashOut::hash_inputs_u64(&self.to_u64_vec())
    }
}

impl TransferTarget {
    pub fn to_vec(&self) -> Vec<Target> {
        let vec = self
            .recipient
            .to_vec()
            .into_iter()
            .chain([self.token_index].iter().copied())
            .chain(self.amount.to_vec().into_iter())
            .chain(self.salt.to_vec().into_iter())
            .collect::<Vec<_>>();
        assert_eq!(vec.len(), TRANSFER_LEN);
        vec
    }

    pub fn new<F: RichField + Extendable<D>, const D: usize>(
        builder: &mut CircuitBuilder<F, D>,
        is_checked: bool,
    ) -> Self {
        Self {
            recipient: GenericAddressTarget::new(builder, is_checked),
            token_index: builder.add_virtual_target(),
            amount: U256::<Target>::new(builder, is_checked),
            salt: SaltTarget::new(builder),
        }
    }

    pub fn connect<F: RichField + Extendable<D>, const D: usize>(
        &self,
        builder: &mut CircuitBuilder<F, D>,
        other: &Self,
    ) {
        self.recipient.connect(builder, other.recipient);
        builder.connect(self.token_index, other.token_index);
        self.amount.connect(builder, other.amount);
        self.salt.connect(builder, other.salt);
    }

    pub fn constant<F: RichField + Extendable<D>, const D: usize>(
        builder: &mut CircuitBuilder<F, D>,
        value: Transfer,
    ) -> Self {
        Self {
            recipient: GenericAddressTarget::constant(builder, value.recipient),
            token_index: builder.add_virtual_target(),
            amount: U256::<Target>::constant(builder, value.amount),
            salt: SaltTarget::constant(builder, value.salt),
        }
    }

    pub fn set_witness<F: Field, W: WitnessWrite<F>>(&self, witness: &mut W, value: Transfer) {
        self.recipient.set_witness(witness, value.recipient);
        witness.set_target(self.token_index, F::from_canonical_u32(value.token_index));
        self.amount.set_witness(witness, value.amount);
        self.salt.set_witness(witness, value.salt);
    }

    pub fn commitment<F: RichField + Extendable<D>, const D: usize>(
        &self,
        builder: &mut CircuitBuilder<F, D>,
    ) -> PoseidonHashOutTarget {
        PoseidonHashOutTarget::hash_inputs(builder, &self.to_vec())
    }
}

impl Leafable for Transfer {
    type LeafableHasher = PoseidonLeafableHasher;

    fn empty_leaf() -> Self {
        Self::default()
    }

    fn hash(&self) -> PoseidonHashOut {
        PoseidonHashOut::hash_inputs_u64(self.to_u64_vec().as_slice())
    }
}

impl LeafableTarget for TransferTarget {
    type Leaf = Transfer;

    fn empty_leaf<F: RichField + Extendable<D>, const D: usize>(
        builder: &mut CircuitBuilder<F, D>,
    ) -> Self {
        let empty_leaf = <Transfer as Leafable>::empty_leaf();
        TransferTarget::constant(builder, empty_leaf)
    }

    fn hash<F: RichField + Extendable<D>, C: GenericConfig<D, F = F> + 'static, const D: usize>(
        &self,
        builder: &mut CircuitBuilder<F, D>,
    ) -> PoseidonHashOutTarget
    where
        <C as GenericConfig<D>>::Hasher: AlgebraicHasher<F>,
    {
        PoseidonHashOutTarget::hash_inputs(builder, &self.to_vec())
    }
}
