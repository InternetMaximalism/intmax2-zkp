use plonky2::{
    field::{extension::Extendable, types::Field},
    hash::hash_types::RichField,
    iop::{
        target::{BoolTarget, Target},
        witness::WitnessWrite,
    },
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
        poseidon_hash_out::{PoseidonHashOut, PoseidonHashOutTarget},
    },
};

pub const TRANSFER_LEN: usize = GENERIC_ADDRESS_LEN + 1 + U256_LEN + SALT_LEN;

#[derive(Debug, Clone, Copy, Default)]
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
            recipient: GenericAddress::rand(rng),
            token_index: rng.gen(),
            amount: U256::rand_small(rng),
            salt: Salt::rand(rng),
        }
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
}

impl Leafable for Transfer {
    type HashOut = PoseidonHashOut;

    fn empty_leaf() -> Self {
        Self::default()
    }

    fn hash(&self) -> Self::HashOut {
        PoseidonHashOut::hash_inputs_u64(self.to_u64_vec().as_slice())
    }

    fn two_to_one(left: Self::HashOut, right: Self::HashOut) -> Self::HashOut {
        let inputs = left
            .to_u64_vec()
            .into_iter()
            .chain(right.to_u64_vec().into_iter())
            .collect::<Vec<_>>();
        PoseidonHashOut::hash_inputs_u64(inputs.as_slice())
    }
}

impl LeafableTarget for TransferTarget {
    type Leaf = Transfer;
    type HashOutTarget = PoseidonHashOutTarget;

    fn hash_out_target<F: RichField + Extendable<D>, const D: usize>(
        builder: &mut CircuitBuilder<F, D>,
    ) -> Self::HashOutTarget {
        PoseidonHashOutTarget::new(builder)
    }

    fn constant_hash_out_target<F: RichField + Extendable<D>, const D: usize>(
        builder: &mut CircuitBuilder<F, D>,
        value: PoseidonHashOut,
    ) -> Self::HashOutTarget {
        PoseidonHashOutTarget::constant(builder, value)
    }

    fn set_hash_out_target<W: WitnessWrite<F>, F: Field>(
        target: &Self::HashOutTarget,
        witness: &mut W,
        value: PoseidonHashOut,
    ) {
        target.set_witness(witness, value)
    }

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

    fn connect_hash<F: RichField + Extendable<D>, const D: usize>(
        builder: &mut CircuitBuilder<F, D>,
        x: &Self::HashOutTarget,
        y: &Self::HashOutTarget,
    ) {
        x.connect(builder, *y)
    }

    fn two_to_one<
        F: RichField + Extendable<D>,
        C: GenericConfig<D, F = F> + 'static,
        const D: usize,
    >(
        builder: &mut CircuitBuilder<F, D>,
        left: &Self::HashOutTarget,
        right: &Self::HashOutTarget,
    ) -> PoseidonHashOutTarget
    where
        <C as GenericConfig<D>>::Hasher: AlgebraicHasher<F>,
    {
        PoseidonHashOutTarget::two_to_one(builder, *left, *right)
    }

    fn two_to_one_swapped<
        F: RichField + Extendable<D>,
        C: GenericConfig<D, F = F> + 'static,
        const D: usize,
    >(
        builder: &mut CircuitBuilder<F, D>,
        left: &Self::HashOutTarget,
        right: &Self::HashOutTarget,
        swap: BoolTarget,
    ) -> Self::HashOutTarget
    where
        <C as GenericConfig<D>>::Hasher: AlgebraicHasher<F>,
    {
        PoseidonHashOutTarget::two_to_one_swapped(builder, *left, *right, swap)
    }
}
