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
use serde::{Deserialize, Serialize};

use crate::utils::{
    leafable::{Leafable, LeafableTarget},
    leafable_hasher::PoseidonLeafableHasher,
    poseidon_hash_out::{PoseidonHashOut, PoseidonHashOutTarget, POSEIDON_HASH_OUT_LEN},
};

pub const TX_LEN: usize = POSEIDON_HASH_OUT_LEN + 1;

/// A transaction, which contains multiple transfers of tokens.
#[derive(Clone, Default, Copy, Debug, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Tx {
    /// The root of the transfer tree
    pub transfer_tree_root: PoseidonHashOut,

    /// The nonce of the sender's accounts
    pub nonce: u32,
}

impl Tx {
    pub fn to_u64_vec(&self) -> Vec<u64> {
        let vec = self
            .transfer_tree_root
            .to_u64_vec()
            .into_iter()
            .chain(vec![self.nonce as u64])
            .collect::<Vec<_>>();
        assert_eq!(vec.len(), TX_LEN);
        vec
    }

    pub fn from_u64_slice(input: &[u64]) -> Result<Self, crate::common::error::CommonError> {
        if input.len() != TX_LEN {
            return Err(crate::common::error::CommonError::InvalidData(format!(
                "Invalid input length for Tx: expected {}, got {}",
                TX_LEN,
                input.len()
            )));
        }
        let transfer_tree_root = PoseidonHashOut::from_u64_slice(&input[0..4]).unwrap();
        let nonce = input[4] as u32;
        Ok(Self {
            transfer_tree_root,
            nonce,
        })
    }

    pub fn rand<R: Rng>(rng: &mut R) -> Self {
        Self {
            transfer_tree_root: PoseidonHashOut::rand(rng),
            nonce: rng.gen(),
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TxTarget {
    pub transfer_tree_root: PoseidonHashOutTarget,
    pub nonce: Target,
}

impl TxTarget {
    pub fn new<F: RichField + Extendable<D>, const D: usize>(
        builder: &mut CircuitBuilder<F, D>,
    ) -> Self {
        Self {
            transfer_tree_root: PoseidonHashOutTarget::new(builder),
            nonce: builder.add_virtual_target(),
        }
    }

    pub fn to_vec(&self) -> Vec<Target> {
        let vec = self
            .transfer_tree_root
            .to_vec()
            .into_iter()
            .chain([self.nonce].iter().copied())
            .collect::<Vec<_>>();
        assert_eq!(vec.len(), TX_LEN);
        vec
    }

    pub fn from_slice(input: &[Target]) -> Self {
        assert_eq!(input.len(), TX_LEN);
        let transfer_tree_root = PoseidonHashOutTarget::from_slice(&input[0..4]);
        let nonce = input[4];
        Self {
            transfer_tree_root,
            nonce,
        }
    }

    pub fn connect<F: RichField + Extendable<D>, const D: usize>(
        &self,
        builder: &mut CircuitBuilder<F, D>,
        other: &Self,
    ) {
        self.transfer_tree_root
            .connect(builder, other.transfer_tree_root);
        builder.connect(self.nonce, other.nonce);
    }

    pub fn constant<F: RichField + Extendable<D>, const D: usize>(
        builder: &mut CircuitBuilder<F, D>,
        value: Tx,
    ) -> Self {
        Self {
            transfer_tree_root: PoseidonHashOutTarget::constant(builder, value.transfer_tree_root),
            nonce: builder.constant(F::from_canonical_u32(value.nonce)),
        }
    }

    pub fn set_witness<W: WitnessWrite<F>, F: Field>(&self, witness: &mut W, value: Tx) {
        self.transfer_tree_root
            .set_witness(witness, value.transfer_tree_root);
        witness.set_target(self.nonce, F::from_canonical_u32(value.nonce));
    }
}

impl Leafable for Tx {
    type LeafableHasher = PoseidonLeafableHasher;

    fn empty_leaf() -> Self {
        Self::default()
    }

    fn hash(&self) -> PoseidonHashOut {
        PoseidonHashOut::hash_inputs_u64(&self.to_u64_vec())
    }
}

impl LeafableTarget for TxTarget {
    type Leaf = Tx;

    fn empty_leaf<F: RichField + Extendable<D>, const D: usize>(
        builder: &mut CircuitBuilder<F, D>,
    ) -> Self {
        TxTarget::constant(builder, Tx::empty_leaf())
    }

    fn hash<F: RichField + Extendable<D>, C: 'static + GenericConfig<D, F = F>, const D: usize>(
        &self,
        builder: &mut CircuitBuilder<F, D>,
    ) -> PoseidonHashOutTarget
    where
        <C as GenericConfig<D>>::Hasher: AlgebraicHasher<F>,
    {
        PoseidonHashOutTarget::hash_inputs(builder, &self.to_vec())
    }
}
