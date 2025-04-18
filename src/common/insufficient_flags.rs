use crate::{
    constants::NUM_TRANSFERS_IN_TX,
    ethereum_types::{
        error::EthereumTypeError,
        u32limb_trait::{U32LimbTargetTrait, U32LimbTrait},
    },
};
use plonky2::{
    field::extension::Extendable,
    hash::hash_types::RichField,
    iop::target::{BoolTarget, Target},
    plonk::circuit_builder::CircuitBuilder,
};
use serde::{Deserialize, Serialize};

pub const INSUFFICIENT_FLAGS_LEN: usize = NUM_TRANSFERS_IN_TX / 32;

/// The insufficient flags which are used to determine if a tx is invalid or not
#[derive(Clone, Copy, Debug, PartialEq, Default, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct InsufficientFlags {
    limbs: [u32; INSUFFICIENT_FLAGS_LEN],
}

impl InsufficientFlags {
    pub fn random_access(&self, index: usize) -> bool {
        self.to_bits_be()[index]
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct InsufficientFlagsTarget {
    limbs: [Target; INSUFFICIENT_FLAGS_LEN],
}

impl InsufficientFlagsTarget {
    pub fn new<F: RichField + Extendable<D>, const D: usize>(
        builder: &mut CircuitBuilder<F, D>,
        range_check: bool,
    ) -> Self {
        U32LimbTargetTrait::<INSUFFICIENT_FLAGS_LEN>::new::<F, D>(builder, range_check)
    }

    pub fn random_access<F: RichField + Extendable<D>, const D: usize>(
        &self,
        builder: &mut CircuitBuilder<F, D>,
        index: Target,
    ) -> BoolTarget {
        let num_bits = NUM_TRANSFERS_IN_TX.trailing_zeros() as usize;
        let (bit_selector, limb_selector) = builder.split_low_high(index, 5, num_bits);
        let selected_limb = builder.random_access(limb_selector, self.to_vec());
        let limb_bits = builder
            .split_le(selected_limb, 32)
            .into_iter()
            .rev()
            .map(|b| b.target)
            .collect();
        let selected_bit = builder.random_access(bit_selector, limb_bits);
        BoolTarget::new_unsafe(selected_bit)
    }
}

impl U32LimbTrait<INSUFFICIENT_FLAGS_LEN> for InsufficientFlags {
    fn to_u32_vec(&self) -> Vec<u32> {
        self.limbs.to_vec()
    }

    fn from_u32_slice(limbs: &[u32]) -> crate::ethereum_types::u32limb_trait::Result<Self> {
        if limbs.len() != INSUFFICIENT_FLAGS_LEN {
            return Err(EthereumTypeError::InvalidLengthSimple(limbs.len()));
        }
        Ok(Self {
            limbs: limbs
                .try_into()
                .map_err(|_| EthereumTypeError::InvalidLengthSimple(limbs.len()))?,
        })
    }
}

impl U32LimbTargetTrait<INSUFFICIENT_FLAGS_LEN> for InsufficientFlagsTarget {
    fn to_vec(&self) -> Vec<Target> {
        self.limbs.to_vec()
    }

    fn from_slice(limbs: &[Target]) -> Self {
        assert_eq!(
            limbs.len(),
            INSUFFICIENT_FLAGS_LEN,
            "Invalid length for InsufficientFlagsTarget"
        );
        Self {
            limbs: limbs.try_into().unwrap(),
        }
    }
}

#[cfg(test)]
mod tests {
    use plonky2::{
        field::{goldilocks_field::GoldilocksField, types::Field as _},
        iop::witness::{PartialWitness, WitnessWrite as _},
        plonk::{
            circuit_builder::CircuitBuilder, circuit_data::CircuitConfig,
            config::PoseidonGoldilocksConfig,
        },
    };
    use rand::Rng as _;

    use crate::{
        constants::NUM_TRANSFERS_IN_TX,
        ethereum_types::u32limb_trait::{U32LimbTargetTrait, U32LimbTrait as _},
    };

    use super::{InsufficientFlags, InsufficientFlagsTarget};

    type F = GoldilocksField;
    type C = PoseidonGoldilocksConfig;
    const D: usize = 2;

    #[test]
    fn test_random_access() {
        let mut rng = rand::thread_rng();
        let index = rng.gen_range(0..NUM_TRANSFERS_IN_TX);
        let mut flag_bits = vec![false; NUM_TRANSFERS_IN_TX];
        flag_bits[index] = true;

        let flag = InsufficientFlags::from_bits_be(&flag_bits)
            .expect("Creating from bits should never fail");

        let mut builder = CircuitBuilder::<F, D>::new(CircuitConfig::default());
        let flags_t = InsufficientFlagsTarget::new(&mut builder, true);
        let index_t = builder.add_virtual_target();
        let selected = flags_t.random_access(&mut builder, index_t);

        let mut pw = PartialWitness::<F>::new();
        flags_t.set_witness(&mut pw, flag);
        pw.set_target(index_t, F::from_canonical_usize(index));
        pw.set_bool_target(selected, true);
        let data = builder.build::<C>();
        let _ = data.prove(pw).unwrap();
    }
}
