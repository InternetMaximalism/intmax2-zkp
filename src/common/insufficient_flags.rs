use crate::{
    constants::NUM_TRANSFERS_IN_TX,
    ethereum_types::u32limb_trait::{U32LimbTargetTrait, U32LimbTrait},
};
use plonky2::{
    field::extension::Extendable,
    hash::hash_types::RichField,
    iop::target::{BoolTarget, Target},
    plonk::circuit_builder::CircuitBuilder,
};

pub const INSUFFICIENT_FLAGS_LEN: usize = NUM_TRANSFERS_IN_TX / 32;

#[derive(Clone, Copy, Debug, PartialEq, Default)]
pub struct InsufficientFlags {
    limbs: [u32; INSUFFICIENT_FLAGS_LEN],
}

impl InsufficientFlags {
    pub fn random_access(&self, index: usize) -> bool {
        self.to_bits_le()[index]
    }
}

#[derive(Clone, Copy, Debug)]
pub struct InsufficientFlagsTarget {
    limbs: [Target; INSUFFICIENT_FLAGS_LEN],
}

impl InsufficientFlagsTarget {
    pub fn random_access<F: RichField + Extendable<D>, const D: usize>(
        &self,
        builder: &mut CircuitBuilder<F, D>,
        index: Target,
    ) -> BoolTarget {
        let num_bits = NUM_TRANSFERS_IN_TX.trailing_zeros() as usize;
        let (bit_selector, limb_selector) = builder.split_low_high(index, 5, num_bits);
        let limbs = self.limbs().into_iter().rev().collect();
        let selected_limb = builder.random_access(limb_selector, limbs);
        let limb_bits = builder
            .split_le(selected_limb, 32)
            .into_iter()
            .map(|b| b.target)
            .collect();
        let selected_bit = builder.random_access(bit_selector, limb_bits);
        BoolTarget::new_unsafe(selected_bit)
    }
}

/* u32 limb trait */
impl U32LimbTrait<INSUFFICIENT_FLAGS_LEN> for InsufficientFlags {
    fn limbs(&self) -> Vec<u32> {
        self.limbs.to_vec()
    }

    fn from_limbs(limbs: &[u32]) -> Self {
        assert_eq!(limbs.len(), INSUFFICIENT_FLAGS_LEN);
        Self {
            limbs: limbs.try_into().unwrap(),
        }
    }
}

impl U32LimbTargetTrait<INSUFFICIENT_FLAGS_LEN> for InsufficientFlagsTarget {
    fn limbs(&self) -> Vec<Target> {
        self.limbs.to_vec()
    }

    fn from_limbs(limbs: &[Target]) -> Self {
        assert_eq!(limbs.len(), INSUFFICIENT_FLAGS_LEN);
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

        let flag = InsufficientFlags::from_bits_le(&flag_bits);

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
