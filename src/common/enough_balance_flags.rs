use plonky2::{
    field::{extension::Extendable, types::Field},
    hash::hash_types::RichField,
    iop::{
        target::{BoolTarget, Target},
        witness::WitnessWrite,
    },
    plonk::circuit_builder::CircuitBuilder,
};

const MAX_RANDOM_ACCESS_LEN: usize = 64;

#[derive(Clone, Debug, PartialEq, Default)]
pub struct EnoughBalanceFlags {
    flags: Vec<bool>,
}

impl EnoughBalanceFlags {
    pub fn new(len_bits: usize) -> Self {
        assert!(
            len_bits <= 11,
            "len_bits should be less than or equal to 11"
        );
        let flags = (0..1 << len_bits).map(|_| false).collect();
        Self { flags }
    }

    pub fn get(&self, index: usize) -> bool {
        self.flags[index]
    }
}

#[derive(Clone, Debug)]
pub struct EnoughBalanceFlagsTarget {
    flags: Vec<BoolTarget>,
}

impl EnoughBalanceFlagsTarget {
    fn flags_target(&self) -> Vec<Target> {
        self.flags.iter().map(|f| f.target).collect()
    }

    fn len_bits(&self) -> usize {
        assert!(self.flags.len().is_power_of_two());
        let len_bits = self.flags.len().trailing_zeros() as usize;
        len_bits
    }

    fn chunk_size(&self) -> usize {
        if self.flags.len() <= MAX_RANDOM_ACCESS_LEN {
            return 1;
        } else {
            return self.flags.len() / MAX_RANDOM_ACCESS_LEN;
        }
    }

    pub fn new<F: RichField + Extendable<D>, const D: usize>(
        builder: &mut CircuitBuilder<F, D>,
        len_bits: usize,
        is_checked: bool,
    ) -> Self {
        assert!(
            len_bits <= 11,
            "len_bits should be less than or equal to 11"
        );
        let flags = (0..1 << len_bits)
            .map(|_| builder.add_virtual_bool_target_unsafe())
            .collect::<Vec<_>>();
        if is_checked {
            flags.iter().for_each(|b| builder.assert_bool(*b));
        }
        Self { flags }
    }

    pub fn set_witness<W: WitnessWrite<F>, F: Field>(
        &self,
        witness: &mut W,
        value: &EnoughBalanceFlags,
    ) {
        assert_eq!(self.flags.len(), value.flags.len());
        for (flag, value) in self.flags.iter().zip(value.flags.iter()) {
            witness.set_bool_target(*flag, *value);
        }
    }

    pub fn random_access<F: RichField + Extendable<D>, const D: usize>(
        &self,
        builder: &mut CircuitBuilder<F, D>,
        index: Target,
    ) -> BoolTarget {
        let chunk_size = self.chunk_size();
        if chunk_size == 1 {
            return BoolTarget::new_unsafe(builder.random_access(index, self.flags_target()));
        }
        let chunk_size_bits = chunk_size.trailing_zeros() as usize;
        let (bit_selector, chunk_selector) =
            builder.split_low_high(index, chunk_size_bits, self.len_bits());
        let chunks = self
            .flags
            .chunks(chunk_size)
            .map(|chunk| builder.le_sum(chunk.into_iter()))
            .collect::<Vec<_>>();
        assert_eq!(chunks.len(), MAX_RANDOM_ACCESS_LEN);
        let selected_chunk = builder.random_access(chunk_selector, chunks);
        let chunk_bits = builder
            .split_le(selected_chunk, chunk_size)
            .into_iter()
            .map(|b| b.target)
            .collect();
        let selected_bit = builder.random_access(bit_selector, chunk_bits);
        BoolTarget::new_unsafe(selected_bit)
    }
}

#[cfg(test)]
mod tests {
    use plonky2::{
        field::{goldilocks_field::GoldilocksField, types::Field},
        iop::witness::{PartialWitness, WitnessWrite},
        plonk::{
            circuit_builder::CircuitBuilder, circuit_data::CircuitConfig,
            config::PoseidonGoldilocksConfig,
        },
    };
    use rand::Rng;

    use super::{EnoughBalanceFlags, EnoughBalanceFlagsTarget};

    type F = GoldilocksField;
    type C = PoseidonGoldilocksConfig;
    const D: usize = 2;

    #[test]
    fn enough_balance_flags() {
        let mut rng = rand::thread_rng();
        let len_bits = 9;
        let mut flag = EnoughBalanceFlags::new(len_bits);
        let index = rng.gen_range(0..1 << len_bits);
        flag.flags[index] = true;

        let mut builder = CircuitBuilder::<F, D>::new(CircuitConfig::default());
        let flags_t = EnoughBalanceFlagsTarget::new(&mut builder, len_bits, true);
        let index_t = builder.add_virtual_target();
        let selected = flags_t.random_access(&mut builder, index_t);

        let mut pw = PartialWitness::<F>::new();
        flags_t.set_witness(&mut pw, &flag);
        pw.set_target(index_t, F::from_canonical_usize(index));
        pw.set_bool_target(selected, true);
        let data = builder.build::<C>();
        let _ = data.prove(pw).unwrap();
    }
}
