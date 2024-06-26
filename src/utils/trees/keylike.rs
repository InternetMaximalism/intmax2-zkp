use crate::ethereum_types::{
    u256::U256,
    u32limb_trait::{U32LimbTargetTrait, U32LimbTrait},
};
use plonky2::{
    field::extension::Extendable,
    hash::hash_types::{HashOutTarget, RichField},
    iop::target::{BoolTarget, Target},
    plonk::circuit_builder::CircuitBuilder,
};
use plonky2_u32::gadgets::arithmetic_u32::U32Target;

pub trait KeyLike: Copy + Eq + Default + std::hash::Hash {
    // little endian
    fn to_bits(&self) -> Vec<bool>;

    fn to_bits_trimed(&self, length: usize) -> Vec<bool> {
        let bits = self.to_bits();
        assert!(bits.len() >= length);
        bits[..length].to_vec()
    }
}

impl KeyLike for u32 {
    fn to_bits(&self) -> Vec<bool> {
        self.to_le_bytes()
            .iter()
            .flat_map(|v| u8_to_le_bits(*v))
            .collect()
    }
}

impl KeyLike for U256<u32> {
    fn to_bits(&self) -> Vec<bool> {
        self.to_bits_le()
    }
}

pub trait KeyLikeTarget {
    fn to_bits<F: RichField + Extendable<D>, const D: usize>(
        &self,
        builder: &mut CircuitBuilder<F, D>,
    ) -> Vec<BoolTarget>;

    fn to_bits_trimed<F: RichField + Extendable<D>, const D: usize>(
        &self,
        builder: &mut CircuitBuilder<F, D>,
        length: usize,
    ) -> Vec<BoolTarget> {
        let bits = self.to_bits(builder);
        assert!(bits.len() >= length);
        bits[..length].to_vec()
    }
}

impl KeyLikeTarget for U32Target {
    fn to_bits<F: RichField + Extendable<D>, const D: usize>(
        &self,
        builder: &mut CircuitBuilder<F, D>,
    ) -> Vec<BoolTarget> {
        builder.split_le(self.0, 32)
    }
}

impl KeyLikeTarget for U256<Target> {
    fn to_bits<F: RichField + Extendable<D>, const D: usize>(
        &self,
        builder: &mut CircuitBuilder<F, D>,
    ) -> Vec<BoolTarget> {
        self.to_bits_le(builder)
    }
}

impl KeyLikeTarget for HashOutTarget {
    fn to_bits<F: RichField + Extendable<D>, const D: usize>(
        &self,
        builder: &mut CircuitBuilder<F, D>,
    ) -> Vec<BoolTarget> {
        self.elements
            .iter()
            .flat_map(|e| builder.split_le(*e, 64))
            .collect::<Vec<_>>()
    }
}

fn u8_to_le_bits(num: u8) -> Vec<bool> {
    let mut result = Vec::with_capacity(8);
    let mut n = num;
    for _ in 0..8 {
        result.push(n & 1 == 1);
        n >>= 1;
    }
    result
}

#[cfg(test)]
mod tests {
    use crate::ethereum_types::{u256::U256, u32limb_trait::U32LimbTargetTrait};
    use plonky2::{
        iop::{
            target::Target,
            witness::{PartialWitness, WitnessWrite},
        },
        plonk::{
            circuit_builder::CircuitBuilder,
            circuit_data::CircuitConfig,
            config::{GenericConfig, PoseidonGoldilocksConfig},
        },
    };
    use plonky2_u32::{gadgets::arithmetic_u32::U32Target, witness::WitnessU32};

    use super::{KeyLike, KeyLikeTarget};

    const D: usize = 2;
    type C = PoseidonGoldilocksConfig;
    type F = <C as GenericConfig<D>>::F;

    #[test]
    fn keylike_u32() {
        let index = 0x12345678u32;
        let length = 10;
        let bits = index.to_bits_trimed(length);

        let mut builder = CircuitBuilder::<F, D>::new(CircuitConfig::default());
        let index_t = U32Target(builder.add_virtual_target());
        let bits_t = index_t.to_bits_trimed(&mut builder, length);

        let data = builder.build::<C>();
        let mut pw = PartialWitness::<F>::new();

        pw.set_u32_target(index_t, index);
        for (&bit_t, &bit) in bits_t.iter().zip(bits.iter()) {
            pw.set_bool_target(bit_t, bit);
        }
        data.prove(pw).unwrap();
    }

    #[test]
    fn keylike_u256() {
        let rng = &mut rand::thread_rng();
        let index = U256::rand(rng);
        let length = 10;
        let bits = index.to_bits_trimed(length);

        let mut builder = CircuitBuilder::<F, D>::new(CircuitConfig::default());
        let index_t = U256::<Target>::new(&mut builder, false);
        let bits_t = index_t.to_bits_trimed(&mut builder, length);

        let data = builder.build::<C>();
        let mut pw = PartialWitness::<F>::new();

        index_t.set_witness(&mut pw, index);
        for (&bit_t, &bit) in bits_t.iter().zip(bits.iter()) {
            pw.set_bool_target(bit_t, bit);
        }
        data.prove(pw).unwrap();
    }
}
