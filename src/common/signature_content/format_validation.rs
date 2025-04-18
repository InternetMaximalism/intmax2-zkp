//! Format validation checks:
//! 1. pubkeys are strictly in descending order, except for dummy keys (value 1) e.g., [50, 43, 1,
//!    1, 1, ...] is valid
//! 2. all pubkeys are within the Fq range (valid field elements)
//! 3. pubkeys can be used as x-coordinates of G1 points (x^3 + 3 is a perfect square)
//! 4. the message_point in signature content is correctly calculated from the block sign payload
use ark_bn254::{Fq, G1Affine};
use num::BigUint;
use plonky2::{
    field::extension::Extendable,
    hash::hash_types::RichField,
    iop::target::BoolTarget,
    plonk::{
        circuit_builder::CircuitBuilder,
        config::{AlgebraicHasher, GenericConfig},
    },
};
use plonky2_bn254::{
    curves::g1::G1Target,
    fields::{fq::FqTarget, recover::RecoverFromX as _},
};

use crate::{
    common::signature_content::SignatureContentError,
    constants::NUM_SENDERS_IN_BLOCK,
    ethereum_types::{
        bytes16::Bytes16,
        u256::{U256Target, U256},
        u32limb_trait::{U32LimbTargetTrait as _, U32LimbTrait as _},
    },
};

use super::{SignatureContent, SignatureContentTarget};

impl SignatureContent {
    /// Validates the format of the signature content with pubkeys
    /// Returns a Result with a boolean indicating if the format is valid,
    /// or an error if the pubkeys length is invalid
    pub fn is_valid_format(&self, pubkeys: &[U256]) -> Result<bool, SignatureContentError> {
        if pubkeys.len() != NUM_SENDERS_IN_BLOCK {
            return Err(SignatureContentError::InvalidPubkeysLength {
                expected: NUM_SENDERS_IN_BLOCK,
                actual: pubkeys.len(),
            });
        }

        let mut result = true;

        // sender flag check
        result &= self.sender_flag != Bytes16::zero();

        // pubkey order check
        let mut cur_pubkey = pubkeys[0];
        for pubkey in pubkeys.iter().skip(1) {
            result &= cur_pubkey > *pubkey || *pubkey == U256::one(); // use one for dummy pubkeys
            cur_pubkey = *pubkey;
        }

        // pubkey range-check
        // it's enough to check only the first pubkey since the order is checked
        result &= pubkey_range_check(pubkeys[0]);

        // pubkey recovery check
        for pubkey in pubkeys.iter() {
            let pubkey_fq: Fq = BigUint::from(*pubkey).into();
            result &= G1Affine::is_recoverable_from_x(pubkey_fq);
        }

        // message point check
        let message_point_expected = self.block_sign_payload.message_point();
        result &= message_point_expected == self.message_point;

        Ok(result)
    }
}

impl SignatureContentTarget {
    /// Validates the format of the signature content with pubkeys
    /// Returns a BoolTarget indicating if the format is valid
    /// Panics if the pubkeys length is invalid
    pub fn is_valid_format<
        F: RichField + Extendable<D>,
        C: GenericConfig<D, F = F> + 'static,
        const D: usize,
    >(
        &self,
        builder: &mut CircuitBuilder<F, D>,
        pubkeys: &[U256Target],
    ) -> BoolTarget
    where
        <C as GenericConfig<D>>::Hasher: AlgebraicHasher<F>,
    {
        assert_eq!(pubkeys.len(), NUM_SENDERS_IN_BLOCK);
        let mut result = builder.constant_bool(true);

        // sender flag check
        let is_sender_flag_zero = self.sender_flag.is_zero::<F, D, Bytes16>(builder);
        let is_not_sender_flag_zero = builder.not(is_sender_flag_zero);
        result = builder.and(result, is_not_sender_flag_zero);

        // pubkey order check
        let mut cur_pubkey = pubkeys[0];
        for pubkey in pubkeys.iter().skip(1) {
            let is_pubkey_lt = pubkey.is_lt(builder, &cur_pubkey);
            let is_pubkey_one = pubkey.is_one::<F, D, U256>(builder);
            let is_pubkey_order_valid = builder.or(is_pubkey_lt, is_pubkey_one);
            result = builder.and(result, is_pubkey_order_valid);
            cur_pubkey = *pubkey;
        }

        // pubkey range-check
        // it's enough to check only the first pubkey since the order is checked
        let pubkey_fq = pubkeys
            .iter()
            .map(|pk| (*pk).into())
            .collect::<Vec<FqTarget<F, D>>>();
        let is_pubkey0_valid = pubkey_fq[0].is_valid(builder);
        result = builder.and(result, is_pubkey0_valid);
        // pubkey recovery check
        for pubkey in pubkey_fq.iter() {
            let is_recoverable = G1Target::is_recoverable_from_x::<C>(builder, pubkey);
            result = builder.and(result, is_recoverable);
        }
        // message point check
        let message_point_expected = self.block_sign_payload.message_point::<F, C, D>(builder);
        let is_message_eq = message_point_expected.is_equal(builder, &self.message_point);
        result = builder.and(result, is_message_eq);
        result
    }
}

fn pubkey_range_check(pubkey: U256) -> bool {
    let pubkey_bg: BigUint = pubkey.into();
    let modulus = BigUint::from(Fq::from(-1)) + 1u32;
    pubkey_bg < modulus
}

#[cfg(test)]
mod tests {
    use ark_bn254::{Fq, G1Affine, G2Affine};
    use ark_ff::UniformRand;
    use plonky2::{
        field::goldilocks_field::GoldilocksField,
        iop::witness::{PartialWitness, WitnessWrite},
        plonk::{
            circuit_builder::CircuitBuilder, circuit_data::CircuitConfig,
            config::PoseidonGoldilocksConfig,
        },
    };
    use plonky2_bn254::fields::recover::RecoverFromX;

    use crate::{
        common::signature_content::{key_set::KeySet, SignatureContent, SignatureContentTarget},
        constants::NUM_SENDERS_IN_BLOCK,
        ethereum_types::{
            u256::{U256Target, U256},
            u32limb_trait::{U32LimbTargetTrait as _, U32LimbTrait},
        },
    };

    type F = GoldilocksField;
    const D: usize = 2;
    type C = PoseidonGoldilocksConfig;

    #[test]
    fn assert_one_is_recoverable() {
        assert!(G1Affine::is_recoverable_from_x(Fq::from(1)));
    }

    #[test]
    fn test_format_validation_valid() {
        let rng = &mut rand::thread_rng();
        let (keyset, signature) = SignatureContent::rand(rng);
        let pubkeys = keyset
            .iter()
            .map(|keyset| keyset.pubkey)
            .collect::<Vec<_>>();

        // Test the format validation
        let result = signature
            .is_valid_format(&pubkeys)
            .expect("Format validation failed");
        assert!(result);

        let mut builder = CircuitBuilder::<F, D>::new(CircuitConfig::default());
        let pubkeys_t = pubkeys
            .iter()
            .map(|x| U256Target::constant(&mut builder, *x))
            .collect::<Vec<_>>();
        let signature_t = SignatureContentTarget::constant(&mut builder, &signature);
        let result_t = signature_t.is_valid_format::<F, C, D>(&mut builder, &pubkeys_t);

        let mut pw = PartialWitness::new();
        pw.set_bool_target(result_t, result);

        let circuit = builder.build::<C>();
        let proof = circuit.prove(pw).unwrap();
        assert!(circuit.verify(proof).is_ok());
    }

    #[test]
    fn test_format_validation_invalid_pubkey_order() {
        let rng = &mut rand::thread_rng();
        let (keyset, signature) = SignatureContent::rand(rng);
        let mut pubkeys = keyset
            .iter()
            .map(|keyset| keyset.pubkey)
            .collect::<Vec<_>>();
        // Reverse the order of pubkeys to make it invalid
        pubkeys.reverse();

        // Test the format validation
        let result = signature
            .is_valid_format(&pubkeys)
            .expect("Format validation failed");
        assert!(!result);

        let mut builder = CircuitBuilder::<F, D>::new(CircuitConfig::default());
        let pubkeys_t = pubkeys
            .iter()
            .map(|x| U256Target::constant(&mut builder, *x))
            .collect::<Vec<_>>();
        let signature_t = SignatureContentTarget::constant(&mut builder, &signature);
        let result_t = signature_t.is_valid_format::<F, C, D>(&mut builder, &pubkeys_t);

        let mut pw = PartialWitness::new();
        pw.set_bool_target(result_t, result);

        let circuit = builder.build::<C>();
        let proof = circuit.prove(pw).unwrap();
        assert!(circuit.verify(proof).is_ok());
    }

    #[test]
    fn test_format_validation_out_of_range() {
        let rng = &mut rand::thread_rng();
        let (keyset, signature) = SignatureContent::rand(rng);
        let mut pubkeys = keyset
            .iter()
            .map(|keyset| keyset.pubkey)
            .collect::<Vec<_>>();

        pubkeys[0] = U256::from(Fq::from(-1)) + U256::one(); // Set the first pubkey to an out-of-range value

        // Test the format validation
        let result = signature
            .is_valid_format(&pubkeys)
            .expect("Format validation failed");
        assert!(!result);

        let mut builder = CircuitBuilder::<F, D>::new(CircuitConfig::default());
        let pubkeys_t = pubkeys
            .iter()
            .map(|x| U256Target::constant(&mut builder, *x))
            .collect::<Vec<_>>();
        let signature_t = SignatureContentTarget::constant(&mut builder, &signature);
        let result_t = signature_t.is_valid_format::<F, C, D>(&mut builder, &pubkeys_t);

        let mut pw = PartialWitness::new();
        pw.set_bool_target(result_t, result);

        let circuit = builder.build::<C>();
        let proof = circuit.prove(pw).unwrap();
        assert!(circuit.verify(proof).is_ok());
    }

    #[test]
    fn test_format_validation_not_recoverable() {
        let rng = &mut rand::thread_rng();
        let (_keyset, signature) = SignatureContent::rand(rng);

        // random pubkeys that are not recoverable
        let mut pubkeys = (0..NUM_SENDERS_IN_BLOCK)
            .map(|_| KeySet::rand(rng).pubkey)
            .collect::<Vec<_>>();
        pubkeys.sort();

        // Test the format validation
        let result = signature
            .is_valid_format(&pubkeys)
            .expect("Format validation failed");
        assert!(!result);

        let mut builder = CircuitBuilder::<F, D>::new(CircuitConfig::default());
        let pubkeys_t = pubkeys
            .iter()
            .map(|x| U256Target::constant(&mut builder, *x))
            .collect::<Vec<_>>();
        let signature_t = SignatureContentTarget::constant(&mut builder, &signature);
        let result_t = signature_t.is_valid_format::<F, C, D>(&mut builder, &pubkeys_t);

        let mut pw = PartialWitness::new();
        pw.set_bool_target(result_t, result);

        let circuit = builder.build::<C>();
        let proof = circuit.prove(pw).unwrap();
        assert!(circuit.verify(proof).is_ok());
    }

    #[test]
    fn test_format_validation_invalid_message_point() {
        let rng = &mut rand::thread_rng();
        let (keyset, mut signature) = SignatureContent::rand(rng);
        let pubkeys = keyset
            .iter()
            .map(|keyset| keyset.pubkey)
            .collect::<Vec<_>>();

        // set the message point to an invalid value
        signature.message_point = G2Affine::rand(rng).into();

        // Test the format validation
        let result = signature
            .is_valid_format(&pubkeys)
            .expect("Format validation failed");
        assert!(!result);

        let mut builder = CircuitBuilder::<F, D>::new(CircuitConfig::default());
        let pubkeys_t = pubkeys
            .iter()
            .map(|x| U256Target::constant(&mut builder, *x))
            .collect::<Vec<_>>();
        let signature_t = SignatureContentTarget::constant(&mut builder, &signature);
        let result_t = signature_t.is_valid_format::<F, C, D>(&mut builder, &pubkeys_t);

        let mut pw = PartialWitness::new();
        pw.set_bool_target(result_t, result);

        let circuit = builder.build::<C>();
        let proof = circuit.prove(pw).unwrap();
        assert!(circuit.verify(proof).is_ok());
    }
}
