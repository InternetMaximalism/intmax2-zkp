use anyhow::{ensure, Result};
use ark_bn254::{Fq, G1Affine, G2Affine};
use num::BigUint;
use plonky2::{
    field::{extension::Extendable, goldilocks_field::GoldilocksField, types::Field as _},
    hash::hash_types::RichField,
    iop::target::BoolTarget,
    plonk::{
        circuit_builder::CircuitBuilder,
        config::{AlgebraicHasher, GenericConfig},
    },
};
use plonky2_bn254::{
    curves::{g1::G1Target, g2::G2Target},
    fields::{fq::FqTarget, recover::RecoverFromX as _},
    utils::hash_to_g2::HashToG2 as _,
};

use crate::{
    common::signature::{flatten::FlatG2Target, pubkey_range_check},
    constants::NUM_SENDERS_IN_BLOCK,
    ethereum_types::{
        bytes16::Bytes16,
        u256::{U256Target, U256},
        u32limb_trait::{U32LimbTargetTrait as _, U32LimbTrait as _},
    },
};

use super::{SignatureContent, SignatureContentTarget};

impl SignatureContent {
    /// Check if the format is correct (if the modulo is correct, etc.) and
    /// ensure that the subsequent ZKP works without any problems
    /// correctness of pubkey hash and account id hash is not checked here
    /// pubkeys are given as witnesses
    /// - pubkeys are in the correct order, unused pubkeys are one
    pub fn is_valid_format(&self, pubkeys: &[U256]) -> Result<()> {
        assert_eq!(
            pubkeys.len(),
            NUM_SENDERS_IN_BLOCK,
            "pubkeys length is invalid"
        );

        // sender flag check
        ensure!(
            self.sender_flag != Bytes16::default(),
            "sender_flag is zero"
        );

        // pubkey order check
        let mut cur_pubkey = pubkeys[0];
        for pubkey in pubkeys.iter().skip(1) {
            ensure!(
                cur_pubkey > *pubkey || *pubkey == U256::one(),
                "pubkey order check failed"
            );
            cur_pubkey = *pubkey;
        }

        // pubkey range-check
        // it's enough to check only the first pubkey since the order is checked
        ensure!(pubkey_range_check(pubkeys[0]), "pubkey range check failed");

        // pubkey recovery check
        for pubkey in pubkeys.iter() {
            let pubkey_fq: Fq = BigUint::from(*pubkey).into();
            ensure!(
                G1Affine::is_recoverable_from_x(pubkey_fq),
                "pubkey is not recoverable"
            );
        }

        // message point check
        let tx_tree_root = self
            .tx_tree_root
            .limbs()
            .iter()
            .map(|x| GoldilocksField::from_canonical_u32(*x))
            .collect::<Vec<_>>();
        let message_point_expected = G2Target::<GoldilocksField, 2>::hash_to_g2(&tx_tree_root);
        let message_point: G2Affine = self.message_point.clone().into();
        ensure!(
            message_point_expected == message_point,
            "message_point is invalid"
        );
        Ok(())
    }
}

impl SignatureContentTarget {
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
        assert_eq!(
            pubkeys.len(),
            NUM_SENDERS_IN_BLOCK,
            "pubkeys length is invalid"
        );
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
            cur_pubkey = pubkey.clone();
        }

        // pubkey range-check
        // it's enough to check only the first pubkey since the order is checked
        let pubkey_fq = pubkeys
            .into_iter()
            .map(|pk| pk.clone().into())
            .collect::<Vec<FqTarget<F, D>>>();
        let is_pubkey0_valid = pubkey_fq[0].is_valid(builder);
        result = builder.and(result, is_pubkey0_valid);
        // pubkey recovery check
        for pubkey in pubkey_fq.iter() {
            let is_recoverable = G1Target::is_recoverable_from_x::<C>(builder, pubkey);
            result = builder.and(result, is_recoverable);
        }
        // message point check
        let message_point: FlatG2Target =
            G2Target::<F, D>::hash_to_g2_circuit::<C>(builder, &self.tx_tree_root.limbs()).into();
        let is_message_eq = message_point.is_equal(builder, &self.message_point);
        result = builder.and(result, is_message_eq);
        result
    }
}

#[cfg(test)]
mod tests {
    use ark_bn254::{Fq, G1Affine};
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
        common::signature::{SignatureContent, SignatureContentTarget},
        ethereum_types::{u256::U256Target, u32limb_trait::U32LimbTargetTrait as _},
    };

    type F = GoldilocksField;
    const D: usize = 2;
    type C = PoseidonGoldilocksConfig;

    #[test]
    fn assert_one_is_recoverable() {
        assert!(G1Affine::is_recoverable_from_x(Fq::from(1)));
    }

    #[test]
    fn is_valid_format() {
        let rng = &mut rand::thread_rng();
        let (keyset, signature) = SignatureContent::rand(rng);
        let pubkeys = keyset
            .iter()
            .map(|keyset| keyset.pubkey)
            .collect::<Vec<_>>();
        signature.is_valid_format(&pubkeys).unwrap();

        let mut builder = CircuitBuilder::<F, D>::new(CircuitConfig::default());
        let pubkeys_t = pubkeys
            .iter()
            .map(|x| U256Target::constant(&mut builder, *x))
            .collect::<Vec<_>>();
        let signature_t = SignatureContentTarget::constant(&mut builder, &signature);
        let result = signature_t.is_valid_format::<F, C, D>(&mut builder, &pubkeys_t);

        let mut pw = PartialWitness::new();
        pw.set_bool_target(result, true);

        let circuit = builder.build::<C>();
        let proof = circuit.prove(pw).unwrap();
        assert!(circuit.verify(proof).is_ok());
    }
}
