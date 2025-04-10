use ark_bn254::{Fq, Fr, G1Affine};
use ark_ec::AffineRepr as _;
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
    fields::{biguint::BigUintTarget, fq::FqTarget, recover::RecoverFromX},
};

use crate::{
    common::signature::flatten::FlatG1,
    ethereum_types::{
        u256::{U256Target, U256},
        u32limb_trait::{U32LimbTargetTrait, U32LimbTrait},
    },
};

use super::{
    flatten::FlatG1Target,
    block_sign_payload::{hash_to_weight, hash_to_weight_circuit},
    SignatureContent, SignatureContentTarget,
};
use plonky2_bn254::utils::g1_msm::g1_msm;

impl SignatureContent {
    /// Verify that the calculation of agg_pubkey matches.
    /// It is assumed that the format validation has already passed.
    pub fn verify_aggregation(&self, pubkeys: &[U256]) -> bool {
        let mut result = true;
        let weighted_pubkeys = pubkeys
            .iter()
            .zip(self.sender_flag.to_bits_be())
            .map(|(pubkey, b)| {
                let x: Fq = (*pubkey).into();
                let pubkey_g1: G1Affine = G1Affine::recover_from_x(x);
                let weight = hash_to_weight(*pubkey, self.pubkey_hash);
                if b {
                    (pubkey_g1 * Fr::from(BigUint::from(weight))).into()
                } else {
                    G1Affine::zero()
                }
            })
            .collect::<Vec<G1Affine>>();
        let agg_pubkey: FlatG1 = weighted_pubkeys
            .iter()
            .fold(G1Affine::zero(), |acc, x| (acc + x).into())
            .into();
        result &= agg_pubkey == self.agg_pubkey;
        result
    }
}

impl SignatureContentTarget {
    pub fn verify_aggregation<
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
        let mut result = builder._true();

        let sender_flag_bits = self.sender_flag.to_bits_be(builder);
        let weights = pubkeys
            .iter()
            .zip(sender_flag_bits.iter())
            .map(|(pubkey, b)| {
                let weight = hash_to_weight_circuit(builder, *pubkey, self.pubkey_hash);
                weight.mul_bool(builder, *b)
            })
            .collect::<Vec<_>>();
        let pubkeys = pubkeys
            .iter()
            .map(|x| {
                let x_fq: FqTarget<F, D> = (*x).into();
                G1Target::recover_from_x(builder, &x_fq) // safely recoverable since the format is
                                                         // already validated
            })
            .collect::<Vec<_>>();
        let zipped: Vec<(BigUintTarget, G1Target<F, D>)> = weights
            .iter()
            .zip(pubkeys.iter())
            .map(|(weight, pubkey)| ((*weight).into(), pubkey.clone()))
            .collect::<Vec<_>>();
        let agg_pubkey: FlatG1Target = g1_msm::<F, C, D>(builder, &zipped).into();
        let is_agg_pubkey_eq = agg_pubkey.is_equal(builder, &self.agg_pubkey);
        result = builder.and(result, is_agg_pubkey_eq);
        result
    }
}

#[cfg(test)]
mod tests {
    use plonky2::{
        field::goldilocks_field::GoldilocksField,
        iop::witness::{PartialWitness, WitnessWrite as _},
        plonk::{
            circuit_builder::CircuitBuilder, circuit_data::CircuitConfig,
            config::PoseidonGoldilocksConfig,
        },
    };

    use crate::{
        common::signature::{SignatureContent, SignatureContentTarget},
        ethereum_types::{u256::U256Target, u32limb_trait::U32LimbTargetTrait as _},
    };

    type F = GoldilocksField;
    const D: usize = 2;
    type C = PoseidonGoldilocksConfig;

    #[test]
    fn verify_aggregation() {
        let rng = &mut rand::thread_rng();
        let (keyset, signature) = SignatureContent::rand(rng);
        let pubkeys = keyset
            .iter()
            .map(|keyset| keyset.pubkey)
            .collect::<Vec<_>>();
        assert!(signature.is_valid_format(&pubkeys));
        assert!(signature.verify_aggregation(&pubkeys));

        let mut builder = CircuitBuilder::<F, D>::new(CircuitConfig::default());
        let pubkeys_t = pubkeys
            .iter()
            .map(|x| U256Target::constant(&mut builder, *x))
            .collect::<Vec<_>>();
        let signature_t = SignatureContentTarget::constant(&mut builder, &signature);
        let result = signature_t.verify_aggregation::<F, C, D>(&mut builder, &pubkeys_t);

        let mut pw = PartialWitness::new();
        pw.set_bool_target(result, true);

        let circuit = builder.build::<C>();
        let proof = circuit.prove(pw).unwrap();
        assert!(circuit.verify(proof).is_ok());
    }
}
