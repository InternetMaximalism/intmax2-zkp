use crate::ethereum_types::{
    u256::{U256Target, U256},
    u32limb_trait::{U32LimbTargetTrait, U32LimbTrait as _},
};
use ark_bn254::{Fr, G1Affine};
use ark_ec::AffineRepr;
use num::BigUint;
use plonky2::{
    field::extension::Extendable, hash::hash_types::RichField, iop::target::BoolTarget,
    plonk::circuit_builder::CircuitBuilder,
};
use plonky2_bn254::fields::{recover::RecoverFromX as _, sgn::Sgn as _};
use rand::Rng;
use serde::{Deserialize, Serialize};

#[derive(Copy, Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct KeySet {
    pub privkey: U256,
    pub pubkey: U256,
}

impl KeySet {
    pub fn new(privkey: U256) -> Self {
        let mut privkey_fr: Fr = BigUint::from(privkey).into();
        let mut pubkey_g1: G1Affine = (G1Affine::generator() * privkey_fr).into();
        if pubkey_g1.y.sgn() {
            privkey_fr = -privkey_fr;
            pubkey_g1 = -pubkey_g1;
        }

        let privkey: U256 = BigUint::from(privkey_fr).try_into().unwrap(); // unwrap is safe
        let pubkey: U256 = pubkey_g1.x.into();

        // assertion
        assert!(!pubkey.is_dummy_pubkey());
        let recovered_pubkey = G1Affine::recover_from_x(pubkey.into());
        assert_eq!(
            recovered_pubkey, pubkey_g1,
            "recovered_pubkey should be equal to pubkey"
        );

        Self { privkey, pubkey }
    }

    pub fn rand<R: Rng>(rng: &mut R) -> Self {
        Self::new(U256::rand(rng))
    }

    pub fn privkey_fr(&self) -> Fr {
        let privkey: Fr = BigUint::from(self.privkey).into();
        privkey
    }

    pub fn pubkey_g1(&self) -> G1Affine {
        let privkey_fr: Fr = BigUint::from(self.privkey).into();
        let pubkey_g1: G1Affine = (G1Affine::generator() * privkey_fr).into();
        pubkey_g1
    }

    /// Create a dummy keyset for padding purposes
    pub fn dummy() -> Self {
        Self {
            privkey: U256::zero(),
            pubkey: U256::dummy_pubkey(),
        }
    }

    pub fn is_dummy(&self) -> bool {
        self.pubkey.is_dummy_pubkey()
    }
}

impl U256 {
    // this is the smallest possible pubkey_x, which is recoverable from x
    pub fn dummy_pubkey() -> Self {
        U256::one()
    }

    pub fn is_dummy_pubkey(&self) -> bool {
        *self == Self::dummy_pubkey()
    }
}

impl U256Target {
    pub fn dummy_pubkey<F: RichField + Extendable<D>, const D: usize>(
        builder: &mut CircuitBuilder<F, D>,
    ) -> Self {
        Self::constant(builder, U256::dummy_pubkey())
    }

    pub fn is_dummy_pubkey<F: RichField + Extendable<D>, const D: usize>(
        &self,
        builder: &mut CircuitBuilder<F, D>,
    ) -> BoolTarget {
        let dummy_pubkey = Self::dummy_pubkey(builder);
        self.is_equal(builder, &dummy_pubkey)
    }
}

#[cfg(test)]
mod tests {
    use num::BigUint;
    use plonky2_bn254::fields::sgn::Sgn as _;

    use crate::{
        common::{signature_content::key_set::KeySet, trees::account_tree::AccountTree},
        ethereum_types::{u256::U256, u32limb_trait::U32LimbTrait},
    };

    #[test]
    fn test_key_set_random() {
        for _ in 0..100 {
            let key_set = KeySet::rand(&mut rand::thread_rng());
            let pubkey_g1 = key_set.pubkey_g1();
            assert!(!pubkey_g1.y.sgn());
        }
    }

    #[test]
    fn test_key_set_dummy_key_account_id() {
        let account_tree = AccountTree::initialize();
        let account_id = account_tree.index(KeySet::dummy().pubkey);
        assert_eq!(account_id, Some(1)); // account_id of dummy key is 1
    }

    #[test]
    fn test_key_set_new() {
        // Create a KeySet with a known private key
        let privkey = U256::try_from(
            BigUint::parse_bytes(b"12345678901234567890123456789012345678901234567890", 10)
                .unwrap(),
        )
        .unwrap();
        let key_set = KeySet::new(privkey);

        // Verify that the private key is stored correctly
        assert_eq!(key_set.privkey, privkey);

        // Verify that the public key is derived correctly
        let pubkey_g1 = key_set.pubkey_g1();
        assert!(
            !pubkey_g1.y.sgn(),
            "Public key y-coordinate should have negative sign"
        );
        assert_eq!(
            key_set.pubkey,
            U256::try_from(BigUint::from(pubkey_g1.x)).unwrap()
        );
    }

    #[test]
    fn test_key_set_privkey_fr() {
        let privkey = U256::try_from(
            BigUint::parse_bytes(b"12345678901234567890123456789012345678901234567890", 10)
                .unwrap(),
        )
        .unwrap();
        let key_set = KeySet::new(privkey);

        // Convert private key to Fr and back to verify conversion
        let privkey_fr = key_set.privkey_fr();
        let privkey_back: U256 = BigUint::from(privkey_fr).try_into().unwrap();

        assert_eq!(
            privkey_back, key_set.privkey,
            "Private key conversion to Fr and back should be lossless"
        );
    }

    #[test]
    fn test_key_set_pubkey_g1() {
        let key_set = KeySet::rand(&mut rand::thread_rng());
        let pubkey_g1 = key_set.pubkey_g1();

        // Verify that the x-coordinate matches the stored public key
        let pubkey_from_g1: U256 = BigUint::from(pubkey_g1.x).try_into().unwrap();
        assert_eq!(
            pubkey_from_g1, key_set.pubkey,
            "Public key x-coordinate should match stored pubkey"
        );

        // Verify that the y-coordinate has negative sign
        assert!(
            !pubkey_g1.y.sgn(),
            "Public key y-coordinate should have negative sign"
        );
    }

    #[test]
    fn test_key_set_dummy() {
        let dummy_key_set = KeySet::dummy();

        // Verify dummy key set properties
        assert_eq!(
            dummy_key_set.privkey,
            U256::from_u32_slice(&[0, 0, 0, 0, 0, 0, 0, 0]).unwrap(),
            "Dummy private key should be zero"
        );
        assert_eq!(
            dummy_key_set.pubkey,
            U256::dummy_pubkey(),
            "Dummy public key should be U256::dummy_pubkey()"
        );
        assert!(
            dummy_key_set.is_dummy(),
            "is_dummy() should return true for dummy key set"
        );

        // Verify non-dummy key set
        let real_key_set = KeySet::rand(&mut rand::thread_rng());
        assert!(
            !real_key_set.is_dummy(),
            "is_dummy() should return false for non-dummy key set"
        );
    }

    #[test]
    fn test_key_set_u256_dummy_pubkey() {
        // Test U256 dummy pubkey methods
        let dummy_pubkey = U256::dummy_pubkey();
        assert_eq!(
            dummy_pubkey,
            U256::from_u32_slice(&[0, 0, 0, 0, 0, 0, 0, 1]).unwrap(),
            "Dummy pubkey should be U256::one()"
        );

        assert!(
            dummy_pubkey.is_dummy_pubkey(),
            "is_dummy_pubkey() should return true for dummy pubkey"
        );
        assert!(
            !U256::try_from(BigUint::parse_bytes(b"123456789", 10).unwrap())
                .unwrap()
                .is_dummy_pubkey(),
            "is_dummy_pubkey() should return false for non-dummy pubkey"
        );
    }
}
