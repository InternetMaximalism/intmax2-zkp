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
    pub is_dummy: bool,
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
        let recovered_pubkey = G1Affine::recover_from_x(pubkey.into());
        assert_eq!(
            recovered_pubkey, pubkey_g1,
            "recovered_pubkey should be equal to pubkey"
        );

        Self {
            is_dummy: false,
            privkey,
            pubkey,
        }
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
            is_dummy: true,
            privkey: U256::zero(),
            pubkey: U256::dummy_pubkey(),
        }
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
    use plonky2_bn254::fields::sgn::Sgn as _;

    use crate::common::{signature_content::key_set::KeySet, trees::account_tree::AccountTree};

    #[test]
    fn test_key_set_random() {
        for _ in 0..100 {
            let key_set = KeySet::rand(&mut rand::thread_rng());
            let pubkey_g1 = key_set.pubkey_g1();
            assert!(!pubkey_g1.y.sgn());
        }
    }

    #[test]
    fn dummy_key_account_id() {
        let account_tree = AccountTree::initialize();
        let account_id = account_tree.index(KeySet::dummy().pubkey);
        assert_eq!(account_id, Some(1)); // account_id of dummy key is 1
    }
}
