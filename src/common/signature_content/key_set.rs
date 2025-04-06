use crate::ethereum_types::{
    u256::{U256Target, U256},
    u32limb_trait::{U32LimbTargetTrait, U32LimbTrait as _},
};
use ark_bn254::{Fr, G1Affine};
use ark_ec::AffineRepr;
use ark_ff::Field;
use ark_std::UniformRand;
use plonky2::{
    field::extension::Extendable, hash::hash_types::RichField, iop::target::BoolTarget,
    plonk::circuit_builder::CircuitBuilder,
};
use plonky2_bn254::fields::sgn::Sgn as _;
use rand::Rng;

#[derive(Copy, Clone, Debug)]
pub struct KeySet {
    pub is_dummy: bool,
    pub privkey: Fr,
    pub pubkey_g1: G1Affine,
    pub pubkey: U256,
}

impl KeySet {
    pub fn rand<R: Rng>(rng: &mut R) -> Self {
        let provisional_privkey = Fr::rand(rng);
        Self::generate_from_provisional(provisional_privkey)
    }

    pub fn generate_from_provisional(provisional_privkey: Fr) -> Self {
        let mut privkey = provisional_privkey;
        let mut pubkey_g1: G1Affine = (G1Affine::generator() * privkey).into();
        // y.sgn() should be false
        if pubkey_g1.y.sgn() {
            privkey = -privkey;
            pubkey_g1 = -pubkey_g1;
        }
        let pubkey: U256 = pubkey_g1.x.into();
        #[cfg(debug_assertions)]
        {
            use plonky2_bn254::fields::recover::RecoverFromX;
            let recovered_pubkey = G1Affine::recover_from_x(pubkey.into());
            debug_assert_eq!(
                recovered_pubkey, pubkey_g1,
                "recovered_pubkey should be equal to pubkey"
            );
        }
        Self {
            is_dummy: false,
            privkey,
            pubkey_g1,
            pubkey,
        }
    }

    pub fn new(privkey: Fr) -> Self {
        let pubkey: G1Affine = (G1Affine::generator() * privkey).into();
        assert!(!pubkey.y.sgn(), "y.sgn() should be false");
        Self {
            is_dummy: false,
            privkey,
            pubkey_g1: pubkey,
            pubkey: pubkey.x.into(),
        }
    }

    /// Create a dummy keyset for padding purposes
    pub fn dummy() -> Self {
        Self {
            is_dummy: true,
            privkey: Fr::ZERO,
            pubkey_g1: G1Affine::zero(),
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
    use crate::common::{signature_content::key_set::KeySet, trees::account_tree::AccountTree};

    #[test]
    fn dummy_key_account_id() {
        let account_tree = AccountTree::initialize();
        let account_id = account_tree.index(KeySet::dummy().pubkey);
        assert_eq!(account_id, Some(1)); // account_id of dummy key is 1
    }
}
