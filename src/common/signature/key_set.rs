use crate::ethereum_types::{u256::U256, u32limb_trait::U32LimbTrait as _};
use ark_bn254::{Fq, Fr, G1Affine};
use ark_ec::AffineRepr;
use ark_ff::Field;
use ark_std::UniformRand;
use plonky2_bn254::fields::sgn::Sgn as _;
use rand::Rng;

#[derive(Copy, Clone, Debug)]
pub struct KeySet {
    pub is_dummy: bool,
    pub privkey: Fr,
    pub pubkey: G1Affine,
    pub pubkey_x: U256,
}

pub struct PublicKey {
    pub pubkey: G1Affine,
    pub pubkey_x: U256,
}

impl PublicKey {
    // address is the decimal representation of the x coordinate of the public key.
    pub fn from_address(address: String) -> Self {
        let pubkey_x: Fq = address.parse().unwrap();
        let pubkey = {
            let x = pubkey_x;
            let x_cubed_plus_b: Fq = x * x * x + Fq::from(3);
            let mut y = x_cubed_plus_b.sqrt().unwrap();
            if y.sgn() {
                y = -y;
            }

            G1Affine::new(x, y)
        };

        Self {
            pubkey,
            pubkey_x: pubkey_x.into(),
        }
    }
}

impl KeySet {
    pub fn rand<R: Rng>(rng: &mut R) -> Self {
        let mut privkey = Fr::rand(rng);
        let mut pubkey: G1Affine = (G1Affine::generator() * privkey.clone()).into();
        // y.sgn() should be false
        if pubkey.y.sgn() {
            privkey = -privkey.clone();
            pubkey = -pubkey;
        }
        let pubkey_x: U256 = pubkey.x.into();
        #[cfg(debug_assertions)]
        {
            use plonky2_bn254::fields::recover::RecoverFromX;
            let recovered_pubkey = G1Affine::recover_from_x(pubkey_x.into());
            assert_eq!(
                recovered_pubkey, pubkey,
                "recovered_pubkey should be equal to pubkey"
            );
        }
        Self {
            is_dummy: false,
            privkey,
            pubkey,
            pubkey_x,
        }
    }

    pub fn new(privkey: Fr) -> Self {
        let pubkey: G1Affine = (G1Affine::generator() * privkey.clone()).into();
        assert!(pubkey.y.sgn() == false, "y.sgn() should be false");
        Self {
            is_dummy: false,
            privkey,
            pubkey,
            pubkey_x: pubkey.x.into(),
        }
    }

    /// Create a dummy keyset for padding purposes
    pub fn dummy() -> Self {
        Self {
            is_dummy: true,
            privkey: Fr::ZERO,
            pubkey: G1Affine::zero(),
            // this is the smallest possible pubkey_x, which is recoverable from x
            pubkey_x: U256::one(),
        }
    }
}

#[cfg(test)]
mod tests {
    use crate::common::{signature::key_set::KeySet, trees::account_tree::AccountTree};

    #[test]
    fn dummy_key_account_id() {
        let account_tree = AccountTree::initialize();
        let account_id = account_tree.index(KeySet::dummy().pubkey_x);
        assert_eq!(account_id, Some(1)); // account_id of dummy key is 1
    }
}
