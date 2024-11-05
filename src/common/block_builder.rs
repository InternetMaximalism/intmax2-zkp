use anyhow::ensure;
use ark_bn254::{Bn254, G1Affine, G2Affine};
use ark_ec::{pairing::Pairing as _, AffineRepr as _};
use plonky2::field::{goldilocks_field::GoldilocksField, types::Field as _};
use plonky2_bn254::{
    curves::g2::G2Target, fields::recover::RecoverFromX, utils::hash_to_g2::HashToG2 as _,
};

use crate::{
    common::signature::utils::get_pubkey_hash,
    ethereum_types::{bytes32::Bytes32, u256::U256, u32limb_trait::U32LimbTrait},
};

use super::{
    signature::{flatten::FlatG2, key_set::KeySet, sign::sign_to_tx_root},
    trees::tx_tree::TxMerkleProof,
    tx::Tx,
};

// Information that block builder presents to the user
#[derive(Debug, Clone)]
pub struct BlockProposal {
    pub tx_tree_root: Bytes32,
    pub tx_index: usize,
    pub tx_merkle_proof: TxMerkleProof,
    pub pubkeys: Vec<U256>, // pubkeys of the senders, without padding
    pub pubkeys_hash: Bytes32,
}

impl BlockProposal {
    pub fn verify(&self, tx: Tx) -> anyhow::Result<()> {
        self.tx_merkle_proof
            .verify(&tx, self.tx_index, self.tx_tree_root.reduce_to_hash_out())
            .map_err(|e| anyhow::anyhow!("Failed to verify tx merkle proof: {}", e))?;
        ensure!(
            get_pubkey_hash(&self.pubkeys) == self.pubkeys_hash,
            "Invalid pubkeys hash"
        );
        Ok(())
    }

    pub fn sign(&self, key: KeySet) -> UserSignature {
        let signature: FlatG2 =
            sign_to_tx_root(key.privkey, self.tx_tree_root, self.pubkeys_hash).into();
        UserSignature {
            pubkey: key.pubkey,
            signature,
        }
    }
}

// User signature to pass to the block builder
#[derive(Debug, Clone)]
pub struct UserSignature {
    pub pubkey: U256,
    pub signature: FlatG2,
}

impl UserSignature {
    // verify single user signature
    pub fn verify(&self, tx_tree_root: Bytes32) -> anyhow::Result<()> {
        let pubkey_g1: G1Affine = G1Affine::recover_from_x(self.pubkey.into());
        let signature_g2: G2Affine = self.signature.clone().into();
        let message_point = tx_tree_root_to_message_point(tx_tree_root);
        ensure!(
            Bn254::pairing(pubkey_g1, message_point)
                == Bn254::pairing(G1Affine::generator(), signature_g2),
            "Invalid signature"
        );
        Ok(())
    }
}

pub fn tx_tree_root_to_message_point(tx_tree_root: Bytes32) -> G2Affine {
    let tx_tree_root_f = tx_tree_root
        .to_u32_vec()
        .iter()
        .map(|x| GoldilocksField::from_canonical_u32(*x))
        .collect::<Vec<_>>();
    let message_point = G2Target::<GoldilocksField, 2>::hash_to_g2(&tx_tree_root_f);
    message_point
}
