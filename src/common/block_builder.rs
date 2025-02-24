use anyhow::ensure;
use ark_bn254::{Bn254, Fr, G1Affine, G2Affine};
use ark_ec::{pairing::Pairing as _, AffineRepr as _};
use num::BigUint;
use plonky2_bn254::fields::recover::RecoverFromX;
use serde::{Deserialize, Serialize};

use crate::{
    common::signature::{
        sign::{hash_to_weight, tx_tree_root_and_expiry_to_message_point},
        utils::get_pubkey_hash,
    },
    constants::NUM_SENDERS_IN_BLOCK,
    ethereum_types::{
        bytes16::Bytes16, bytes32::Bytes32, u256::U256, u32limb_trait::U32LimbTrait as _,
    },
};

use super::{
    signature::{
        flatten::FlatG2, key_set::KeySet, sign::sign_to_tx_root_and_expiry, SignatureContent,
    },
    trees::tx_tree::TxMerkleProof,
    tx::Tx,
};

// Information that block builder presents to the user
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct BlockProposal {
    pub expiry: u64,
    pub tx_tree_root: Bytes32,
    pub tx_index: u32,
    pub tx_merkle_proof: TxMerkleProof,
    pub pubkeys: Vec<U256>, // pubkeys of the senders, without padding
    pub pubkeys_hash: Bytes32,
}

impl BlockProposal {
    pub fn verify(&self, tx: Tx) -> anyhow::Result<()> {
        self.tx_merkle_proof
            .verify(
                &tx,
                self.tx_index as u64,
                self.tx_tree_root.reduce_to_hash_out(),
            )
            .map_err(|e| anyhow::anyhow!("Failed to verify tx merkle proof: {}", e))?;
        ensure!(
            get_pubkey_hash(&self.pubkeys) == self.pubkeys_hash,
            "Invalid pubkeys hash"
        );
        Ok(())
    }

    pub fn sign(&self, key: KeySet) -> UserSignature {
        let signature: FlatG2 = sign_to_tx_root_and_expiry(
            key.privkey,
            self.tx_tree_root,
            self.expiry,
            self.pubkeys_hash,
        )
        .into();
        UserSignature {
            pubkey: key.pubkey,
            signature,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SenderWithSignature {
    pub sender: U256,
    pub signature: Option<FlatG2>,
}

pub fn construct_signature(
    tx_tree_root: Bytes32,
    expiry: u64,
    pubkey_hash: Bytes32,
    account_id_hash: Bytes32,
    is_registration_block: bool,
    sender_with_signatures: &[SenderWithSignature],
) -> SignatureContent {
    assert_eq!(sender_with_signatures.len(), NUM_SENDERS_IN_BLOCK);
    let sender_flag_bits = sender_with_signatures
        .iter()
        .map(|s| s.signature.is_some())
        .collect::<Vec<_>>();
    let sender_flag = Bytes16::from_bits_be(&sender_flag_bits);
    let agg_pubkey = sender_with_signatures
        .iter()
        .map(|s| {
            let weight = hash_to_weight(s.sender, pubkey_hash);
            if s.signature.is_some() {
                let pubkey_g1: G1Affine = G1Affine::recover_from_x(s.sender.into());
                (pubkey_g1 * Fr::from(BigUint::from(weight))).into()
            } else {
                G1Affine::zero()
            }
        })
        .fold(G1Affine::zero(), |acc: G1Affine, x: G1Affine| {
            (acc + x).into()
        });
    let agg_signature = sender_with_signatures
        .iter()
        .map(|s| {
            if let Some(signature) = s.signature.clone() {
                signature.into()
            } else {
                G2Affine::zero()
            }
        })
        .fold(G2Affine::zero(), |acc: G2Affine, x: G2Affine| {
            (acc + x).into()
        });
    // message point
    let message_point = tx_tree_root_and_expiry_to_message_point(tx_tree_root, expiry.into());
    assert!(
        Bn254::pairing(agg_pubkey, message_point)
            == Bn254::pairing(G1Affine::generator(), agg_signature)
    );
    SignatureContent {
        is_registration_block,
        tx_tree_root,
        expiry: expiry.into(),
        sender_flag,
        pubkey_hash,
        account_id_hash,
        agg_pubkey: agg_pubkey.into(),
        agg_signature: agg_signature.into(),
        message_point: message_point.into(),
    }
}

// User signature to pass to the block builder
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct UserSignature {
    pub pubkey: U256,
    pub signature: FlatG2,
}

impl UserSignature {
    // verify single user signature
    pub fn verify(
        &self,
        tx_tree_root: Bytes32,
        expiry: u64,
        pubkey_hash: Bytes32,
    ) -> anyhow::Result<()> {
        let weight = hash_to_weight(self.pubkey, pubkey_hash);
        let pubkey_g1: G1Affine = G1Affine::recover_from_x(self.pubkey.into());
        let weighted_pubkey_g1: G1Affine = (pubkey_g1 * Fr::from(BigUint::from(weight))).into();
        let signature_g2: G2Affine = self.signature.clone().into();
        let message_point = tx_tree_root_and_expiry_to_message_point(tx_tree_root, expiry.into());
        ensure!(
            Bn254::pairing(weighted_pubkey_g1, message_point)
                == Bn254::pairing(G1Affine::generator(), signature_g2),
            "Invalid signature"
        );
        Ok(())
    }
}
