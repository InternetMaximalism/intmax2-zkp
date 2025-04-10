use ark_bn254::{Bn254, Fr, G1Affine, G2Affine};
use ark_ec::{pairing::Pairing as _, AffineRepr as _};
use num::BigUint;
use plonky2_bn254::fields::recover::RecoverFromX;
use serde::{Deserialize, Serialize};

use crate::{
    common::{
        error::CommonError,
        signature_content::{
            block_sign_payload::{hash_to_weight, BlockSignPayload},
            flatten::FlatG1,
            utils::get_pubkey_hash,
        },
    },
    constants::NUM_SENDERS_IN_BLOCK,
    ethereum_types::{
        bytes16::Bytes16, bytes32::Bytes32, u256::U256, u32limb_trait::U32LimbTrait as _,
    },
};

use super::{
    signature_content::{flatten::FlatG2, key_set::KeySet, SignatureContent},
    trees::tx_tree::TxMerkleProof,
    tx::Tx,
};

// Information that block builder presents to the user
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct BlockProposal {
    pub block_sign_payload: BlockSignPayload,
    pub tx_index: u32,
    pub tx_merkle_proof: TxMerkleProof,
    pub pubkeys: Vec<U256>, // pubkeys of the senders, without padding
    pub pubkeys_hash: Bytes32,
}

impl BlockProposal {
    pub fn verify(&self, tx: Tx) -> Result<(), CommonError> {
        self.tx_merkle_proof
            .verify(
                &tx,
                self.tx_index as u64,
                self.block_sign_payload.tx_tree_root.reduce_to_hash_out(),
            )
            .map_err(|e| CommonError::TxMerkleProofVerificationFailed(e.to_string()))?;

        if get_pubkey_hash(&self.pubkeys) != self.pubkeys_hash {
            return Err(CommonError::InvalidData("Invalid pubkeys hash".to_string()));
        }

        Ok(())
    }

    pub fn sign(&self, key: KeySet) -> UserSignature {
        let signature: FlatG2 = self.block_sign_payload.sign(key.privkey, self.pubkeys_hash);
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
    block_sign_payload: &BlockSignPayload,
    pubkey_hash: Bytes32,
    account_id_hash: Bytes32,
    sender_with_signatures: &[SenderWithSignature],
) -> SignatureContent {
    assert_eq!(sender_with_signatures.len(), NUM_SENDERS_IN_BLOCK);
    let sender_flag_bits = sender_with_signatures
        .iter()
        .map(|s| s.signature.is_some())
        .collect::<Vec<_>>();
    let sender_flag = Bytes16::from_bits_be(&sender_flag_bits).unwrap();
    let agg_pubkey: FlatG1 = sender_with_signatures
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
        })
        .into();
    let agg_signature: FlatG2 = sender_with_signatures
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
        })
        .into();
    // message point
    let message_point = block_sign_payload.message_point();
    assert!(
        Bn254::pairing(
            G1Affine::from(agg_pubkey.clone()),
            G2Affine::from(message_point.clone())
        ) == Bn254::pairing(G1Affine::generator(), G2Affine::from(agg_signature.clone()))
    );
    SignatureContent {
        block_sign_payload: block_sign_payload.clone(),
        sender_flag,
        pubkey_hash,
        account_id_hash,
        agg_pubkey,
        agg_signature,
        message_point,
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
        block_sign_payload: &BlockSignPayload,
        pubkey_hash: Bytes32,
    ) -> Result<(), CommonError> {
        let weight = hash_to_weight(self.pubkey, pubkey_hash);
        let pubkey_g1: G1Affine = G1Affine::recover_from_x(self.pubkey.into());
        let weighted_pubkey_g1: G1Affine = (pubkey_g1 * Fr::from(BigUint::from(weight))).into();
        let message_point = block_sign_payload.message_point();

        if Bn254::pairing(weighted_pubkey_g1, G2Affine::from(message_point))
            != Bn254::pairing(
                G1Affine::generator(),
                G2Affine::from(self.signature.clone()),
            )
        {
            return Err(CommonError::InvalidSignature);
        }

        Ok(())
    }
}
