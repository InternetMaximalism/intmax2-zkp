pub mod block_sign_payload;
pub mod flatten;
pub mod format_validation;
pub mod key_set;
pub mod serialize;
pub mod sign_tools;
pub mod utils;
pub mod verify;

use ark_bn254::Fq;
use block_sign_payload::{BlockSignPayload, BlockSignPayloadTarget};
use flatten::{FlatG1, FlatG1Target, FlatG2, FlatG2Target};
use num::BigUint;
use plonky2::{
    field::extension::Extendable,
    hash::hash_types::RichField,
    iop::{target::Target, witness::Witness},
    plonk::{
        circuit_builder::CircuitBuilder,
        config::{AlgebraicHasher, GenericConfig},
    },
};

use plonky2_keccak::{builder::BuilderKeccak256 as _, utils::solidity_keccak256};
use serde::{Deserialize, Serialize};

use crate::{
    ethereum_types::{
        bytes16::{Bytes16, Bytes16Target, BYTES16_LEN},
        bytes32::{Bytes32, Bytes32Target, BYTES32_LEN},
        u256::{U256, U256_LEN},
        u32limb_trait::{U32LimbTargetTrait, U32LimbTrait},
        u64::U64Target,
    },
    utils::poseidon_hash_out::{PoseidonHashOut, PoseidonHashOutTarget},
};

pub const SIGNATURE_LEN: usize = 1 + BYTES16_LEN + 2 * BYTES32_LEN + 10 * U256_LEN;

#[derive(Debug, thiserror::Error)]
pub enum SignatureContentError {}

/// The signature that is verified by the contract. It is already guaranteed by
/// the contract that e(`agg_pubkey`, message_point) = e(`agg_signature`, G2)
/// holds.
#[derive(Clone, Default, Debug, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SignatureContent {
    pub block_sign_payload: BlockSignPayload,
    pub sender_flag: Bytes16,
    pub pubkey_hash: Bytes32,
    pub account_id_hash: Bytes32,
    pub agg_pubkey: FlatG1,
    pub agg_signature: FlatG2,
    pub message_point: FlatG2,
}

#[derive(Clone, Debug)]
pub struct SignatureContentTarget {
    pub block_sign_payload: BlockSignPayloadTarget,
    pub sender_flag: Bytes16Target,
    pub pubkey_hash: Bytes32Target,
    pub account_id_hash: Bytes32Target,
    pub agg_pubkey: FlatG1Target,
    pub agg_signature: FlatG2Target,
    pub message_point: FlatG2Target,
}

impl SignatureContent {
    pub fn to_u32_vec(&self) -> Vec<u32> {
        let vec = vec![
            self.block_sign_payload.to_u32_vec(),
            self.sender_flag.to_u32_vec(),
            self.pubkey_hash.to_u32_vec(),
            self.account_id_hash.to_u32_vec(),
            self.agg_pubkey.to_u32_vec(),
            self.agg_signature.to_u32_vec(),
            self.message_point.to_u32_vec(),
        ]
        .concat();
        assert_eq!(vec.len(), SIGNATURE_LEN);
        vec
    }

    pub fn commitment(&self) -> PoseidonHashOut {
        PoseidonHashOut::hash_inputs_u32(&self.to_u32_vec())
    }

    pub fn hash(&self) -> Bytes32 {
        Bytes32::from_u32_slice(&solidity_keccak256(&self.to_u32_vec()))
            .expect("Failed to convert from U32 to Bytes32")
    }
}

impl SignatureContentTarget {
    pub fn to_vec<F: RichField>(&self) -> Vec<Target> {
        let vec = vec![
            self.block_sign_payload.to_vec(),
            self.sender_flag.to_vec(),
            self.pubkey_hash.to_vec(),
            self.account_id_hash.to_vec(),
            self.agg_pubkey.to_vec(),
            self.agg_signature.to_vec(),
            self.message_point.to_vec(),
        ]
        .concat();
        assert_eq!(vec.len(), SIGNATURE_LEN);
        vec
    }

    pub fn new<F: RichField + Extendable<D>, const D: usize>(
        builder: &mut CircuitBuilder<F, D>,
        range_check: bool,
    ) -> Self {
        Self {
            block_sign_payload: BlockSignPayloadTarget::new(builder, range_check),
            sender_flag: Bytes16Target::new(builder, range_check),
            pubkey_hash: Bytes32Target::new(builder, range_check),
            account_id_hash: Bytes32Target::new(builder, range_check),
            agg_pubkey: FlatG1Target::new(builder, range_check),
            agg_signature: FlatG2Target::new(builder, range_check),
            message_point: FlatG2Target::new(builder, range_check),
        }
    }

    pub fn constant<F: RichField + Extendable<D>, const D: usize>(
        builder: &mut CircuitBuilder<F, D>,
        value: &SignatureContent,
    ) -> Self {
        Self {
            block_sign_payload: BlockSignPayloadTarget::constant(builder, &value.block_sign_payload),
            sender_flag: Bytes16Target::constant(builder, value.sender_flag),
            pubkey_hash: Bytes32Target::constant(builder, value.pubkey_hash),
            account_id_hash: Bytes32Target::constant(builder, value.account_id_hash),
            agg_pubkey: FlatG1Target::constant(builder, &value.agg_pubkey),
            agg_signature: FlatG2Target::constant(builder, &value.agg_signature),
            message_point: FlatG2Target::constant(builder, &value.message_point),
        }
    }

    pub fn set_witness<F: RichField, W: Witness<F>>(
        &self,
        witness: &mut W,
        value: &SignatureContent,
    ) {
        self.block_sign_payload
            .set_witness(witness, &value.block_sign_payload);
        self.sender_flag.set_witness(witness, value.sender_flag);
        self.pubkey_hash.set_witness(witness, value.pubkey_hash);
        self.account_id_hash
            .set_witness(witness, value.account_id_hash);
        self.agg_pubkey.set_witness(witness, &value.agg_pubkey);
        self.agg_signature
            .set_witness(witness, &value.agg_signature);
        self.message_point
            .set_witness(witness, &value.message_point);
    }

    pub fn commitment<F: RichField + Extendable<D>, const D: usize>(
        &self,
        builder: &mut CircuitBuilder<F, D>,
    ) -> PoseidonHashOutTarget {
        PoseidonHashOutTarget::hash_inputs::<F, D>(builder, &self.to_vec::<F>())
    }

    pub fn hash<
        F: RichField + Extendable<D>,
        C: GenericConfig<D, F = F> + 'static,
        const D: usize,
    >(
        &self,
        builder: &mut CircuitBuilder<F, D>,
    ) -> Bytes32Target
    where
        <C as GenericConfig<D>>::Hasher: AlgebraicHasher<F>,
    {
        Bytes32Target::from_slice(&builder.keccak256::<C>(&self.to_vec::<F>()))
    }
}

pub(super) fn pubkey_range_check(pubkey: U256) -> bool {
    let pubkey_bg: BigUint = pubkey.into();
    let modulus = BigUint::from(Fq::from(-1)) + 1u32;
    pubkey_bg < modulus
}
