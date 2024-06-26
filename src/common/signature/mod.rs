pub mod format_validation;
pub mod key_set;
pub mod sign;
pub mod utils;
pub mod verify;

use ark_bn254::Fq;
use num::BigUint;
use plonky2::{
    field::extension::Extendable,
    hash::hash_types::RichField,
    iop::{
        target::{BoolTarget, Target},
        witness::Witness,
    },
    plonk::{
        circuit_builder::CircuitBuilder,
        config::{AlgebraicHasher, GenericConfig},
    },
};
use plonky2_bn254::fields::fq::FqTarget;
use plonky2_keccak::{builder::BuilderKeccak256 as _, utils::solidity_keccak256};
use serde::{Deserialize, Serialize};

use crate::{
    ethereum_types::{
        bytes32::{Bytes32, BYTES32_LEN},
        u128::{U128, U128_LEN},
        u256::{U256, U256_LEN},
        u32limb_trait::{U32LimbTargetTrait, U32LimbTrait},
    },
    utils::poseidon_hash_out::{PoseidonHashOut, PoseidonHashOutTarget},
};

pub const SIGNATURE_LEN: usize = 1 + U128_LEN + 3 * BYTES32_LEN + 10 * U256_LEN;

/// The signature that is verified by the contract. It is already guaranteed by
/// the contract that e(`agg_pubkey`, message_point) = e(`agg_signature`, G2)
/// holds.
#[derive(Clone, Default, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SignatureContent {
    pub is_registoration_block: bool,
    pub tx_tree_root: Bytes32<u32>,
    pub sender_flag: U128<u32>,
    pub pubkey_hash: Bytes32<u32>,
    pub account_id_hash: Bytes32<u32>,
    pub agg_pubkey: [U256<u32>; 2],
    pub agg_signature: [U256<u32>; 4],
    pub message_point: [U256<u32>; 4],
}

#[derive(Clone, Debug)]
pub struct SignatureContentTarget {
    pub is_registoration_block: BoolTarget,
    pub tx_tree_root: Bytes32<Target>,
    pub sender_flag: U128<Target>,
    pub pubkey_hash: Bytes32<Target>,
    pub account_id_hash: Bytes32<Target>,
    pub agg_pubkey: [U256<Target>; 2],
    pub agg_signature: [U256<Target>; 4],
    pub message_point: [U256<Target>; 4],
}

impl SignatureContent {
    pub fn to_u32_vec(&self) -> Vec<u32> {
        let limbs = vec![
            vec![self.is_registoration_block as u32],
            self.tx_tree_root.limbs(),
            self.sender_flag.limbs(),
            self.pubkey_hash.limbs(),
            self.account_id_hash.limbs(),
            self.agg_pubkey[0].limbs(),
            self.agg_pubkey[1].limbs(),
            self.agg_signature[0].limbs(),
            self.agg_signature[1].limbs(),
            self.agg_signature[2].limbs(),
            self.agg_signature[3].limbs(),
            self.message_point[0].limbs(),
            self.message_point[1].limbs(),
            self.message_point[2].limbs(),
            self.message_point[3].limbs(),
        ]
        .concat();
        limbs
    }

    pub fn commitment(&self) -> PoseidonHashOut {
        PoseidonHashOut::hash_inputs_u32(&self.to_u32_vec())
    }

    pub fn hash(&self) -> Bytes32<u32> {
        Bytes32::<u32>::from_limbs(&solidity_keccak256(&self.to_u32_vec()))
    }
}

impl SignatureContentTarget {
    pub fn to_vec<F: RichField>(&self) -> Vec<Target> {
        let vec = vec![
            vec![self.is_registoration_block.target],
            self.tx_tree_root.to_vec(),
            self.sender_flag.to_vec(),
            self.pubkey_hash.to_vec(),
            self.account_id_hash.to_vec(),
            self.agg_pubkey[0].to_vec(),
            self.agg_pubkey[1].to_vec(),
            self.agg_signature[0].to_vec(),
            self.agg_signature[1].to_vec(),
            self.agg_signature[2].to_vec(),
            self.agg_signature[3].to_vec(),
            self.message_point[0].to_vec(),
            self.message_point[1].to_vec(),
            self.message_point[2].to_vec(),
            self.message_point[3].to_vec(),
        ]
        .concat();
        assert_eq!(vec.len(), SIGNATURE_LEN);
        vec
    }

    pub fn new<F: RichField + Extendable<D>, const D: usize>(
        builder: &mut CircuitBuilder<F, D>,
        is_checked: bool,
    ) -> Self {
        let is_registoration_block = builder.add_virtual_bool_target_unsafe();
        if is_checked {
            builder.assert_bool(is_registoration_block);
        }
        Self {
            tx_tree_root: Bytes32::new(builder, is_checked),
            is_registoration_block,
            sender_flag: U128::<Target>::new(builder, is_checked),
            pubkey_hash: Bytes32::<Target>::new(builder, is_checked),
            account_id_hash: Bytes32::<Target>::new(builder, is_checked),
            agg_pubkey: [
                U256::<Target>::new(builder, is_checked),
                U256::<Target>::new(builder, is_checked),
            ],
            agg_signature: [
                U256::<Target>::new(builder, is_checked),
                U256::<Target>::new(builder, is_checked),
                U256::<Target>::new(builder, is_checked),
                U256::<Target>::new(builder, is_checked),
            ],
            message_point: [
                U256::<Target>::new(builder, is_checked),
                U256::<Target>::new(builder, is_checked),
                U256::<Target>::new(builder, is_checked),
                U256::<Target>::new(builder, is_checked),
            ],
        }
    }

    pub fn constant<F: RichField + Extendable<D>, const D: usize>(
        builder: &mut CircuitBuilder<F, D>,
        value: &SignatureContent,
    ) -> Self {
        Self {
            tx_tree_root: Bytes32::<Target>::constant(builder, value.tx_tree_root),
            is_registoration_block: builder.constant_bool(value.is_registoration_block),
            sender_flag: U128::<Target>::constant(builder, value.sender_flag),
            pubkey_hash: Bytes32::<Target>::constant(builder, value.pubkey_hash),
            account_id_hash: Bytes32::<Target>::constant(builder, value.account_id_hash),
            agg_pubkey: [
                U256::<Target>::constant(builder, value.agg_pubkey[0]),
                U256::<Target>::constant(builder, value.agg_pubkey[1]),
            ],
            agg_signature: [
                U256::<Target>::constant(builder, value.agg_signature[0]),
                U256::<Target>::constant(builder, value.agg_signature[1]),
                U256::<Target>::constant(builder, value.agg_signature[2]),
                U256::<Target>::constant(builder, value.agg_signature[3]),
            ],
            message_point: [
                U256::<Target>::constant(builder, value.message_point[0]),
                U256::<Target>::constant(builder, value.message_point[1]),
                U256::<Target>::constant(builder, value.message_point[2]),
                U256::<Target>::constant(builder, value.message_point[3]),
            ],
        }
    }

    pub fn set_witness<F: RichField, W: Witness<F>>(
        &self,
        witness: &mut W,
        value: &SignatureContent,
    ) {
        self.tx_tree_root.set_witness(witness, value.tx_tree_root);
        witness.set_bool_target(self.is_registoration_block, value.is_registoration_block);
        self.sender_flag.set_witness(witness, value.sender_flag);
        self.pubkey_hash.set_witness(witness, value.pubkey_hash);
        self.account_id_hash
            .set_witness(witness, value.account_id_hash);
        self.agg_pubkey[0].set_witness(witness, value.agg_pubkey[0]);
        self.agg_pubkey[1].set_witness(witness, value.agg_pubkey[1]);
        self.agg_signature[0].set_witness(witness, value.agg_signature[0]);
        self.agg_signature[1].set_witness(witness, value.agg_signature[1]);
        self.agg_signature[2].set_witness(witness, value.agg_signature[2]);
        self.agg_signature[3].set_witness(witness, value.agg_signature[3]);
        self.message_point[0].set_witness(witness, value.message_point[0]);
        self.message_point[1].set_witness(witness, value.message_point[1]);
        self.message_point[2].set_witness(witness, value.message_point[2]);
        self.message_point[3].set_witness(witness, value.message_point[3]);
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
    ) -> Bytes32<Target>
    where
        <C as GenericConfig<D>>::Hasher: AlgebraicHasher<F>,
    {
        Bytes32::<Target>::from_limbs(&builder.keccak256::<C>(&self.to_vec::<F>()))
    }
}

pub(super) fn pubkey_range_check(pubkey: U256<u32>) -> bool {
    let pubky_bg: BigUint = pubkey.into();
    let modulus = BigUint::from(Fq::from(-1)) + 1u32;
    pubky_bg < modulus
}

pub(super) fn u256_to_fq_target<F: RichField + Extendable<D>, const D: usize>(
    x: U256<Target>,
) -> FqTarget<F, D> {
    FqTarget::from_vec(&x.limbs().into_iter().rev().collect::<Vec<_>>())
}

pub(super) fn fq_to_u256_target<F: RichField + Extendable<D>, const D: usize>(
    x: FqTarget<F, D>,
) -> U256<Target> {
    U256::<Target>::from_limbs(&x.to_vec().into_iter().rev().collect::<Vec<_>>())
}
