use crate::ethereum_types::{
    address::{Address, AddressTarget, ADDRESS_LEN},
    bytes32::{Bytes32, Bytes32Target, BYTES32_LEN},
    u256::{U256Target, U256},
    u32limb_trait::{U32LimbTargetTrait as _, U32LimbTrait as _},
    u64::{U64Target, U64, U64_LEN},
};
use ark_bn254::{Fr, G1Affine, G2Affine};
use ark_ec::AffineRepr;
use num::{BigUint, One, Zero as _};
use plonky2::{
    field::{extension::Extendable, goldilocks_field::GoldilocksField, types::Field},
    hash::{hash_types::RichField, poseidon::PoseidonHash},
    iop::{
        challenger::{Challenger, RecursiveChallenger},
        target::{BoolTarget, Target},
        witness::WitnessWrite,
    },
    plonk::{
        circuit_builder::CircuitBuilder,
        config::{AlgebraicHasher, GenericConfig},
    },
};
use plonky2_bn254::{
    curves::g2::G2Target,
    fields::biguint::{BigUintTarget, CircuitBuilderBiguint},
    utils::hash_to_g2::HashToG2 as _,
};
use plonky2_u32::gadgets::arithmetic_u32::U32Target;
use rand::Rng;
use serde::{Deserialize, Serialize};

use super::flatten::{FlatG2, FlatG2Target};

pub const BLOCK_SIGN_PAYLOAD_LEN: usize = 1 + BYTES32_LEN + U64_LEN + ADDRESS_LEN + 1;

#[derive(Default, Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct BlockSignPayload {
    pub is_registration_block: bool,
    pub tx_tree_root: Bytes32,
    pub expiry: U64,
    pub block_builder_address: Address,
    pub block_builder_nonce: u32,
}

impl BlockSignPayload {
    pub fn to_u32_vec(&self) -> Vec<u32> {
        let mut vec = Vec::new();
        vec.push(self.is_registration_block as u32);
        vec.extend_from_slice(&self.tx_tree_root.to_u32_vec());
        vec.extend_from_slice(&self.expiry.to_u32_vec());
        vec.extend_from_slice(&self.block_builder_address.to_u32_vec());
        vec.push(self.block_builder_nonce);
        assert_eq!(vec.len(), BLOCK_SIGN_PAYLOAD_LEN);
        vec
    }

    pub fn message_point(&self) -> FlatG2 {
        let elements = self
            .to_u32_vec()
            .iter()
            .map(|x| GoldilocksField::from_canonical_u32(*x))
            .collect::<Vec<_>>();
        G2Target::<GoldilocksField, 2>::hash_to_g2(&elements).into()
    }

    pub fn sign(&self, privkey: Fr, pubkey_hash: Bytes32) -> FlatG2 {
        let pubkey: G1Affine = (G1Affine::generator() * privkey).into();
        let pubkey_x: U256 = pubkey.x.into();
        let weight = hash_to_weight(pubkey_x, pubkey_hash);
        let message_point: G2Affine = self.message_point().into();
        let signature: G2Affine =
            (message_point * privkey * Fr::from(BigUint::from(weight))).into();
        signature.into()
    }

    pub fn rand<R: Rng>(rng: &mut R) -> Self {
        let expiry = 0;
        let tx_tree_root = Bytes32::rand(rng);
        let is_registration_block = rng.gen();
        let block_builder_address = Address::rand(rng);
        let block_builder_nonce = rng.gen();
        Self {
            is_registration_block,
            tx_tree_root,
            expiry: expiry.into(),
            block_builder_address,
            block_builder_nonce,
        }
    }
}

#[derive(Clone, Debug)]
pub struct BlockSignPayloadTarget {
    pub is_registration_block: BoolTarget,
    pub tx_tree_root: Bytes32Target,
    pub expiry: U64Target,
    pub block_builder_address: AddressTarget,
    pub block_builder_nonce: Target,
}

impl BlockSignPayloadTarget {
    pub fn new<F: RichField + Extendable<D>, const D: usize>(
        builder: &mut CircuitBuilder<F, D>,
        range_check: bool,
    ) -> Self {
        let is_registration_block = builder.add_virtual_bool_target_unsafe();
        let tx_tree_root = Bytes32Target::new(builder, range_check);
        let expiry = U64Target::new(builder, range_check);
        let block_builder_address = AddressTarget::new(builder, range_check);
        let block_builder_nonce = builder.add_virtual_target();
        if range_check {
            builder.assert_bool(is_registration_block);
            builder.range_check(block_builder_nonce, 32);
        }
        Self {
            is_registration_block,
            tx_tree_root,
            expiry,
            block_builder_address,
            block_builder_nonce,
        }
    }

    pub fn to_vec(&self) -> Vec<Target> {
        let mut vec = Vec::new();
        vec.push(self.is_registration_block.target);
        vec.extend_from_slice(&self.tx_tree_root.to_vec());
        vec.extend_from_slice(&self.expiry.to_vec());
        vec.extend_from_slice(&self.block_builder_address.to_vec());
        vec.push(self.block_builder_nonce);
        assert_eq!(vec.len(), BLOCK_SIGN_PAYLOAD_LEN);
        vec
    }

    pub fn message_point<
        F: RichField + Extendable<D>,
        C: GenericConfig<D, F = F> + 'static,
        const D: usize,
    >(
        &self,
        builder: &mut CircuitBuilder<F, D>,
    ) -> FlatG2Target
    where
        <C as GenericConfig<D>>::Hasher: AlgebraicHasher<F>,
    {
        let elements = self.to_vec().to_vec();
        G2Target::<F, D>::hash_to_g2_circuit::<C>(builder, &elements).into()
    }

    pub fn constant<F: RichField + Extendable<D>, const D: usize>(
        builder: &mut CircuitBuilder<F, D>,
        value: &BlockSignPayload,
    ) -> Self {
        Self {
            is_registration_block: builder.constant_bool(value.is_registration_block),
            tx_tree_root: Bytes32Target::constant(builder, value.tx_tree_root),
            expiry: U64Target::constant(builder, value.expiry),
            block_builder_address: AddressTarget::constant(builder, value.block_builder_address),
            block_builder_nonce: builder.constant(F::from_canonical_u32(value.block_builder_nonce)),
        }
    }

    pub fn set_witness<W: WitnessWrite<F>, F: Field>(
        &self,
        witness: &mut W,
        value: &BlockSignPayload,
    ) {
        witness.set_bool_target(self.is_registration_block, value.is_registration_block);
        self.tx_tree_root.set_witness(witness, value.tx_tree_root);
        self.expiry.set_witness(witness, value.expiry);
        self.block_builder_address
            .set_witness(witness, value.block_builder_address);
        witness.set_target(
            self.block_builder_nonce,
            F::from_canonical_u32(value.block_builder_nonce),
        );
    }
}

pub(crate) fn hash_to_weight(my_pubkey: U256, pubkey_hash: Bytes32) -> U256 {
    type F = GoldilocksField;
    let flattened = my_pubkey
        .to_u32_vec()
        .into_iter()
        .chain(pubkey_hash.to_u32_vec())
        .map(F::from_canonical_u32)
        .collect::<Vec<_>>();
    let mut challenger = Challenger::<F, PoseidonHash>::new();
    challenger.observe_elements(&flattened);
    let output = challenger.get_n_challenges(16);
    field_slice_to_biguint(&output).try_into().unwrap()
}

pub(crate) fn hash_to_weight_circuit<F: RichField + Extendable<D>, const D: usize>(
    builder: &mut CircuitBuilder<F, D>,
    my_pubkey: U256Target,
    pubkey_hash: Bytes32Target,
) -> U256Target {
    let flattened = my_pubkey
        .to_vec()
        .into_iter()
        .chain(pubkey_hash.to_vec())
        .collect::<Vec<_>>();
    let mut challenger = RecursiveChallenger::<F, PoseidonHash, D>::new(builder);
    challenger.observe_elements(&flattened);
    let output = challenger.get_n_challenges(builder, 16);
    let output = target_slice_to_biguint_target(builder, &output);

    U256Target::from_slice(
        &output
            .limbs
            .into_iter()
            .map(|x| x.0)
            .rev()
            .collect::<Vec<_>>(),
    )
}

fn field_slice_to_biguint<F: RichField>(input: &[F]) -> BigUint {
    let limbs = input
        .iter()
        .map(|c| {
            let x = c.to_canonical_u64();
            // discard the high bits because it's not uniformly distributed
            x as u32
        })
        .collect::<Vec<_>>();
    let mut value = BigUint::zero();
    for (i, limb) in limbs.iter().enumerate() {
        value += BigUint::from(*limb) << (i * 32);
    }
    let r = BigUint::from(Fr::from(-1)) + BigUint::one();
    value % r
}

fn target_slice_to_biguint_target<F: RichField + Extendable<D>, const D: usize>(
    builder: &mut CircuitBuilder<F, D>,
    input: &[Target],
) -> BigUintTarget {
    let limbs = input
        .iter()
        .map(|c| {
            let (lo, _hi) = builder.split_low_high(*c, 32, 64);
            // discard the high bits because it's not uniformly distributed
            U32Target(lo)
        })
        .collect::<Vec<_>>();
    let r = BigUint::from(Fr::from(-1)) + BigUint::one();
    let value = BigUintTarget { limbs };
    builder.div_rem_biguint(&value, &r).1
}

#[cfg(test)]
mod tests {
    use plonky2::{
        field::goldilocks_field::GoldilocksField,
        iop::witness::PartialWitness,
        plonk::{
            circuit_builder::CircuitBuilder, circuit_data::CircuitConfig,
            config::PoseidonGoldilocksConfig,
        },
    };

    use super::{BlockSignPayload, BlockSignPayloadTarget};

    type F = GoldilocksField;
    const D: usize = 2;
    type C = PoseidonGoldilocksConfig;

    #[test]
    fn test_block_sign_payload_message_point_circuit() {
        let rng = &mut rand::thread_rng();

        let payload = BlockSignPayload::rand(rng);
        let message_point = payload.message_point();

        let mut builder = CircuitBuilder::<F, D>::new(CircuitConfig::default());
        let payload_target = BlockSignPayloadTarget::constant(&mut builder, &payload);
        let message_point_target = payload_target.message_point::<F, C, D>(&mut builder);

        let mut pw = PartialWitness::new();
        message_point_target.set_witness(&mut pw, &message_point);
        let circuit = builder.build::<C>();
        let proof = circuit.prove(pw).unwrap();
        assert!(circuit.verify(proof).is_ok());
    }
}
