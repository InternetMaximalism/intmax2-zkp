use plonky2::{
    field::{extension::Extendable, types::Field},
    hash::hash_types::RichField,
    iop::{
        target::{BoolTarget, Target},
        witness::WitnessWrite,
    },
    plonk::{
        circuit_builder::CircuitBuilder,
        config::{AlgebraicHasher, GenericConfig},
    },
};
use plonky2_keccak::{builder::BuilderKeccak256 as _, utils::solidity_keccak256};
use rand::Rng;
use serde::{Deserialize, Serialize};

use crate::{
    ethereum_types::{
        address::{Address, AddressTarget},
        bytes32::{Bytes32, Bytes32Target},
        u256::{U256Target, U256},
        u32limb_trait::{U32LimbTargetTrait as _, U32LimbTrait},
    },
    utils::{
        leafable::{Leafable, LeafableTarget},
        leafable_hasher::KeccakLeafableHasher,
        poseidon_hash_out::{PoseidonHashOut, PoseidonHashOutTarget},
    },
};

use super::salt::{Salt, SaltTarget};

/// A deposit of tokens to the contract
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Deposit {
    pub depositor: Address,        // The address of the depositor
    pub pubkey_salt_hash: Bytes32, // The poseidon hash of the pubkey and salt, to hide the pubkey
    pub amount: U256,              // The amount of the token, which is the amount of the deposit
    pub token_index: u32,          // The index of the token
    pub is_eligible: bool,         /* The flag to indicate whether the depositor is eligible for
                                    * the mining reward */
}

#[derive(Debug, Clone)]
pub struct DepositTarget {
    pub depositor: AddressTarget,
    pub pubkey_salt_hash: Bytes32Target,
    pub amount: U256Target,
    pub token_index: Target,
    pub is_eligible: BoolTarget,
}

impl Deposit {
    pub fn to_u32_vec(&self) -> Vec<u32> {
        let vec = vec![
            self.depositor.to_u32_vec(),
            self.pubkey_salt_hash.to_u32_vec(),
            self.amount.to_u32_vec(),
            vec![self.token_index, self.is_eligible as u32],
        ]
        .concat();
        vec
    }

    pub fn rand<R: Rng>(rng: &mut R) -> Self {
        Self {
            depositor: Address::rand(rng),
            pubkey_salt_hash: Bytes32::rand(rng),
            amount: U256::rand(rng),
            token_index: rng.gen(),
            is_eligible: true,
        }
    }

    pub fn poseidon_hash(&self) -> PoseidonHashOut {
        PoseidonHashOut::hash_inputs_u32(&self.to_u32_vec())
    }
}

impl DepositTarget {
    pub fn to_vec(&self) -> Vec<Target> {
        let vec = vec![
            self.depositor.to_vec(),
            self.pubkey_salt_hash.to_vec(),
            self.amount.to_vec(),
            vec![self.token_index, self.is_eligible.target],
        ]
        .concat();
        vec
    }

    pub fn new<F: RichField + Extendable<D>, const D: usize>(
        builder: &mut CircuitBuilder<F, D>,
        is_checked: bool,
    ) -> Self {
        let depositor = AddressTarget::new(builder, is_checked);
        let pubkey_salt_hash = Bytes32Target::new(builder, is_checked);
        let amount = U256Target::new(builder, is_checked);
        let token_index = builder.add_virtual_target();
        if is_checked {
            builder.range_check(token_index, 32);
        }
        let is_eligible = builder.add_virtual_bool_target_safe();
        Self {
            depositor,
            pubkey_salt_hash,
            amount,
            token_index,
            is_eligible,
        }
    }

    pub fn constant<F: RichField + Extendable<D>, const D: usize>(
        builder: &mut CircuitBuilder<F, D>,
        value: &Deposit,
    ) -> Self {
        let depositor = AddressTarget::constant(builder, value.depositor);
        let pubkey_salt_hash = Bytes32Target::constant(builder, value.pubkey_salt_hash);
        let amount = U256Target::constant(builder, value.amount);
        let token_index = builder.constant(F::from_canonical_u32(value.token_index));
        let is_eligible = builder.constant_bool(value.is_eligible);
        Self {
            depositor,
            pubkey_salt_hash,
            amount,
            token_index,
            is_eligible,
        }
    }

    pub fn poseidon_hash<F: RichField + Extendable<D>, const D: usize>(
        &self,
        builder: &mut CircuitBuilder<F, D>,
    ) -> PoseidonHashOutTarget {
        PoseidonHashOutTarget::hash_inputs(builder, &self.to_vec())
    }

    pub fn set_witness<F: Field, W: WitnessWrite<F>>(&self, witness: &mut W, value: &Deposit) {
        self.depositor.set_witness(witness, value.depositor);
        self.pubkey_salt_hash
            .set_witness(witness, value.pubkey_salt_hash);
        self.amount.set_witness(witness, value.amount);
        witness.set_target(self.token_index, F::from_canonical_u32(value.token_index));
        witness.set_bool_target(self.is_eligible, value.is_eligible);
    }
}

impl Leafable for Deposit {
    type LeafableHasher = KeccakLeafableHasher;

    fn empty_leaf() -> Self {
        Self::default()
    }

    fn hash(&self) -> Bytes32 {
        Bytes32::from_u32_slice(&solidity_keccak256(&self.to_u32_vec()))
    }
}

impl LeafableTarget for DepositTarget {
    type Leaf = Deposit;

    fn empty_leaf<F: RichField + Extendable<D>, const D: usize>(
        builder: &mut CircuitBuilder<F, D>,
    ) -> Self {
        Self::constant(builder, &Deposit::default())
    }

    fn hash<F: RichField + Extendable<D>, C: GenericConfig<D, F = F> + 'static, const D: usize>(
        &self,
        builder: &mut CircuitBuilder<F, D>,
    ) -> Bytes32Target
    where
        <C as GenericConfig<D>>::Hasher: AlgebraicHasher<F>,
    {
        let limbs = self.to_vec();
        Bytes32Target::from_slice(&builder.keccak256::<C>(&limbs))
    }
}

pub fn get_pubkey_salt_hash(pubkey: U256, salt: Salt) -> Bytes32 {
    let input = vec![pubkey.to_u64_vec(), salt.to_u64_vec()].concat();
    let hash = PoseidonHashOut::hash_inputs_u64(&input);
    hash.into()
}

pub fn get_pubkey_salt_hash_circuit<F: RichField + Extendable<D>, const D: usize>(
    builder: &mut CircuitBuilder<F, D>,
    pubkey: U256Target,
    salt: SaltTarget,
) -> Bytes32Target {
    let inputs = vec![pubkey.to_vec(), salt.to_vec()].concat();
    let hash = PoseidonHashOutTarget::hash_inputs(builder, &inputs);
    Bytes32Target::from_hash_out(builder, hash)
}
