use plonky2::{
    field::{extension::Extendable, types::Field},
    hash::hash_types::RichField,
    iop::{target::Target, witness::WitnessWrite},
    plonk::{
        circuit_builder::CircuitBuilder,
        config::{AlgebraicHasher, GenericConfig},
    },
    util::serialization::{Buffer, IoResult, Read, Write},
};
use plonky2_keccak::{builder::BuilderKeccak256 as _, utils::solidity_keccak256};
use rand::Rng;
use serde::{Deserialize, Serialize};

use crate::{
    ethereum_types::{
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
    pub pubkey_salt_hash: Bytes32, // The poseidon hash of the pubkey and salt, to hide the pubkey
    pub token_index: u32,          // The index of the token
    pub amount: U256,              // The amount of the token, which is the amount of the deposit
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DepositTarget {
    pub pubkey_salt_hash: Bytes32Target,
    pub token_index: Target,
    pub amount: U256Target,
}

impl Deposit {
    pub fn to_u32_vec(&self) -> Vec<u32> {
        let vec = vec![
            self.pubkey_salt_hash.to_u32_vec(),
            vec![self.token_index],
            self.amount.to_u32_vec(),
        ]
        .concat();
        vec
    }

    pub fn rand<R: Rng>(rng: &mut R) -> Self {
        Self {
            pubkey_salt_hash: Bytes32::rand(rng),
            token_index: rng.gen(),
            amount: U256::rand(rng),
        }
    }

    pub fn poseidon_hash(&self) -> PoseidonHashOut {
        PoseidonHashOut::hash_inputs_u32(&self.to_u32_vec())
    }
}

impl DepositTarget {
    pub fn to_vec(&self) -> Vec<Target> {
        let vec = vec![
            self.pubkey_salt_hash.to_vec(),
            vec![self.token_index],
            self.amount.to_vec(),
        ]
        .concat();
        vec
    }

    pub fn new<F: RichField + Extendable<D>, const D: usize>(
        builder: &mut CircuitBuilder<F, D>,
        is_checked: bool,
    ) -> Self {
        let pubkey_salt_hash = Bytes32Target::new(builder, is_checked);
        let token_index = builder.add_virtual_target();
        let amount = U256Target::new(builder, is_checked);
        Self {
            pubkey_salt_hash,
            token_index,
            amount,
        }
    }

    pub fn constant<F: RichField + Extendable<D>, const D: usize>(
        builder: &mut CircuitBuilder<F, D>,
        value: &Deposit,
    ) -> Self {
        let pubkey_salt_hash = Bytes32Target::constant(builder, value.pubkey_salt_hash);
        let token_index = builder.constant(F::from_canonical_u32(value.token_index));
        let amount = U256Target::constant(builder, value.amount);
        Self {
            pubkey_salt_hash,
            token_index,
            amount,
        }
    }

    pub fn poseidon_hash<F: RichField + Extendable<D>, const D: usize>(
        &self,
        builder: &mut CircuitBuilder<F, D>,
    ) -> PoseidonHashOutTarget {
        PoseidonHashOutTarget::hash_inputs(builder, &self.to_vec())
    }

    pub fn set_witness<F: Field, W: WitnessWrite<F>>(&self, witness: &mut W, value: &Deposit) {
        self.pubkey_salt_hash
            .set_witness(witness, value.pubkey_salt_hash);
        witness.set_target(self.token_index, F::from_canonical_u32(value.token_index));
        self.amount.set_witness(witness, value.amount);
    }

    pub fn to_buffer(&self, buffer: &mut Vec<u8>) -> IoResult<()> {
        self.pubkey_salt_hash.to_buffer(buffer)?;
        buffer.write_target(self.token_index)?;
        self.amount.to_buffer(buffer)
    }

    pub fn from_buffer(buffer: &mut Buffer) -> IoResult<Self> {
        let pubkey_salt_hash = Bytes32Target::from_buffer(buffer)?;
        let token_index = buffer.read_target()?;
        let amount = U256Target::from_buffer(buffer)?;
        Ok(Self {
            pubkey_salt_hash,
            token_index,
            amount,
        })
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
