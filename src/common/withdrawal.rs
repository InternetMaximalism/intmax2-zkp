use plonky2::{
    field::extension::Extendable,
    hash::hash_types::RichField,
    iop::target::Target,
    plonk::{
        circuit_builder::CircuitBuilder,
        config::{AlgebraicHasher, GenericConfig},
    },
};
use plonky2_keccak::{builder::BuilderKeccak256, utils::solidity_keccak256};
use serde::{Deserialize, Serialize};

use crate::{
    ethereum_types::{
        address::{Address, AddressTarget, ADDRESS_LEN},
        bytes32::{Bytes32, Bytes32Target, BYTES32_LEN},
        u256::{U256Target, U256, U256_LEN},
        u32limb_trait::{U32LimbTargetTrait as _, U32LimbTrait},
    },
    utils::poseidon_hash_out::{PoseidonHashOut, PoseidonHashOutTarget},
};

use super::{
    block::Block,
    transfer::{Transfer, TransferTarget},
};

pub const WITHDRAWAL_LEN: usize = ADDRESS_LEN + 1 + U256_LEN + BYTES32_LEN + BYTES32_LEN + 1;

/// A withdrawal that is processed in the withdrawal contract.
#[derive(Default, Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Withdrawal {
    pub recipient: Address,  // The recipient of the withdrawal
    pub token_index: u32,    // The index of the token
    pub amount: U256,        // The amount of the token
    pub nullifier: Bytes32,  // The nullifier which is used to prevent double withdrawal
    pub block_hash: Bytes32, // The block hash of the balance proof that is used to withdraw
    pub block_number: u32,   // The block number of the balance proof that is used to withdraw
}

pub struct WithdrawalTarget {
    pub recipient: AddressTarget,
    pub token_index: Target,
    pub amount: U256Target,
    pub nullifier: Bytes32Target,
    pub block_hash: Bytes32Target,
    pub block_number: Target,
}

impl Withdrawal {
    pub fn to_u32_vec(&self) -> Vec<u32> {
        let result = [
            self.recipient.to_u32_vec(),
            vec![self.token_index],
            self.amount.to_u32_vec(),
            self.nullifier.to_u32_vec(),
            self.block_hash.to_u32_vec(),
            vec![self.block_number],
        ]
        .concat();
        assert_eq!(result.len(), WITHDRAWAL_LEN);
        result
    }

    pub fn from_u32_slice(slice: &[u32]) -> Self {
        assert_eq!(slice.len(), WITHDRAWAL_LEN);
        let recipient = Address::from_u32_slice(&slice[0..ADDRESS_LEN]).unwrap();
        let token_index = slice[ADDRESS_LEN];
        let amount =
            U256::from_u32_slice(&slice[ADDRESS_LEN + 1..ADDRESS_LEN + 1 + U256_LEN]).unwrap();
        let nullifier = Bytes32::from_u32_slice(
            &slice[ADDRESS_LEN + 1 + U256_LEN..ADDRESS_LEN + 1 + U256_LEN + BYTES32_LEN],
        )
        .unwrap();
        let block_hash = Bytes32::from_u32_slice(
            &slice[ADDRESS_LEN + 1 + U256_LEN + BYTES32_LEN
                ..ADDRESS_LEN + 1 + U256_LEN + BYTES32_LEN + BYTES32_LEN],
        )
        .unwrap();
        let block_number = slice[ADDRESS_LEN + 1 + U256_LEN + BYTES32_LEN + BYTES32_LEN];
        Self {
            recipient,
            token_index,
            amount,
            nullifier,
            block_hash,
            block_number,
        }
    }

    pub fn from_u64_slice(slice: &[u64]) -> Self {
        let u32_slice: Vec<u32> = slice
            .iter()
            .map(|&x| {
                assert!(x <= u32::MAX as u64);
                x as u32
            })
            .collect();
        Self::from_u32_slice(&u32_slice)
    }

    pub fn hash_with_prev_hash(&self, prev_withdrawal_hash: Bytes32) -> Bytes32 {
        let input = [prev_withdrawal_hash.to_u32_vec(), self.to_u32_vec()].concat();
        Bytes32::from_u32_slice(&solidity_keccak256(&input)).unwrap()
    }

    pub fn rand<R: rand::Rng>(rng: &mut R) -> Self {
        Self {
            recipient: Address::rand(rng),
            token_index: rng.gen(),
            amount: U256::rand_small(rng),
            nullifier: Bytes32::rand(rng),
            block_hash: Bytes32::rand(rng),
            block_number: rng.gen(),
        }
    }

    pub fn rand_with_block<R: rand::Rng>(rng: &mut R, block: &Block) -> Self {
        Self {
            recipient: Address::rand(rng),
            token_index: rng.gen(),
            amount: U256::rand_small(rng),
            nullifier: Bytes32::rand(rng),
            block_hash: block.hash(),
            block_number: block.block_number,
        }
    }
}

impl WithdrawalTarget {
    pub fn to_vec(&self) -> Vec<Target> {
        let result = [
            self.recipient.to_vec(),
            vec![self.token_index],
            self.amount.to_vec(),
            self.nullifier.to_vec(),
            self.block_hash.to_vec(),
            vec![self.block_number],
        ]
        .concat();
        assert_eq!(result.len(), WITHDRAWAL_LEN);
        result
    }

    pub fn from_slice(slice: &[Target]) -> Self {
        assert_eq!(slice.len(), WITHDRAWAL_LEN);
        let recipient = AddressTarget::from_slice(&slice[0..ADDRESS_LEN]);
        let token_index = slice[ADDRESS_LEN];
        let amount = U256Target::from_slice(&slice[ADDRESS_LEN + 1..ADDRESS_LEN + 1 + U256_LEN]);
        let nullifier = Bytes32Target::from_slice(
            &slice[ADDRESS_LEN + 1 + U256_LEN..ADDRESS_LEN + 1 + U256_LEN + BYTES32_LEN],
        );
        let block_hash = Bytes32Target::from_slice(
            &slice[ADDRESS_LEN + 1 + U256_LEN + BYTES32_LEN
                ..ADDRESS_LEN + 1 + U256_LEN + BYTES32_LEN + BYTES32_LEN],
        );
        let block_number = slice[ADDRESS_LEN + 1 + U256_LEN + BYTES32_LEN + BYTES32_LEN];
        Self {
            recipient,
            token_index,
            amount,
            nullifier,
            block_hash,
            block_number,
        }
    }

    pub fn hash_with_prev_hash<
        F: RichField + Extendable<D>,
        C: GenericConfig<D, F = F> + 'static,
        const D: usize,
    >(
        &self,
        builder: &mut CircuitBuilder<F, D>,
        prev_withdrawal_hash: Bytes32Target,
    ) -> Bytes32Target
    where
        <C as GenericConfig<D>>::Hasher: AlgebraicHasher<F>,
    {
        let input = [prev_withdrawal_hash.to_vec(), self.to_vec()].concat();
        Bytes32Target::from_slice(&builder.keccak256::<C>(&input))
    }
}

pub fn get_withdrawal_nullifier(transfer: &Transfer) -> Bytes32 {
    let transfer_commitment = transfer.poseidon_hash();
    let input = [transfer_commitment.to_u64_vec(), transfer.salt.to_u64_vec()].concat();
    let input_hash = PoseidonHashOut::hash_inputs_u64(&input);
    let nullifier: Bytes32 = input_hash.into();
    nullifier
}

pub fn get_withdrawal_nullifier_circuit<F: RichField + Extendable<D>, const D: usize>(
    builder: &mut CircuitBuilder<F, D>,
    transfer: &TransferTarget,
) -> Bytes32Target {
    let transfer_commitment = transfer.poseidon_hash(builder);
    let input = [transfer_commitment.to_vec(), transfer.salt.to_vec()].concat();
    let input_hash = PoseidonHashOutTarget::hash_inputs(builder, &input);

    Bytes32Target::from_hash_out(builder, input_hash)
}
