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
        address::{Address, AddressTarget},
        bytes32::{Bytes32, Bytes32Target},
        u256::{U256Target, U256},
        u32limb_trait::{U32LimbTargetTrait as _, U32LimbTrait},
    },
    utils::poseidon_hash_out::{PoseidonHashOut, PoseidonHashOutTarget},
};

use super::transfer::{Transfer, TransferTarget};

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Withdrawal {
    pub prev_withdrawal_hash: Bytes32,
    pub recipient: Address,
    pub token_index: u32,
    pub amount: U256,
    pub nullifier: Bytes32,
    pub block_hash: Bytes32,
}

pub struct WithdrawalTarget {
    pub prev_withdral_hash: Bytes32Target,
    pub recipient: AddressTarget,
    pub token_index: Target,
    pub amount: U256Target,
    pub nullifier: Bytes32Target,
    pub block_hash: Bytes32Target,
}

impl Withdrawal {
    pub fn to_u32_vec(&self) -> Vec<u32> {
        [
            self.prev_withdrawal_hash.limbs(),
            self.recipient.limbs(),
            vec![self.token_index],
            self.amount.limbs(),
            self.nullifier.limbs(),
            self.block_hash.limbs(),
        ]
        .concat()
    }

    pub fn hash(&self) -> Bytes32 {
        Bytes32::from_limbs(&solidity_keccak256(&self.to_u32_vec()))
    }
}

impl WithdrawalTarget {
    pub fn to_vec(&self) -> Vec<Target> {
        [
            self.prev_withdral_hash.limbs(),
            self.recipient.limbs(),
            vec![self.token_index],
            self.amount.limbs(),
            self.nullifier.limbs(),
            self.block_hash.limbs(),
        ]
        .concat()
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
        Bytes32Target::from_limbs(&builder.keccak256::<C>(&self.to_vec()))
    }
}

pub fn get_withdrawal_nullifier(transfer: &Transfer) -> Bytes32 {
    let transfer_commitment = transfer.commitment();
    let input = [transfer_commitment.to_u64_vec(), transfer.salt.to_u64_vec()].concat();
    let input_hash = PoseidonHashOut::hash_inputs_u64(&input);
    let nullifier: Bytes32 = input_hash.into();
    nullifier
}

pub fn get_withdrawal_nullifier_circuit<F: RichField + Extendable<D>, const D: usize>(
    builder: &mut CircuitBuilder<F, D>,
    transfer: &TransferTarget,
) -> Bytes32Target {
    let transfer_commitment = transfer.commitment(builder);
    let input = [transfer_commitment.to_vec(), transfer.salt.to_vec()].concat();
    let input_hash = PoseidonHashOutTarget::hash_inputs(builder, &input);
    let nullifier = Bytes32Target::from_hash_out(builder, input_hash);
    nullifier
}
