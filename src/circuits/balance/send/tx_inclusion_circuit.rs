use plonky2::{
    field::extension::Extendable,
    hash::hash_types::RichField,
    iop::target::{BoolTarget, Target},
    plonk::{config::GenericConfig, proof::ProofWithPublicInputs},
};

use crate::{
    common::{
        public_state::{PublicState, PublicStateTarget},
        trees::block_hash_tree::BlockHashMerkleProof,
        tx::{Tx, TxTarget},
    },
    ethereum_types::u256::U256,
};

#[derive(Clone, Debug)]
pub struct TxInclusionPublicInputs {
    pub prev_public_state: PublicState,
    pub new_public_state: PublicState,
    pub pubkey: U256<u32>,
    pub tx: Tx,
    pub is_valid: bool,
}

#[derive(Clone, Debug)]
pub struct TxInclusionPublicInputsTarget {
    pub prev_public_state: PublicStateTarget,
    pub new_public_state: PublicStateTarget,
    pub pubkey: U256<Target>,
    pub tx: TxTarget,
    pub is_valid: BoolTarget,
}

// pub struct TxInclusionValue<
//     F: RichField + Extendable<D>,
//     C: GenericConfig<D, F = F>,
//     const D: usize,
// > {
//     pub prev_public_state: PublicState,
//     pub new_public_state: PublicState,
//     pub validity_proof: ProofWithPublicInputs<F, C, D>,
//     pub block_merkle_proof: BlockHashMerkleProof,
//     pub tx_merkle_proof: 
// }
