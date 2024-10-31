use serde::{Deserialize, Serialize};

use crate::common::witness::{
    block_witness::BlockWitness, validity_transition_witness::ValidityTransitionWitness,
    validity_witness::ValidityWitness,
};

use super::{
    compressed_block_witness::CompressedBlockWitness,
    compressed_transition_witness::CompressedValidityTransitionWitness,
};

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CompressedValidityWitness {
    pub block_witness: CompressedBlockWitness,
    pub validity_transition_witness: CompressedValidityTransitionWitness,
}

impl ValidityWitness {
    pub fn compress(&self, max_account_id: usize) -> CompressedValidityWitness {
        CompressedValidityWitness {
            block_witness: self.block_witness.compress(max_account_id),
            validity_transition_witness: self.validity_transition_witness.compress(max_account_id),
        }
    }

    pub fn decompress(compressed: &CompressedValidityWitness) -> Self {
        Self {
            block_witness: BlockWitness::decompress(&compressed.block_witness),
            validity_transition_witness: ValidityTransitionWitness::decompress(
                &compressed.validity_transition_witness,
            ),
        }
    }
}
