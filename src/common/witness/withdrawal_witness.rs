use plonky2::{
    field::extension::Extendable,
    hash::hash_types::RichField,
    plonk::{
        circuit_data::VerifierCircuitData,
        config::{AlgebraicHasher, GenericConfig},
        proof::ProofWithPublicInputs,
    },
};
use serde::{Deserialize, Serialize};

use super::transfer_witness::TransferWitness;
use crate::{
    circuits::balance::{
        balance_pis::BalancePublicInputs,
        receive::receive_targets::transfer_inclusion::TransferInclusionValue,
    },
    common::{
        error::CommonError,
        withdrawal::{get_withdrawal_nullifier, Withdrawal},
    },
    utils::leafable::Leafable,
};

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
#[serde(bound = "")]
pub struct WithdrawalWitness<F, C, const D: usize>
where
    F: RichField + Extendable<D>,
    C: GenericConfig<D, F = F>,
{
    pub transfer_witness: TransferWitness,
    pub balance_proof: ProofWithPublicInputs<F, C, D>,
}

impl<F, C, const D: usize> WithdrawalWitness<F, C, D>
where
    F: RichField + Extendable<D>,
    C: GenericConfig<D, F = F>,
{
    pub fn to_withdrawal(&self) -> Result<Withdrawal, CommonError> {
        let balance_pis = BalancePublicInputs::from_pis(&self.balance_proof.public_inputs)
            .map_err(|e| CommonError::InvalidData(format!("Failed to parse balance public inputs: {}", e)))?;
            
        if balance_pis.last_tx_hash != self.transfer_witness.tx.hash() {
            return Err(CommonError::InvalidData(
                "last tx hash mismatch".to_string()
            ));
        }
        
        #[cfg(not(feature = "skip_insufficient_check"))]
        if balance_pis
            .last_tx_insufficient_flags
            .random_access(self.transfer_witness.transfer_index as usize)
        {
            return Err(CommonError::InvalidData(
                "insufficient flag is true".to_string()
            ));
        }
        
        let transfer = self.transfer_witness.transfer;
        let nullifier = get_withdrawal_nullifier(&transfer);
        let recipient = transfer.recipient.to_address()?;
            
        Ok(Withdrawal {
            recipient,
            token_index: transfer.token_index,
            amount: transfer.amount,
            nullifier,
            block_hash: balance_pis.public_state.block_hash,
            block_number: balance_pis.public_state.block_number,
        })
    }

    pub fn to_transition_inclusion_value(
        &self,
        balance_verifier_data: &VerifierCircuitData<F, C, D>,
    ) -> Result<TransferInclusionValue<F, C, D>, CommonError>
    where
        <C as GenericConfig<D>>::Hasher: AlgebraicHasher<F>,
    {
        let transfer_witness = &self.transfer_witness;
        let transition_inclusion_value = TransferInclusionValue::new(
            balance_verifier_data,
            &transfer_witness.transfer,
            transfer_witness.transfer_index,
            &transfer_witness.transfer_merkle_proof,
            &transfer_witness.tx,
            &self.balance_proof,
        )
        .map_err(|e| CommonError::TransferInclusionValueCreationFailed(e.to_string()))?;
        Ok(transition_inclusion_value)
    }
}
