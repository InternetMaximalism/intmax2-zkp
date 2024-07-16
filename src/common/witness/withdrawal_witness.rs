use plonky2::{
    field::extension::Extendable,
    hash::hash_types::RichField,
    plonk::{config::GenericConfig, proof::ProofWithPublicInputs},
};

use super::transfer_witness::TransferWitness;
use crate::{
    circuits::balance::balance_pis::BalancePublicInputs,
    common::withdrawal::{get_withdrawal_nullifier, Withdrawal},
    ethereum_types::bytes32::Bytes32,
    utils::leafable::Leafable,
};

#[derive(Debug, Clone)]
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
    pub fn to_withdrawal(&self, prev_withdrawal_hash: Bytes32) -> Withdrawal {
        let balance_pis = BalancePublicInputs::from_pis(&self.balance_proof.public_inputs);
        assert_eq!(
            balance_pis.last_tx_hash,
            self.transfer_witness.tx.hash(),
            "last tx hash mismatch"
        );
        #[cfg(not(feature = "skip_insufficient_check"))]
        assert!(
            !balance_pis
                .last_tx_insufficient_flags
                .random_access(self.transfer_witness.transfer_index),
            "insufficient flag is true"
        );
        let transfer = self.transfer_witness.transfer.clone();
        let nullifier = get_withdrawal_nullifier(&transfer);
        let recipient = transfer
            .recipient
            .to_address()
            .expect("recipient is not an eth address");
        Withdrawal {
            prev_withdrawal_hash,
            recipient,
            token_index: transfer.token_index,
            amount: transfer.amount,
            nullifier,
            block_hash: balance_pis.public_state.block_hash,
        }
    }
}
