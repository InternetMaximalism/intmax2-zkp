use plonky2::{
    field::extension::Extendable,
    hash::hash_types::RichField,
    plonk::{
        config::{AlgebraicHasher, GenericConfig},
        proof::ProofWithPublicInputs,
    },
};

use crate::{
    circuits::validity::validity_circuit::ValidityCircuit,
    common::witness::{
        send_witness::SendWitness, update_public_state_witness::UpdatePublicStateWitness,
    },
};

use super::{
    sender_circuit::{SenderCircuit, SenderValue},
    spent_circuit::{SpentCircuit, SpentValue},
    tx_inclusion_circuit::{TxInclusionCircuit, TxInclusionValue},
};

pub struct SenderProcessor<F, C, const D: usize>
where
    F: RichField + Extendable<D>,
    C: GenericConfig<D, F = F>,
{
    pub spent_circuit: SpentCircuit<F, C, D>,
    pub tx_inclusion_circuit: TxInclusionCircuit<F, C, D>,
    pub sender_circuit: SenderCircuit<F, C, D>,
}

impl<F, C, const D: usize> SenderProcessor<F, C, D>
where
    F: RichField + Extendable<D>,
    C: GenericConfig<D, F = F> + 'static,
    <C as GenericConfig<D>>::Hasher: AlgebraicHasher<F>,
{
    pub fn new(validity_circuit: &ValidityCircuit<F, C, D>) -> Self {
        let spent_circuit = SpentCircuit::new();
        let tx_inclusion_circuit = TxInclusionCircuit::new(validity_circuit);
        let sender_circuit = SenderCircuit::new(&spent_circuit, &tx_inclusion_circuit);
        Self {
            spent_circuit,
            tx_inclusion_circuit,
            sender_circuit,
        }
    }

    pub fn prove(
        &self,
        validity_circuit: &ValidityCircuit<F, C, D>,
        send_witness: &SendWitness,
        update_public_state_witness: &UpdatePublicStateWitness<F, C, D>,
    ) -> ProofWithPublicInputs<F, C, D> {
        let spent_value = SpentValue::new(
            &send_witness.prev_private_state,
            &send_witness.prev_balances,
            &send_witness.transfers,
            &send_witness.asset_merkle_proofs,
            send_witness.tx_witness.tx.nonce,
        );
        let tx_witness = &send_witness.tx_witness;
        let sender_tree = tx_witness.block_witness.get_sender_tree();
        let sender_leaf = sender_tree.get_leaf(tx_witness.tx_index);
        let sender_merkle_proof = sender_tree.prove(tx_witness.tx_index);

        let tx_inclusion_value = TxInclusionValue::new(
            validity_circuit,
            send_witness.prev_balance_pis.pubkey,
            &send_witness.prev_balance_pis.public_state,
            &update_public_state_witness.validity_proof,
            &update_public_state_witness.block_merkle_proof,
            tx_witness.tx_index,
            &tx_witness.tx,
            &tx_witness.tx_merkle_proof,
            &sender_leaf,
            &sender_merkle_proof,
        );

        let spent_proof = self.spent_circuit.prove(&spent_value).unwrap();
        let tx_inclusion_proof = self
            .tx_inclusion_circuit
            .prove(&tx_inclusion_value)
            .unwrap();
        let sender_value = SenderValue::new(
            &self.spent_circuit,
            &self.tx_inclusion_circuit,
            &spent_proof,
            &tx_inclusion_proof,
            &send_witness.prev_balance_pis,
        );
        self.sender_circuit.prove(&sender_value).unwrap()
    }
}

#[cfg(test)]
mod tests {
    use plonky2::{
        field::goldilocks_field::GoldilocksField, plonk::config::PoseidonGoldilocksConfig,
    };

    use crate::circuits::validity::validity_processor::ValidityProcessor;

    use super::SenderProcessor;

    type F = GoldilocksField;
    type C = PoseidonGoldilocksConfig;
    const D: usize = 2;

    #[test]
    fn sender_processor() {
        let validity_processor = ValidityProcessor::<F, C, D>::new();
        let _sender_processor = SenderProcessor::new(&validity_processor.validity_circuit);
    }
}
