use plonky2::{
    field::extension::Extendable,
    hash::hash_types::RichField,
    plonk::{
        circuit_data::{CircuitConfig, VerifierOnlyCircuitData},
        config::{AlgebraicHasher, GenericConfig},
        proof::ProofWithPublicInputs,
    },
};

use crate::circuits::{
    balance::{
        balance_pis::BalancePublicInputs,
        receive::{
            receive_deposit_circuit::ReceiveDepositCircuit,
            receive_transfer_circuit::ReceiveTransferCircuit, update_circuit::UpdateCircuit,
        },
        send::sender_processor::SenderProcessor,
    },
    validity::validity_circuit::ValidityCircuit,
};

use super::transition_circuit::{
    BalanceTransitionCircuit, BalanceTransitionType, BalanceTransitionValue,
};

pub struct BalanceTransitionProcessor<F, C, const D: usize>
where
    F: RichField + Extendable<D>,
    C: GenericConfig<D, F = F>,
{
    pub receive_transfer_circuit: ReceiveTransferCircuit<F, C, D>,
    pub receive_deposit_circuit: ReceiveDepositCircuit<F, C, D>,
    pub update_circuit: UpdateCircuit<F, C, D>,
    pub sender_processor: SenderProcessor<F, C, D>,
    pub balance_transition_circuit: BalanceTransitionCircuit<F, C, D>,
}

impl<F, C, const D: usize> BalanceTransitionProcessor<F, C, D>
where
    F: RichField + Extendable<D>,
    C: GenericConfig<D, F = F> + 'static,
    <C as GenericConfig<D>>::Hasher: AlgebraicHasher<F>,
{
    pub fn new(validity_circuit: &ValidityCircuit<F, C, D>) -> Self {
        let receive_transfer_circuit = ReceiveTransferCircuit::new();
        let receive_deposit_circuit = ReceiveDepositCircuit::new();
        let update_circuit = UpdateCircuit::new(validity_circuit);
        let sender_processor = SenderProcessor::new(validity_circuit);
        let balance_transition_circuit = BalanceTransitionCircuit::new(
            &receive_transfer_circuit,
            &receive_deposit_circuit,
            &update_circuit,
            &sender_processor.sender_circuit,
        );
        Self {
            receive_transfer_circuit,
            receive_deposit_circuit,
            update_circuit,
            sender_processor,
            balance_transition_circuit,
        }
    }

    pub fn prove(&self) {}

    pub fn prove_dummy(
        &self,
        balance_circuit_vd: &VerifierOnlyCircuitData<C, D>,
        prev_balance_pis: &BalancePublicInputs,
    ) -> ProofWithPublicInputs<F, C, D> {
        let config = CircuitConfig::default();
        let balance_transition_value = BalanceTransitionValue::new(
            &config,
            BalanceTransitionType::Dummy,
            &self.receive_transfer_circuit,
            &self.receive_deposit_circuit,
            &self.update_circuit,
            &self.sender_processor.sender_circuit,
            None,
            None,
            None,
            None,
            prev_balance_pis.clone(),
            balance_circuit_vd.clone(),
        );
        self.balance_transition_circuit
            .prove(
                &self.receive_transfer_circuit,
                &self.receive_deposit_circuit,
                &self.update_circuit,
                &self.sender_processor.sender_circuit,
                &balance_transition_value,
            )
            .unwrap()
    }
}

#[cfg(test)]
mod tests {
    use plonky2::{
        field::goldilocks_field::GoldilocksField, plonk::config::PoseidonGoldilocksConfig,
    };

    use crate::{
        circuits::{
            balance::{balance_pis::BalancePublicInputs, balance_processor::BalanceProcessor},
            validity::validity_processor::ValdityProcessor,
        },
        ethereum_types::u256::U256,
    };

    type F = GoldilocksField;
    type C = PoseidonGoldilocksConfig;
    const D: usize = 2;

    #[test]
    fn balance_transition_processor_prove_dummy() {
        let validity_processor = ValdityProcessor::<F, C, D>::new();
        let balance_processor = BalanceProcessor::new(&validity_processor.validity_circuit);

        let pubkey = U256::<u32>::rand(&mut rand::thread_rng());
        let balance_pis = BalancePublicInputs::new(pubkey);
        let balance_circuit_vd = balance_processor.get_verifier_only_data();

        let _ = balance_processor
            .balance_transition_processor
            .prove_dummy(&balance_circuit_vd, &balance_pis);
    }
}
