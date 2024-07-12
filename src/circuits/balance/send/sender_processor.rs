use plonky2::{
    field::extension::Extendable,
    hash::hash_types::RichField,
    plonk::config::{AlgebraicHasher, GenericConfig},
};

use crate::circuits::validity::validity_circuit::ValidityCircuit;

use super::{
    sender_circuit::SenderCircuit, spent_circuit::SpentCircuit,
    tx_inclusion_circuit::TxInclusionCircuit,
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

    pub fn prove(&self) {}
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
