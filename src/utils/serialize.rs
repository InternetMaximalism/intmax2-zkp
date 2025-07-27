use crate::utils::error::{Result, SerializeError};
use plonky2::{
    field::extension::Extendable,
    gates::{
        arithmetic_base::ArithmeticGate, arithmetic_extension::ArithmeticExtensionGate,
        base_sum::BaseSumGate, constant::ConstantGate, coset_interpolation::CosetInterpolationGate,
        exponentiation::ExponentiationGate, lookup::LookupGate, lookup_table::LookupTableGate,
        multiplication_extension::MulExtensionGate, noop::NoopGate, poseidon::PoseidonGate,
        poseidon_mds::PoseidonMdsGate, public_input::PublicInputGate,
        random_access::RandomAccessGate, reducing::ReducingGate,
        reducing_extension::ReducingExtensionGate,
    },
    get_gate_tag_impl,
    hash::hash_types::RichField,
    impl_gate_serializer,
    plonk::{circuit_data::VerifierCircuitData, config::GenericConfig},
    read_gate_impl,
    util::serialization::GateSerializer,
};
use plonky2_u32::gates::{
    add_many_u32::U32AddManyGate, comparison::ComparisonGate, subtraction_u32::U32SubtractionGate,
};

#[derive(Debug)]
pub struct AllGateSerializer;
impl<F: RichField + Extendable<D>, const D: usize> GateSerializer<F, D> for AllGateSerializer {
    impl_gate_serializer! {
        DefaultGateSerializer,
        ArithmeticGate,
        ArithmeticExtensionGate<D>,
        BaseSumGate<2>,
        ConstantGate,
        CosetInterpolationGate<F, D>,
        ExponentiationGate<F, D>,
        LookupGate,
        LookupTableGate,
        MulExtensionGate<D>,
        NoopGate,
        PoseidonMdsGate<F, D>,
        PoseidonGate<F, D>,
        PublicInputGate,
        RandomAccessGate<F, D>,
        ReducingExtensionGate<D>,
        ReducingGate<D>,
        ComparisonGate<F, D>,
        U32AddManyGate<F, D>,
        U32SubtractionGate<F, D>
    }
}

pub fn serialize_verifier_data<F, C, const D: usize>(
    circuit_data: &VerifierCircuitData<F, C, D>,
) -> Result<Vec<u8>>
where
    F: RichField + Extendable<D>,
    C: GenericConfig<D, F = F>,
{
    let gate_serializer = AllGateSerializer;
    let bytes = circuit_data
        .to_bytes(&gate_serializer)
        .map_err(|e| SerializeError::SerializationFailed(e.to_string()))?;
    Ok(bytes)
}

pub fn deserialize_verifier_data<F, C, const D: usize>(
    bytes: &[u8],
) -> Result<VerifierCircuitData<F, C, D>>
where
    F: RichField + Extendable<D>,
    C: GenericConfig<D, F = F>,
{
    let gate_serializer = AllGateSerializer;
    let circuit_data = VerifierCircuitData::from_bytes(bytes.to_vec(), &gate_serializer)
        .map_err(|e| SerializeError::DeserializationFailed(e.to_string()))?;
    Ok(circuit_data)
}

#[cfg(test)]
mod tests {
    use plonky2::{
        field::goldilocks_field::GoldilocksField,
        plonk::{circuit_data::VerifierCircuitData, config::PoseidonGoldilocksConfig},
    };

    use crate::{
        circuits::{
            balance::{balance_processor::BalanceProcessor, send::spent_circuit::SpentCircuit},
            claim::{
                determine_lock_time::LockTimeConfig, single_claim_processor::SingleClaimProcessor,
            },
            validity::validity_processor::ValidityProcessor,
            withdrawal::single_withdrawal_circuit::SingleWithdrawalCircuit,
        },
        utils::serialize::{deserialize_verifier_data, serialize_verifier_data},
    };

    type F = GoldilocksField;
    type C = PoseidonGoldilocksConfig;
    const D: usize = 2;

    fn serialize_and_deserialize_test(verifier_data: &VerifierCircuitData<F, C, D>) {
        let serialized_data = serialize_verifier_data(verifier_data).unwrap();
        let deserialized_data = deserialize_verifier_data::<F, C, D>(&serialized_data).unwrap();
        assert_eq!(verifier_data, &deserialized_data);
    }

    #[test]
    fn test_spent_circuit_serialize() {
        let spent_circuit = SpentCircuit::<F, C, D>::new();
        let verifier_data = spent_circuit.data.verifier_data();
        serialize_and_deserialize_test(&verifier_data);
    }

    // #[test]
    // fn test_validity_transition_circuit() {
    //     let validity_processor = ValidityProcessor::<F, C, D>::new();
    //     let verifier_data = validity_processor
    //         .transition_processor
    //         .transition_wrapper_circuit
    //         .data
    //         .verifier_data();
    //     serialize_and_deserialize_test(&verifier_data);
    // }

    #[test]
    fn test_validity_circuit_serialize() {
        let validity_processor = ValidityProcessor::<F, C, D>::new();
        let verifier_data = validity_processor.get_verifier_data();
        serialize_and_deserialize_test(&verifier_data);
    }

    #[test]
    fn test_balance_circuit_serialize() {
        let validity_processor = ValidityProcessor::<F, C, D>::new();
        let balance_processor = BalanceProcessor::new(&validity_processor.get_verifier_data());
        let verifier_data = balance_processor.get_verifier_data();
        serialize_and_deserialize_test(&verifier_data);
    }

    #[test]
    fn test_single_withdrawal_circuit_serialize() {
        let validity_processor = ValidityProcessor::<F, C, D>::new();
        let balance_processor = BalanceProcessor::new(&validity_processor.get_verifier_data());
        let single_withdrawal_circuit =
            SingleWithdrawalCircuit::new(&balance_processor.get_verifier_data());
        let verifier_data = single_withdrawal_circuit.data.verifier_data();
        serialize_and_deserialize_test(&verifier_data);
    }

    #[test]
    fn test_single_claim_circuit_serialize() {
        let validity_processor = ValidityProcessor::<F, C, D>::new();
        let single_claim_processor = SingleClaimProcessor::new(
            &validity_processor.get_verifier_data(),
            &LockTimeConfig::normal(),
        );
        let verifier_data = single_claim_processor.get_verifier_data();
        serialize_and_deserialize_test(&verifier_data);
    }
}
