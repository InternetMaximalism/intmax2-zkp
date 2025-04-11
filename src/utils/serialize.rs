use plonky2::{
    field::extension::Extendable,
    hash::hash_types::RichField,
    plonk::{
        circuit_data::CircuitData,
        config::{AlgebraicHasher, GenericConfig},
    },
    util::serialization::{DefaultGateSerializer, DefaultGeneratorSerializer},
};

use crate::utils::error::{Result, SerializeError};

pub fn serialize_circuit<F, C, const D: usize>(
    circuit_data: &CircuitData<F, C, D>,
) -> Result<Vec<u8>>
where
    F: RichField + Extendable<D>,
    C: GenericConfig<D, F = F> + Default + 'static,
    <C as GenericConfig<D>>::Hasher: AlgebraicHasher<F>,
{
    let gate_serializer = DefaultGateSerializer;
    let generator_serializer = DefaultGeneratorSerializer::<C, D>::default();
    let bytes = circuit_data
        .to_bytes(&gate_serializer, &generator_serializer)
        .map_err(|e| {
            SerializeError::SerializationFailed(format!("failed to serialize circuit {}", e))
        })?;
    Ok(bytes)
}

pub fn deserialize_circuit<F, C, const D: usize>(
    bytes: &[u8],
) -> Result<CircuitData<F, C, D>>
where
    F: RichField + Extendable<D>,
    C: GenericConfig<D, F = F> + Default + 'static,
    <C as GenericConfig<D>>::Hasher: AlgebraicHasher<F>,
{
    let gate_serializer = DefaultGateSerializer;
    let generator_serializer = DefaultGeneratorSerializer::<C, D>::default();
    let circuit_data = CircuitData::from_bytes(bytes, &gate_serializer, &generator_serializer)
        .map_err(|e| {
            SerializeError::DeserializationFailed(format!("failed to deserialize circuit {}", e))
        })?;
    Ok(circuit_data)
}
