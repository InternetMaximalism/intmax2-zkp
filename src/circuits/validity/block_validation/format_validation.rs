use plonky2::{
    field::extension::Extendable,
    hash::hash_types::RichField,
    iop::{
        target::{BoolTarget, Target},
        witness::{PartialWitness, Witness},
    },
    plonk::{
        circuit_builder::CircuitBuilder,
        circuit_data::{CircuitConfig, CircuitData},
        config::{AlgebraicHasher, GenericConfig},
        proof::ProofWithPublicInputs,
    },
};

use crate::{
    circuits::validity::block_validation::utils::get_pubkey_commitment_circuit,
    common::signature::{SignatureContent, SignatureContentTarget},
    constants::NUM_SENDERS_IN_BLOCK,
    ethereum_types::{u256::U256, u32limb_trait::U32LimbTargetTrait},
    utils::{
        poseidon_hash_out::{PoseidonHashOut, PoseidonHashOutTarget},
        recursivable::Recursivable,
    },
};

use super::utils::get_pubkey_commitment;

pub const FORMAT_VALIDATION_PUBLIC_INPUTS_LEN: usize = 4 + 4 + 1;

#[derive(Clone, Debug)]
pub struct FormatValidationPublicInputs {
    pub pubkey_commitment: PoseidonHashOut,
    pub signature_commitment: PoseidonHashOut,
    pub is_valid: bool,
}

#[derive(Clone, Debug)]
pub struct FormatValidationPublicInputsTarget {
    pub pubkey_commitment: PoseidonHashOutTarget,
    pub signature_commitment: PoseidonHashOutTarget,
    pub is_valid: BoolTarget,
}

impl FormatValidationPublicInputs {
    pub fn from_u64_vec(input: &[u64]) -> Self {
        assert_eq!(input.len(), FORMAT_VALIDATION_PUBLIC_INPUTS_LEN);
        let pubkey_commitment = PoseidonHashOut::from_u64_vec(&input[0..4]);
        let signature_commitment = PoseidonHashOut::from_u64_vec(&input[4..8]);
        let is_valid = input[8] == 1;
        Self {
            pubkey_commitment,
            signature_commitment,
            is_valid,
        }
    }
}

impl FormatValidationPublicInputsTarget {
    pub fn to_vec(&self) -> Vec<Target> {
        let vec = self
            .pubkey_commitment
            .elements
            .into_iter()
            .chain(self.signature_commitment.elements.into_iter())
            .chain([self.is_valid.target])
            .collect::<Vec<_>>();
        assert_eq!(vec.len(), FORMAT_VALIDATION_PUBLIC_INPUTS_LEN);
        vec
    }

    pub fn from_vec(input: &[Target]) -> Self {
        assert_eq!(input.len(), FORMAT_VALIDATION_PUBLIC_INPUTS_LEN);
        let pubkey_commitment = PoseidonHashOutTarget {
            elements: input[0..4].try_into().unwrap(),
        };
        let signature_commitment = PoseidonHashOutTarget {
            elements: input[4..8].try_into().unwrap(),
        };
        let is_valid = BoolTarget::new_unsafe(input[8]);
        Self {
            pubkey_commitment,
            signature_commitment,
            is_valid,
        }
    }
}

pub struct FormatValidationValue {
    pub pubkeys: Vec<U256<u32>>,
    pub signature: SignatureContent,
    pub pubkey_commitment: PoseidonHashOut,
    pub signature_commitment: PoseidonHashOut,
    pub is_valid: bool,
}

pub struct FormatValidationTarget {
    pub pubkeys: Vec<U256<Target>>,
    pub signature: SignatureContentTarget,
    pub pubkey_commitment: PoseidonHashOutTarget,
    pub signature_commitment: PoseidonHashOutTarget,
    pub is_valid: BoolTarget,
}

impl FormatValidationValue {
    pub fn new(pubkeys: Vec<U256<u32>>, signature: SignatureContent) -> Self {
        let pubkey_commitment = get_pubkey_commitment(&pubkeys);
        let signature_commitment = signature.commitment();
        let is_valid = signature.is_valid_format(&pubkeys).is_ok();
        Self {
            pubkeys,
            signature,
            pubkey_commitment,
            signature_commitment,
            is_valid,
        }
    }
}

impl FormatValidationTarget {
    pub fn new<F: RichField + Extendable<D>, C: GenericConfig<D, F = F> + 'static, const D: usize>(
        builder: &mut CircuitBuilder<F, D>,
    ) -> Self
    where
        <C as GenericConfig<D>>::Hasher: AlgebraicHasher<F>,
    {
        let pubkeys = (0..NUM_SENDERS_IN_BLOCK)
            .map(|_| U256::<Target>::new(builder, true))
            .collect::<Vec<_>>();
        let pubkey_commitment = get_pubkey_commitment_circuit(builder, &pubkeys);
        let signature = SignatureContentTarget::new(builder, true);
        let signature_commitment = signature.commitment(builder);
        let is_valid = signature.is_valid_format::<F, C, D>(builder, &pubkeys);
        Self {
            pubkeys,
            signature,
            pubkey_commitment,
            signature_commitment,
            is_valid,
        }
    }

    pub fn set_witness<F: RichField, W: Witness<F>>(
        &self,
        witness: &mut W,
        value: &FormatValidationValue,
    ) {
        for (pubkey_t, pubkey) in self.pubkeys.iter().zip(value.pubkeys.iter()) {
            pubkey_t.set_witness(witness, *pubkey);
        }
        self.signature.set_witness(witness, &value.signature);
        self.pubkey_commitment
            .set_witness(witness, value.pubkey_commitment);
        self.signature_commitment
            .set_witness(witness, value.signature_commitment);
        witness.set_bool_target(self.is_valid, value.is_valid);
    }
}

pub struct FormatValidationCircuit<F, C, const D: usize>
where
    F: RichField + Extendable<D>,
    C: GenericConfig<D, F = F>,
{
    pub data: CircuitData<F, C, D>,
    pub target: FormatValidationTarget,
}

impl<F, C, const D: usize> FormatValidationCircuit<F, C, D>
where
    F: RichField + Extendable<D>,
    C: GenericConfig<D, F = F> + 'static,
{
    pub fn new() -> Self
    where
        <C as GenericConfig<D>>::Hasher: AlgebraicHasher<F>,
    {
        let mut builder = CircuitBuilder::<F, D>::new(CircuitConfig::default());
        let target = FormatValidationTarget::new::<F, C, D>(&mut builder);
        let pis = FormatValidationPublicInputsTarget {
            signature_commitment: target.signature_commitment,
            pubkey_commitment: target.pubkey_commitment,
            is_valid: target.is_valid,
        };
        builder.register_public_inputs(&pis.to_vec());
        let data = builder.build();
        Self { data, target }
    }

    pub fn prove(
        &self,
        value: &FormatValidationValue,
    ) -> anyhow::Result<ProofWithPublicInputs<F, C, D>> {
        let mut pw = PartialWitness::<F>::new();
        self.target.set_witness(&mut pw, value);
        self.data.prove(pw)
    }
}

impl<F, C, const D: usize> Recursivable<F, C, D> for FormatValidationCircuit<F, C, D>
where
    F: RichField + Extendable<D>,
    C: GenericConfig<D, F = F> + 'static,
    C::Hasher: AlgebraicHasher<F>,
{
    fn circuit_data(&self) -> &CircuitData<F, C, D> {
        &self.data
    }
}
