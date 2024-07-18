use plonky2::{
    field::extension::Extendable,
    hash::hash_types::RichField,
    iop::{
        target::Target,
        witness::{PartialWitness, WitnessWrite as _},
    },
    plonk::{
        circuit_builder::CircuitBuilder,
        circuit_data::{CircuitConfig, CircuitData},
        config::{AlgebraicHasher, GenericConfig},
        proof::{ProofWithPublicInputs, ProofWithPublicInputsTarget},
    },
};
use plonky2_keccak::{builder::BuilderKeccak256 as _, utils::solidity_keccak256};
use serde::{Deserialize, Serialize};

use crate::{
    ethereum_types::{
        address::{Address, AddressTarget},
        bytes32::{Bytes32, Bytes32Target, BYTES32_LEN},
        u32limb_trait::{U32LimbTargetTrait as _, U32LimbTrait},
    },
    utils::recursivable::Recursivable,
};

use super::withdrawal_circuit::WithdrawalCircuit;

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct WithdrawalProofPublicInputs {
    pub last_withdrawal_hash: Bytes32,
    pub withdrawal_aggregator: Address,
}

impl WithdrawalProofPublicInputs {
    pub fn to_u32_vec(&self) -> Vec<u32> {
        [
            self.last_withdrawal_hash.limbs(),
            self.withdrawal_aggregator.limbs(),
        ]
        .concat()
    }

    pub fn hash(&self) -> Bytes32 {
        Bytes32::from_limbs(&solidity_keccak256(&self.to_u32_vec()))
    }
}

#[derive(Debug, Clone)]
struct WithdrawalProofPublicInputsTarget {
    last_withdrawal_hash: Bytes32Target,
    withdrawal_aggregator: AddressTarget,
}

impl WithdrawalProofPublicInputsTarget {
    fn to_vec(&self) -> Vec<Target> {
        [
            self.last_withdrawal_hash.limbs(),
            self.withdrawal_aggregator.limbs(),
        ]
        .concat()
    }

    fn hash<F: RichField + Extendable<D>, C: GenericConfig<D, F = F> + 'static, const D: usize>(
        &self,
        builder: &mut CircuitBuilder<F, D>,
    ) -> Bytes32Target
    where
        <C as GenericConfig<D>>::Hasher: AlgebraicHasher<F>,
    {
        Bytes32Target::from_limbs(&builder.keccak256::<C>(&self.to_vec()))
    }
}

#[derive(Debug)]
pub struct WithdrawalWrapperCircuit<F, C, const D: usize>
where
    F: RichField + Extendable<D>,
    C: GenericConfig<D, F = F>,
{
    data: CircuitData<F, C, D>,
    withdrawal_wrapper_proof: ProofWithPublicInputsTarget<D>,
    withdrawal_aggregator: AddressTarget, // Who makes the withdrawal proof and receive the reward
}

impl<F, C, const D: usize> WithdrawalWrapperCircuit<F, C, D>
where
    F: RichField + Extendable<D>,
    C: GenericConfig<D, F = F> + 'static,
    C::Hasher: AlgebraicHasher<F>,
{
    pub fn new(withdrawal_circuit: &WithdrawalCircuit<F, C, D>) -> Self {
        let mut builder = CircuitBuilder::<F, D>::new(CircuitConfig::default());
        let withdrawal_wrapper_proof = withdrawal_circuit.add_proof_target_and_verify(&mut builder);
        let last_withdrawal_hash =
            Bytes32Target::from_limbs(&withdrawal_wrapper_proof.public_inputs[0..BYTES32_LEN]);
        let withdrawal_aggregator = AddressTarget::new(&mut builder, true);
        let pis = WithdrawalProofPublicInputsTarget {
            last_withdrawal_hash,
            withdrawal_aggregator,
        };
        let pis_hash = pis.hash::<F, C, D>(&mut builder);
        builder.register_public_inputs(&pis_hash.to_vec());
        let data = builder.build();
        Self {
            data,
            withdrawal_wrapper_proof,
            withdrawal_aggregator,
        }
    }

    pub fn prove(
        &self,
        withdrawal_proof: &ProofWithPublicInputs<F, C, D>,
        withdrawal_aggregator: Address,
    ) -> anyhow::Result<ProofWithPublicInputs<F, C, D>> {
        let mut pw = PartialWitness::<F>::new();
        pw.set_proof_with_pis_target(&self.withdrawal_wrapper_proof, withdrawal_proof);
        self.withdrawal_aggregator
            .set_witness(&mut pw, withdrawal_aggregator);
        self.data.prove(pw)
    }
}

impl<F: RichField + Extendable<D>, C: GenericConfig<D, F = F> + 'static, const D: usize>
    Recursivable<F, C, D> for WithdrawalWrapperCircuit<F, C, D>
where
    <C as GenericConfig<D>>::Hasher: AlgebraicHasher<F>,
{
    fn circuit_data(&self) -> &CircuitData<F, C, D> {
        &self.data
    }
}
