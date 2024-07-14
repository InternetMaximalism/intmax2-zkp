use plonky2::{
    field::extension::Extendable,
    hash::hash_types::RichField,
    iop::{
        target::Target,
        witness::{PartialWitness, WitnessWrite},
    },
    plonk::{
        circuit_builder::CircuitBuilder,
        circuit_data::{CircuitConfig, CircuitData},
        config::{AlgebraicHasher, GenericConfig},
        proof::{ProofWithPublicInputs, ProofWithPublicInputsTarget},
    },
};

use crate::{
    circuits::validity::{
        validity_circuit::ValidityCircuit,
        validity_pis::{
            ValidityPublicInputs, ValidityPublicInputsTarget, VALIDITY_PUBLIC_INPUTS_LEN,
        },
    },
    common::{
        public_state::{PublicState, PublicStateTarget, PUBLIC_STATE_LEN},
        trees::block_hash_tree::{BlockHashMerkleProof, BlockHashMerkleProofTarget},
    },
    constants::BLOCK_HASH_TREE_HEIGHT,
    utils::{conversion::ToU64, dummy::DummyProof, recursivable::Recursivable},
};

pub const UPDATE_PUBLIC_INPUTS_LEN: usize = PUBLIC_STATE_LEN * 2;

#[derive(Debug, Clone)]
pub struct UpdatePublicInputs {
    pub prev_public_state: PublicState,
    pub new_public_state: PublicState,
}

#[derive(Debug, Clone)]
pub struct UpdatePublicInputsTarget {
    pub prev_public_state: PublicStateTarget,
    pub new_public_state: PublicStateTarget,
}

impl UpdatePublicInputs {
    pub fn to_u64_vec(&self) -> Vec<u64> {
        let vec = vec![
            self.prev_public_state.to_u64_vec(),
            self.new_public_state.to_u64_vec(),
        ]
        .concat();
        assert_eq!(vec.len(), UPDATE_PUBLIC_INPUTS_LEN);
        vec
    }

    pub fn from_u64_vec(input: &[u64]) -> Self {
        assert_eq!(input.len(), UPDATE_PUBLIC_INPUTS_LEN);
        let prev_public_state = PublicState::from_u64_vec(&input[0..PUBLIC_STATE_LEN]);
        let new_public_state = PublicState::from_u64_vec(&input[PUBLIC_STATE_LEN..]);
        UpdatePublicInputs {
            prev_public_state,
            new_public_state,
        }
    }
}

impl UpdatePublicInputsTarget {
    pub fn to_vec(&self) -> Vec<Target> {
        let vec = vec![
            self.prev_public_state.to_vec(),
            self.new_public_state.to_vec(),
        ]
        .concat();
        assert_eq!(vec.len(), UPDATE_PUBLIC_INPUTS_LEN);
        vec
    }

    pub fn from_vec(input: &[Target]) -> Self {
        assert_eq!(input.len(), UPDATE_PUBLIC_INPUTS_LEN);
        let prev_public_state = PublicStateTarget::from_vec(&input[0..PUBLIC_STATE_LEN]);
        let new_public_state = PublicStateTarget::from_vec(&input[PUBLIC_STATE_LEN..]);
        UpdatePublicInputsTarget {
            prev_public_state,
            new_public_state,
        }
    }
}

#[derive(Debug, Clone)]
pub struct UpdateValue<
    F: RichField + Extendable<D>,
    C: GenericConfig<D, F = F> + 'static,
    const D: usize,
> where
    <C as GenericConfig<D>>::Hasher: AlgebraicHasher<F>,
{
    pub prev_public_state: PublicState,
    pub new_public_state: PublicState,
    pub validity_proof: ProofWithPublicInputs<F, C, D>,
    pub block_merkle_proof: BlockHashMerkleProof,
}

impl<F: RichField + Extendable<D>, C: GenericConfig<D, F = F> + 'static, const D: usize>
    UpdateValue<F, C, D>
where
    <C as GenericConfig<D>>::Hasher: AlgebraicHasher<F>,
{
    pub fn new(
        validity_circuit: &ValidityCircuit<F, C, D>,
        validity_proof: &ProofWithPublicInputs<F, C, D>,
        prev_public_state: &PublicState,
        block_merkle_proof: &BlockHashMerkleProof,
    ) -> Self {
        validity_circuit
            .verify(validity_proof)
            .expect("validity proof is invalid");
        let validity_pis = ValidityPublicInputs::from_u64_vec(
            &validity_proof.public_inputs[0..VALIDITY_PUBLIC_INPUTS_LEN].to_u64_vec(),
        );
        block_merkle_proof
            .verify(
                &prev_public_state.block_hash,
                prev_public_state.block_number as usize,
                validity_pis.public_state.block_tree_root,
            )
            .expect("block merkle proof is invalid");
        Self {
            prev_public_state: prev_public_state.clone(),
            new_public_state: validity_pis.public_state.clone(),
            validity_proof: validity_proof.clone(),
            block_merkle_proof: block_merkle_proof.clone(),
        }
    }
}

#[derive(Debug, Clone)]
pub struct UpdateTarget<const D: usize> {
    pub prev_public_state: PublicStateTarget,
    pub new_public_state: PublicStateTarget,
    pub validity_proof: ProofWithPublicInputsTarget<D>,
    pub block_merkle_proof: BlockHashMerkleProofTarget,
}

impl<const D: usize> UpdateTarget<D> {
    pub fn new<F: RichField + Extendable<D>, C: GenericConfig<D, F = F> + 'static>(
        validity_circuit: &ValidityCircuit<F, C, D>,
        builder: &mut CircuitBuilder<F, D>,
        is_checked: bool,
    ) -> Self
    where
        <C as GenericConfig<D>>::Hasher: AlgebraicHasher<F>,
    {
        let block_merkle_proof = BlockHashMerkleProofTarget::new(builder, BLOCK_HASH_TREE_HEIGHT);
        let prev_public_state = PublicStateTarget::new(builder, is_checked);
        let validity_proof = validity_circuit.add_proof_target_and_verify(builder);
        let validity_pis = ValidityPublicInputsTarget::from_vec(
            &validity_proof.public_inputs[0..VALIDITY_PUBLIC_INPUTS_LEN],
        );
        block_merkle_proof.verify::<F, C, D>(
            builder,
            &prev_public_state.block_hash,
            prev_public_state.block_number,
            validity_pis.public_state.block_tree_root,
        );
        Self {
            prev_public_state,
            new_public_state: validity_pis.public_state,
            validity_proof,
            block_merkle_proof,
        }
    }

    pub fn set_witness<
        F: RichField + Extendable<D>,
        C: GenericConfig<D, F = F> + 'static,
        W: WitnessWrite<F>,
    >(
        &self,
        witness: &mut W,
        value: &UpdateValue<F, C, D>,
    ) where
        <C as GenericConfig<D>>::Hasher: AlgebraicHasher<F>,
    {
        self.prev_public_state
            .set_witness(witness, &value.prev_public_state);
        self.new_public_state
            .set_witness(witness, &value.new_public_state);
        witness.set_proof_with_pis_target(&self.validity_proof, &value.validity_proof);
        self.block_merkle_proof
            .set_witness(witness, &value.block_merkle_proof);
    }
}

pub struct UpdateCircuit<F, C, const D: usize>
where
    F: RichField + Extendable<D>,
    C: GenericConfig<D, F = F>,
{
    pub data: CircuitData<F, C, D>,
    pub target: UpdateTarget<D>,
    pub dummy_proof: DummyProof<F, C, D>,
}

impl<F, C, const D: usize> UpdateCircuit<F, C, D>
where
    F: RichField + Extendable<D>,
    C: GenericConfig<D, F = F> + 'static,
    C::Hasher: AlgebraicHasher<F>,
{
    pub fn new(validity_circuit: &ValidityCircuit<F, C, D>) -> Self {
        let mut builder = CircuitBuilder::<F, D>::new(CircuitConfig::default());
        let target = UpdateTarget::new::<F, C>(validity_circuit, &mut builder, true);
        let pis = UpdatePublicInputsTarget {
            prev_public_state: target.prev_public_state.clone(),
            new_public_state: target.new_public_state.clone(),
        };
        builder.register_public_inputs(&pis.to_vec());
        let data = builder.build();
        let dummy_proof = DummyProof::new(&data.common);
        Self {
            data,
            target,
            dummy_proof,
        }
    }

    pub fn prove(
        &self,
        value: &UpdateValue<F, C, D>,
    ) -> anyhow::Result<ProofWithPublicInputs<F, C, D>> {
        let mut pw = PartialWitness::<F>::new();
        self.target.set_witness(&mut pw, value);
        self.data.prove(pw)
    }
}

impl<F, C, const D: usize> Recursivable<F, C, D> for UpdateCircuit<F, C, D>
where
    F: RichField + Extendable<D>,
    C: GenericConfig<D, F = F> + 'static,
    C::Hasher: AlgebraicHasher<F>,
{
    fn circuit_data(&self) -> &CircuitData<F, C, D> {
        &self.data
    }
}
