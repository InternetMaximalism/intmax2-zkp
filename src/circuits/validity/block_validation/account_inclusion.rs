use crate::{
    circuits::validity::block_validation::utils::get_pubkey_commitment,
    common::trees::account_tree::{AccountMerkleProof, AccountMerkleProofTarget},
    constants::NUM_SENDERS_IN_BLOCK,
    ethereum_types::{
        account_id_packed::AccountIdPacked,
        bytes32::{Bytes32, BYTES32_LEN},
        u256::U256,
        u32limb_trait::{U32LimbTargetTrait, U32LimbTrait},
    },
    utils::{
        dummy::DummyProof,
        poseidon_hash_out::{PoseidonHashOut, PoseidonHashOutTarget},
        recursivable::Recursivable,
    },
};
use plonky2::{
    field::{extension::Extendable, types::Field},
    gates::constant::ConstantGate,
    hash::hash_types::RichField,
    iop::{
        target::{BoolTarget, Target},
        witness::{PartialWitness, WitnessWrite},
    },
    plonk::{
        circuit_builder::CircuitBuilder,
        circuit_data::{CircuitConfig, CircuitData},
        config::{AlgebraicHasher, GenericConfig},
        proof::ProofWithPublicInputs,
    },
};

use super::utils::get_pubkey_commitment_circuit;

const ACCOUNT_INCLUSION_PUBLIC_INPUTS_LEN: usize = BYTES32_LEN + 4 + 4 + 1;

#[derive(Clone, Debug)]
pub struct AccountInclusionPublicInputs {
    pub account_id_hash: Bytes32<u32>,
    pub account_tree_root: PoseidonHashOut,
    pub pubkey_commitment: PoseidonHashOut,
    pub is_valid: bool,
}

#[derive(Clone, Debug)]
pub struct AccountInclusionPublicInputsTarget {
    pub account_id_hash: Bytes32<Target>,
    pub account_tree_root: PoseidonHashOutTarget,
    pub pubkey_commitment: PoseidonHashOutTarget,
    pub is_valid: BoolTarget,
}

impl AccountInclusionPublicInputs {
    pub fn from_u64_vec(input: &[u64]) -> Self {
        assert_eq!(input.len(), ACCOUNT_INCLUSION_PUBLIC_INPUTS_LEN);
        let account_id_hash = Bytes32::from_u64_vec(&input[0..8]);
        let account_tree_root = PoseidonHashOut::from_u64_vec(&input[8..12]);
        let pubkey_commitment = PoseidonHashOut::from_u64_vec(&input[12..16]);
        let is_valid = input[16] == 1;
        Self {
            account_id_hash,
            account_tree_root,
            pubkey_commitment,
            is_valid,
        }
    }
}

impl AccountInclusionPublicInputsTarget {
    pub fn to_vec(&self) -> Vec<Target> {
        let vec = self
            .account_id_hash
            .limbs()
            .into_iter()
            .chain(self.account_tree_root.elements.into_iter())
            .chain(self.pubkey_commitment.elements.into_iter())
            .chain([self.is_valid.target])
            .collect::<Vec<_>>();
        assert_eq!(vec.len(), ACCOUNT_INCLUSION_PUBLIC_INPUTS_LEN);
        vec
    }

    pub fn from_vec(input: &[Target]) -> Self {
        assert_eq!(input.len(), ACCOUNT_INCLUSION_PUBLIC_INPUTS_LEN);
        let account_id_hash = Bytes32::<Target>::from_limbs(&input[0..8]);
        let account_tree_root = PoseidonHashOutTarget {
            elements: input[8..12].try_into().unwrap(),
        };
        let pubkey_commitment = PoseidonHashOutTarget {
            elements: input[12..16].try_into().unwrap(),
        };
        let is_valid = BoolTarget::new_unsafe(input[16]);
        Self {
            account_id_hash,
            account_tree_root,
            pubkey_commitment,
            is_valid,
        }
    }
}

#[derive(Clone, Debug)]
pub struct AccountInclusionValue {
    pub account_id_packed: AccountIdPacked<u32>,
    pub account_id_hash: Bytes32<u32>,
    pub account_tree_root: PoseidonHashOut,
    pub account_merkle_proofs: Vec<AccountMerkleProof>,
    pub pubkeys: Vec<U256<u32>>,
    pub pubkey_commitment: PoseidonHashOut,
    pub is_valid: bool,
}

impl AccountInclusionValue {
    pub fn new(
        account_tree_root: PoseidonHashOut,
        account_id_packed: AccountIdPacked<u32>,
        account_merkle_proofs: Vec<AccountMerkleProof>,
        pubkeys: Vec<U256<u32>>,
    ) -> Self {
        assert_eq!(account_merkle_proofs.len(), NUM_SENDERS_IN_BLOCK);
        assert_eq!(pubkeys.len(), NUM_SENDERS_IN_BLOCK);

        let mut result = true;
        let account_id_hash = account_id_packed.hash();
        let account_ids = account_id_packed.unpack();
        for ((account_id, proof), pubkey) in account_ids
            .iter()
            .zip(account_merkle_proofs.iter())
            .zip(pubkeys.iter())
        {
            result = result && proof.verify(account_tree_root, *account_id, *pubkey);
        }
        let pubkey_commitment = get_pubkey_commitment(&pubkeys);
        Self {
            account_id_packed,
            account_tree_root,
            account_merkle_proofs,
            pubkeys,
            account_id_hash,
            pubkey_commitment,
            is_valid: result,
        }
    }
}

#[derive(Clone, Debug)]
pub struct AccountInclusionTarget {
    pub account_id_packed: AccountIdPacked<Target>,
    pub account_tree_root: PoseidonHashOutTarget,
    pub account_merkle_proofs: Vec<AccountMerkleProofTarget>,
    pub pubkeys: Vec<U256<Target>>,
    pub account_id_hash: Bytes32<Target>,
    pub pubkey_commitment: PoseidonHashOutTarget,
    pub is_valid: BoolTarget,
}

impl AccountInclusionTarget {
    pub fn new<F: RichField + Extendable<D>, C: GenericConfig<D, F = F> + 'static, const D: usize>(
        builder: &mut CircuitBuilder<F, D>,
    ) -> Self
    where
        <C as GenericConfig<D>>::Hasher: AlgebraicHasher<F>,
    {
        let mut result = builder._true();
        let account_tree_root = PoseidonHashOutTarget::new(builder);
        let account_id_packed = AccountIdPacked::new(builder, true);
        let account_merkle_proofs = (0..NUM_SENDERS_IN_BLOCK)
            .map(|_| AccountMerkleProofTarget::new(builder, true))
            .collect::<Vec<_>>();
        // The pubkey already exists in the account tree, so it has already been range
        // checked.
        let pubkeys = (0..NUM_SENDERS_IN_BLOCK)
            .map(|_| U256::<Target>::new(builder, false))
            .collect::<Vec<_>>();
        let account_id_hash = account_id_packed.hash::<F, C, D>(builder);
        let account_ids = account_id_packed.unpack(builder);
        for ((account_id, proof), pubkey) in account_ids
            .iter()
            .zip(account_merkle_proofs.iter())
            .zip(pubkeys.iter())
        {
            let is_proof_valid =
                proof.verify::<F, C, D>(builder, account_tree_root, *account_id, *pubkey);
            result = builder.and(result, is_proof_valid);
        }
        let pubkey_commitment = get_pubkey_commitment_circuit(builder, &pubkeys);
        Self {
            account_id_packed,
            account_tree_root,
            account_merkle_proofs,
            pubkeys,
            account_id_hash,
            pubkey_commitment,
            is_valid: result,
        }
    }

    pub fn set_witness<F: Field, W: WitnessWrite<F>>(
        &self,
        witness: &mut W,
        value: &AccountInclusionValue,
    ) {
        self.account_id_packed
            .set_witness(witness, value.account_id_packed);
        self.account_tree_root
            .set_witness(witness, value.account_tree_root);
        for (proof_t, proof) in self
            .account_merkle_proofs
            .iter()
            .zip(value.account_merkle_proofs.iter())
        {
            proof_t.set_witness(witness, proof);
        }
        for (pubkey_t, pubkey) in self.pubkeys.iter().zip(value.pubkeys.iter()) {
            pubkey_t.set_witness(witness, *pubkey);
        }
        self.account_id_hash
            .set_witness(witness, value.account_id_hash);
        self.pubkey_commitment
            .set_witness(witness, value.pubkey_commitment);
        witness.set_bool_target(self.is_valid, value.is_valid);
    }
}

pub struct AccountInclusionCircuit<F, C, const D: usize>
where
    F: RichField + Extendable<D>,
    C: GenericConfig<D, F = F>,
{
    pub data: CircuitData<F, C, D>,
    pub target: AccountInclusionTarget,
    pub dummy_proof: DummyProof<F, C, D>,
}

impl<F, C, const D: usize> AccountInclusionCircuit<F, C, D>
where
    F: RichField + Extendable<D>,
    C: GenericConfig<D, F = F> + 'static,
    C::Hasher: AlgebraicHasher<F>,
{
    pub fn new() -> Self {
        let config = CircuitConfig::default();
        let mut builder = CircuitBuilder::<F, D>::new(config.clone());
        let target = AccountInclusionTarget::new::<F, C, D>(&mut builder);
        let pis = AccountInclusionPublicInputsTarget {
            account_id_hash: target.account_id_hash,
            account_tree_root: target.account_tree_root,
            pubkey_commitment: target.pubkey_commitment,
            is_valid: target.is_valid,
        };
        builder.register_public_inputs(&pis.to_vec());

        // Add a ContantGate to create a dummy proof.
        builder.add_gate(ConstantGate::new(config.num_constants), vec![]);

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
        value: &AccountInclusionValue,
    ) -> anyhow::Result<ProofWithPublicInputs<F, C, D>> {
        let mut pw = PartialWitness::<F>::new();
        self.target.set_witness(&mut pw, value);
        self.data.prove(pw)
    }
}

impl<F: RichField + Extendable<D>, C: GenericConfig<D, F = F> + 'static, const D: usize>
    Recursivable<F, C, D> for AccountInclusionCircuit<F, C, D>
where
    <C as GenericConfig<D>>::Hasher: AlgebraicHasher<F>,
{
    fn circuit_data(&self) -> &CircuitData<F, C, D> {
        &self.data
    }
}

#[cfg(test)]
mod tests {
    use plonky2::{
        field::goldilocks_field::GoldilocksField, plonk::config::PoseidonGoldilocksConfig,
    };
    use rand::Rng as _;

    use crate::{
        common::{signature::key_set::KeySet, trees::account_tree::AccountTree},
        constants::NUM_SENDERS_IN_BLOCK,
        ethereum_types::account_id_packed::AccountIdPacked,
    };

    use super::{AccountInclusionCircuit, AccountInclusionValue};
    type F = GoldilocksField;
    const D: usize = 2;
    type C = PoseidonGoldilocksConfig;

    #[test]
    fn account_inclusion() {
        let mut rng = rand::thread_rng();
        let mut tree = AccountTree::initialize();

        let mut pubkeys = Vec::new();
        // insert
        for _ in 0..NUM_SENDERS_IN_BLOCK {
            let keyset = KeySet::rand(&mut rng);
            pubkeys.push(keyset.pubkey_x);
            let last_block_number = rng.gen();
            tree.insert(keyset.pubkey_x, last_block_number).unwrap();
        }

        let mut account_ids = Vec::new();
        let mut account_merkle_proofs = Vec::new();
        for pubkey in &pubkeys {
            let account_id = tree.index(*pubkey).unwrap();
            let proof = tree.prove_inclusion(account_id);
            account_ids.push(account_id);
            account_merkle_proofs.push(proof);
        }
        let account_tree_root = tree.get_root();
        let account_id_packed = AccountIdPacked::pack(&account_ids);
        let value = AccountInclusionValue::new(
            account_tree_root,
            account_id_packed,
            account_merkle_proofs,
            pubkeys,
        );
        assert!(value.is_valid);
        let circuit = AccountInclusionCircuit::<F, C, D>::new();
        let _proof = circuit.prove(&value).unwrap();
    }
}
