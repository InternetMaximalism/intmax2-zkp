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
    common::trees::account_tree::{AccountMembershipProof, AccountMembershipProofTarget},
    constants::{ACCOUNT_TREE_HEIGHT, NUM_SENDERS_IN_BLOCK},
    ethereum_types::{
        u256::U256,
        u32limb_trait::{U32LimbTargetTrait as _, U32LimbTrait},
    },
    utils::{
        dummy::DummyProof,
        poseidon_hash_out::{PoseidonHashOut, PoseidonHashOutTarget},
        recursivable::Recursivable,
    },
};

use super::utils::{get_pubkey_commitment, get_pubkey_commitment_circuit};

const ACCOUNT_EXCLUSION_PUBLIC_INPUTS_LEN: usize = 4 + 4 + 1;

#[derive(Clone, Debug)]
pub struct AccountExclusionPublicInputs {
    pub account_tree_root: PoseidonHashOut,
    pub pubkey_commitment: PoseidonHashOut,
    pub is_valid: bool,
}

#[derive(Clone, Debug)]
pub struct AccountExclusionPublicInputsTarget {
    pub account_tree_root: PoseidonHashOutTarget,
    pub pubkey_commitment: PoseidonHashOutTarget,
    pub is_valid: BoolTarget,
}

impl AccountExclusionPublicInputs {
    pub fn from_u64_vec(input: &[u64]) -> Self {
        assert_eq!(input.len(), ACCOUNT_EXCLUSION_PUBLIC_INPUTS_LEN);
        let account_tree_root = PoseidonHashOut::from_u64_vec(&input[0..4]);
        let pubkey_commitment = PoseidonHashOut::from_u64_vec(&input[4..8]);
        let is_valid = input[8] == 1;
        Self {
            account_tree_root,
            pubkey_commitment,
            is_valid,
        }
    }
}

impl AccountExclusionPublicInputsTarget {
    pub fn to_vec(&self) -> Vec<Target> {
        let vec = self
            .account_tree_root
            .elements
            .into_iter()
            .chain(self.pubkey_commitment.elements.into_iter())
            .chain([self.is_valid.target])
            .collect::<Vec<_>>();
        assert_eq!(vec.len(), ACCOUNT_EXCLUSION_PUBLIC_INPUTS_LEN);
        vec
    }

    pub fn from_vec(input: &[Target]) -> Self {
        assert_eq!(input.len(), ACCOUNT_EXCLUSION_PUBLIC_INPUTS_LEN);
        let account_tree_root = PoseidonHashOutTarget::from_vec(&input[0..4]);
        let pubkey_commitment = PoseidonHashOutTarget::from_vec(&input[4..8]);
        let is_valid = BoolTarget::new_unsafe(input[8]);
        Self {
            account_tree_root,
            pubkey_commitment,
            is_valid,
        }
    }
}

#[derive(Clone, Debug)]
pub struct AccountExclusionValue {
    pub account_tree_root: PoseidonHashOut,
    pub account_membership_proofs: Vec<AccountMembershipProof>,
    pub pubkeys: Vec<U256<u32>>,
    pub pubkey_commitment: PoseidonHashOut,
    pub is_valid: bool,
}

impl AccountExclusionValue {
    pub fn new(
        account_tree_root: PoseidonHashOut,
        account_membership_proofs: Vec<AccountMembershipProof>,
        pubkeys: Vec<U256<u32>>,
    ) -> Self {
        let mut result = true;
        for (pubkey, proof) in pubkeys.iter().zip(account_membership_proofs.iter()) {
            proof.verify(*pubkey, account_tree_root).unwrap();
            let is_dummy = pubkey == &U256::<u32>::one();
            let is_excluded = !proof.is_included || is_dummy; // ignore dummy pubkey
            result = result && is_excluded;
        }
        let pubkey_commitment = get_pubkey_commitment(&pubkeys);
        Self {
            account_tree_root,
            account_membership_proofs,
            pubkeys,
            pubkey_commitment,
            is_valid: result,
        }
    }
}

#[derive(Clone, Debug)]
pub struct AccountExclusionTarget {
    pub account_tree_root: PoseidonHashOutTarget,
    pub account_membership_proofs: Vec<AccountMembershipProofTarget>,
    pub pubkeys: Vec<U256<Target>>,
    pub pubkey_commitment: PoseidonHashOutTarget,
    pub is_valid: BoolTarget,
}

impl AccountExclusionTarget {
    pub fn new<F: RichField + Extendable<D>, C: GenericConfig<D, F = F> + 'static, const D: usize>(
        builder: &mut CircuitBuilder<F, D>,
    ) -> Self
    where
        <C as GenericConfig<D>>::Hasher: AlgebraicHasher<F>,
    {
        let mut result = builder._true();
        let account_tree_root = PoseidonHashOutTarget::new(builder);

        let account_membership_proofs = (0..NUM_SENDERS_IN_BLOCK)
            .map(|_| AccountMembershipProofTarget::new(builder, ACCOUNT_TREE_HEIGHT, true))
            .collect::<Vec<_>>();
        let pubkeys = (0..NUM_SENDERS_IN_BLOCK)
            .map(|_| U256::<Target>::new(builder, true))
            .collect::<Vec<_>>();

        for (pubkey, proof) in pubkeys.iter().zip(account_membership_proofs.iter()) {
            proof.verify::<F, C, D>(builder, *pubkey, account_tree_root);
            let is_dummy = pubkey.is_one::<F, D, U256<u32>>(builder);
            let is_not_included = builder.not(proof.is_included);
            let is_excluded = builder.or(is_not_included, is_dummy);
            result = builder.and(result, is_excluded);
        }
        let pubkey_commitment = get_pubkey_commitment_circuit(builder, &pubkeys);
        Self {
            account_tree_root,
            account_membership_proofs,
            pubkeys,
            pubkey_commitment,
            is_valid: result,
        }
    }

    pub fn set_witness<F: RichField, W: Witness<F>>(
        &self,
        witness: &mut W,
        value: &AccountExclusionValue,
    ) {
        self.account_tree_root
            .set_witness(witness, value.account_tree_root);
        for (proof_t, proof) in self
            .account_membership_proofs
            .iter()
            .zip(value.account_membership_proofs.iter())
        {
            proof_t.set_witness(witness, proof);
        }
        for (pubkey_t, pubkey) in self.pubkeys.iter().zip(value.pubkeys.iter()) {
            pubkey_t.set_witness(witness, *pubkey);
        }
        self.pubkey_commitment
            .set_witness(witness, value.pubkey_commitment);
        witness.set_bool_target(self.is_valid, value.is_valid);
    }
}

pub struct AccountExclusionCircuit<F, C, const D: usize>
where
    F: RichField + Extendable<D>,
    C: GenericConfig<D, F = F>,
{
    pub data: CircuitData<F, C, D>,
    pub target: AccountExclusionTarget,
    pub dummy_proof: DummyProof<F, C, D>,
}

impl<F, C, const D: usize> AccountExclusionCircuit<F, C, D>
where
    F: RichField + Extendable<D>,
    C: GenericConfig<D, F = F> + 'static,
    C::Hasher: AlgebraicHasher<F>,
{
    pub fn new() -> Self {
        let mut builder = CircuitBuilder::<F, D>::new(CircuitConfig::default());
        let target = AccountExclusionTarget::new::<F, C, D>(&mut builder);
        let pis = AccountExclusionPublicInputsTarget {
            account_tree_root: target.account_tree_root,
            pubkey_commitment: target.pubkey_commitment,
            is_valid: target.is_valid,
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
        value: &AccountExclusionValue,
    ) -> anyhow::Result<ProofWithPublicInputs<F, C, D>> {
        let mut pw = PartialWitness::<F>::new();
        self.target.set_witness(&mut pw, value);
        self.data.prove(pw)
    }
}

impl<F, C, const D: usize> Recursivable<F, C, D> for AccountExclusionCircuit<F, C, D>
where
    F: RichField + Extendable<D>,
    C: GenericConfig<D, F = F> + 'static,
    C::Hasher: AlgebraicHasher<F>,
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

    use crate::{
        common::trees::account_tree::AccountTree, constants::NUM_SENDERS_IN_BLOCK,
        ethereum_types::u256::U256, test_utils::account_tree::add_random_accounts,
    };

    use super::*;

    type F = GoldilocksField;
    const D: usize = 2;
    type C = PoseidonGoldilocksConfig;

    #[test]
    fn account_exclusion() {
        let mut rng = rand::thread_rng();
        let mut tree = AccountTree::initialize();
        add_random_accounts(&mut rng, &mut tree, 1000);
        let account_tree_root = tree.get_root();

        let mut pubkeys = (0..10)
            .map(|_| U256::<u32>::rand(&mut rng))
            .collect::<Vec<_>>();
        pubkeys.resize(NUM_SENDERS_IN_BLOCK, U256::<u32>::one());
        let mut account_membership_proofs = Vec::new();
        for pubkey in pubkeys.iter() {
            let proof = tree.prove_membership(*pubkey);
            account_membership_proofs.push(proof);
        }

        let value =
            AccountExclusionValue::new(account_tree_root, account_membership_proofs, pubkeys);
        assert!(value.is_valid);
        let circuit = AccountExclusionCircuit::<F, C, D>::new();
        let _proof = circuit.prove(&value).unwrap();
    }
}
