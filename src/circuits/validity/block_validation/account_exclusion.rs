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
    common::trees::{
        account_tree::{AccountMembershipProof, AccountMembershipProofTarget},
        sender_tree::{SenderLeaf, SenderLeafTarget},
    },
    constants::{ACCOUNT_TREE_HEIGHT, NUM_SENDERS_IN_BLOCK, SENDER_TREE_HEIGHT},
    utils::{
        dummy::DummyProof,
        poseidon_hash_out::{PoseidonHashOut, PoseidonHashOutTarget},
        trees::get_root::{get_merkle_root_from_leaves, get_merkle_root_from_leaves_circuit},
    },
};

const ACCOUNT_EXCLUSION_PUBLIC_INPUTS_LEN: usize = 4 + 4 + 1;

#[derive(Clone, Debug)]
pub struct AccountExclusionPublicInputs {
    pub account_tree_root: PoseidonHashOut,
    pub sender_tree_root: PoseidonHashOut,
    pub is_valid: bool,
}

#[derive(Clone, Debug)]
pub struct AccountExclusionPublicInputsTarget {
    pub account_tree_root: PoseidonHashOutTarget,
    pub sender_tree_root: PoseidonHashOutTarget,
    pub is_valid: BoolTarget,
}

impl AccountExclusionPublicInputs {
    pub fn from_u64_slice(input: &[u64]) -> Self {
        assert_eq!(input.len(), ACCOUNT_EXCLUSION_PUBLIC_INPUTS_LEN);
        let account_tree_root = PoseidonHashOut::from_u64_slice(&input[0..4]);
        let sender_tree_root = PoseidonHashOut::from_u64_slice(&input[4..8]);
        let is_valid = input[8] == 1;
        Self {
            account_tree_root,
            sender_tree_root,
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
            .chain(self.sender_tree_root.elements.into_iter())
            .chain([self.is_valid.target])
            .collect::<Vec<_>>();
        assert_eq!(vec.len(), ACCOUNT_EXCLUSION_PUBLIC_INPUTS_LEN);
        vec
    }

    pub fn from_slice(input: &[Target]) -> Self {
        assert_eq!(input.len(), ACCOUNT_EXCLUSION_PUBLIC_INPUTS_LEN);
        let account_tree_root = PoseidonHashOutTarget::from_slice(&input[0..4]);
        let sender_tree_root = PoseidonHashOutTarget::from_slice(&input[4..8]);
        let is_valid = BoolTarget::new_unsafe(input[8]);
        Self {
            account_tree_root,
            sender_tree_root,
            is_valid,
        }
    }
}

#[derive(Clone, Debug)]
pub struct AccountExclusionValue {
    pub account_tree_root: PoseidonHashOut,
    pub account_membership_proofs: Vec<AccountMembershipProof>,
    pub sender_leaves: Vec<SenderLeaf>,
    pub sender_tree_root: PoseidonHashOut,
    pub is_valid: bool,
}

impl AccountExclusionValue {
    pub fn new(
        account_tree_root: PoseidonHashOut,
        account_membership_proofs: Vec<AccountMembershipProof>,
        sender_leaves: Vec<SenderLeaf>,
    ) -> Self {
        let mut result = true;
        for (sender_leaf, proof) in sender_leaves.iter().zip(account_membership_proofs.iter()) {
            proof.verify(sender_leaf.sender, account_tree_root).unwrap();
            let is_dummy = sender_leaf.sender.is_dummy_pubkey();
            let is_valid = (!proof.is_included && sender_leaf.did_return_sig) || is_dummy;
            result = result && is_valid;
        }
        let sender_tree_root = get_merkle_root_from_leaves(SENDER_TREE_HEIGHT, &sender_leaves);
        Self {
            account_tree_root,
            account_membership_proofs,
            sender_leaves,
            sender_tree_root,
            is_valid: result,
        }
    }
}

#[derive(Clone, Debug)]
pub struct AccountExclusionTarget {
    pub account_tree_root: PoseidonHashOutTarget,
    pub account_membership_proofs: Vec<AccountMembershipProofTarget>,
    pub sender_leaves: Vec<SenderLeafTarget>,
    pub sender_tree_root: PoseidonHashOutTarget,
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
        let sender_leaves = (0..NUM_SENDERS_IN_BLOCK)
            .map(|_| SenderLeafTarget::new(builder, true))
            .collect::<Vec<_>>();

        for (sender_leaf, proof) in sender_leaves.iter().zip(account_membership_proofs.iter()) {
            proof.verify::<F, C, D>(builder, sender_leaf.sender, account_tree_root);
            let is_dummy = sender_leaf.sender.is_dummy_pubkey(builder);
            let is_not_included = builder.not(proof.is_included);
            let is_not_included_and_did_return_sig =
                builder.and(is_not_included, sender_leaf.did_return_sig);
            let is_valid = builder.or(is_not_included_and_did_return_sig, is_dummy);
            result = builder.and(result, is_valid);
        }
        let sender_tree_root = get_merkle_root_from_leaves_circuit::<F, C, D, _>(
            builder,
            SENDER_TREE_HEIGHT,
            &sender_leaves,
        );
        Self {
            account_tree_root,
            account_membership_proofs,
            sender_leaves,
            sender_tree_root,
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
        for (sender_leaf_t, sender_leaf) in
            self.sender_leaves.iter().zip(value.sender_leaves.iter())
        {
            sender_leaf_t.set_witness(witness, sender_leaf);
        }
        self.sender_tree_root
            .set_witness(witness, value.sender_tree_root);
        witness.set_bool_target(self.is_valid, value.is_valid);
    }
}

#[derive(Debug)]
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
            sender_tree_root: target.sender_tree_root,
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

#[cfg(test)]
mod tests {
    use plonky2::{
        field::goldilocks_field::GoldilocksField, plonk::config::PoseidonGoldilocksConfig,
    };

    use crate::{
        common::{signature::key_set::KeySet, trees::account_tree::AccountTree},
        constants::NUM_SENDERS_IN_BLOCK,
        ethereum_types::u256::U256,
    };
    use rand::Rng;

    use super::*;

    type F = GoldilocksField;
    const D: usize = 2;
    type C = PoseidonGoldilocksConfig;

    #[test]
    fn account_exclusion() {
        let mut rng = rand::thread_rng();
        let mut tree = AccountTree::initialize();
        for _ in 0..100 {
            let keyset = KeySet::rand(&mut rng);
            let last_block_number = rng.gen();
            tree.insert(keyset.pubkey, last_block_number).unwrap();
        }
        let account_tree_root = tree.get_root();

        let mut pubkeys = (0..10).map(|_| U256::rand(&mut rng)).collect::<Vec<_>>();
        pubkeys.resize(NUM_SENDERS_IN_BLOCK, U256::dummy_pubkey());
        let mut account_membership_proofs = Vec::new();
        let mut sender_leaves = Vec::new();
        for pubkey in pubkeys.iter() {
            let proof = tree.prove_membership(*pubkey);
            account_membership_proofs.push(proof);
            let sender_leaf = SenderLeaf {
                sender: *pubkey,
                did_return_sig: rng.gen(),
            };
            sender_leaves.push(sender_leaf);
        }

        let value =
            AccountExclusionValue::new(account_tree_root, account_membership_proofs, sender_leaves);
        // assert!(value.is_valid);
        let circuit = AccountExclusionCircuit::<F, C, D>::new();
        let _proof = circuit.prove(&value).unwrap();
    }
}
