use plonky2::{
    field::extension::Extendable,
    hash::hash_types::RichField,
    iop::{
        target::Target,
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
        account_tree::{AccountUpdateProof, AccountUpdateProofTarget},
        sender_tree::{SenderLeaf, SenderLeafTarget},
    },
    constants::{ACCOUNT_TREE_HEIGHT, NUM_SENDERS_IN_BLOCK, SENDER_TREE_HEIGHT},
    utils::{
        dummy::DummyProof,
        poseidon_hash_out::{PoseidonHashOut, PoseidonHashOutTarget},
        trees::get_root::{get_merkle_root_from_leaves, get_merkle_root_from_leaves_circuit},
    },
};

use super::account_transition_pis::AccountTransitionPublicInputsTarget;

pub(crate) struct AccountUpdateValue {
    pub(crate) prev_account_tree_root: PoseidonHashOut,
    pub(crate) new_account_tree_root: PoseidonHashOut,
    pub(crate) next_account_id: u64,
    pub(crate) sender_tree_root: PoseidonHashOut,
    pub(crate) block_number: u32,
    pub(crate) sender_leaves: Vec<SenderLeaf>,
    pub(crate) account_update_proofs: Vec<AccountUpdateProof>,
}

impl AccountUpdateValue {
    pub(crate) fn new(
        prev_account_tree_root: PoseidonHashOut,
        prev_next_account_id: u64,
        block_number: u32,
        sender_leaves: Vec<SenderLeaf>,
        account_update_proofs: Vec<AccountUpdateProof>,
    ) -> Self {
        assert_eq!(
            sender_leaves.len(),
            NUM_SENDERS_IN_BLOCK,
            "Invalid number of sender leaves"
        );
        assert_eq!(
            account_update_proofs.len(),
            NUM_SENDERS_IN_BLOCK,
            "Invalid number of account registration proofs"
        );
        let sender_tree_root = get_merkle_root_from_leaves(SENDER_TREE_HEIGHT, &sender_leaves);

        let mut account_tree_root = prev_account_tree_root;
        for (sender_leaf, account_registration_proof) in
            sender_leaves.iter().zip(account_update_proofs.iter())
        {
            let prev_last_block_number = account_registration_proof.prev_leaf.value as u32;
            let last_block_number = if sender_leaf.did_return_sig {
                block_number
            } else {
                prev_last_block_number
            };
            account_tree_root = account_registration_proof
                .get_new_root(
                    sender_leaf.sender,
                    prev_last_block_number as u64,
                    last_block_number as u64,
                    account_tree_root,
                )
                .expect("Invalid account update proof");
        }

        Self {
            prev_account_tree_root,
            new_account_tree_root: account_tree_root,
            next_account_id: prev_next_account_id,
            sender_tree_root,
            block_number,
            sender_leaves,
            account_update_proofs,
        }
    }
}

#[derive(Debug)]
pub(crate) struct AccountUpdateTarget {
    pub(crate) prev_account_tree_root: PoseidonHashOutTarget,
    pub(crate) new_account_tree_root: PoseidonHashOutTarget,
    pub(crate) next_account_id: Target,
    pub(crate) sender_tree_root: PoseidonHashOutTarget,
    pub(crate) block_number: Target,
    pub(crate) sender_leaves: Vec<SenderLeafTarget>,
    pub(crate) account_update_proofs: Vec<AccountUpdateProofTarget>,
}

impl AccountUpdateTarget {
    pub(crate) fn new<
        F: RichField + Extendable<D>,
        C: GenericConfig<D, F = F> + 'static,
        const D: usize,
    >(
        builder: &mut CircuitBuilder<F, D>,
    ) -> Self
    where
        <C as GenericConfig<D>>::Hasher: AlgebraicHasher<F>,
    {
        let prev_account_tree_root = PoseidonHashOutTarget::new(builder);
        let next_account_id = builder.add_virtual_target();
        let block_number = builder.add_virtual_target();

        // Range check is not needed because we check the commitment
        let sender_leaves = (0..NUM_SENDERS_IN_BLOCK)
            .map(|_| SenderLeafTarget::new(builder, false))
            .collect::<Vec<_>>();
        let account_update_proofs = (0..NUM_SENDERS_IN_BLOCK)
            .map(|_| AccountUpdateProofTarget::new(builder, ACCOUNT_TREE_HEIGHT, false))
            .collect::<Vec<_>>();
        let sender_tree_root = get_merkle_root_from_leaves_circuit::<F, C, D, _>(
            builder,
            SENDER_TREE_HEIGHT,
            &sender_leaves,
        );

        let mut account_tree_root = prev_account_tree_root;
        for (sender_leaf, account_update_proof) in
            sender_leaves.iter().zip(account_update_proofs.iter())
        {
            let prev_last_block_number = account_update_proof.prev_leaf.value;
            let last_block_number = builder.select(
                sender_leaf.did_return_sig,
                block_number,
                prev_last_block_number,
            );
            account_tree_root = account_update_proof.get_new_root::<F, C, D>(
                builder,
                sender_leaf.sender.clone(),
                prev_last_block_number,
                last_block_number,
                account_tree_root.clone(),
            );
        }

        Self {
            prev_account_tree_root,
            new_account_tree_root: account_tree_root,
            next_account_id,
            sender_tree_root,
            block_number,
            sender_leaves,
            account_update_proofs,
        }
    }

    pub(crate) fn set_witness<F: RichField, W: Witness<F>>(
        &self,
        witness: &mut W,
        value: &AccountUpdateValue,
    ) {
        self.prev_account_tree_root
            .set_witness(witness, value.prev_account_tree_root);
        self.new_account_tree_root
            .set_witness(witness, value.new_account_tree_root);
        witness.set_target(self.next_account_id, F::from_canonical_u64(value.next_account_id));
        self.sender_tree_root
            .set_witness(witness, value.sender_tree_root);
        witness.set_target(self.block_number, F::from_canonical_u32(value.block_number));

        for (sender_leaf, sender_leaf_t) in
            value.sender_leaves.iter().zip(self.sender_leaves.iter())
        {
            sender_leaf_t.set_witness(witness, sender_leaf);
        }

        for (account_update_proof, account_update_proof_t) in value
            .account_update_proofs
            .iter()
            .zip(self.account_update_proofs.iter())
        {
            account_update_proof_t.set_witness(witness, account_update_proof);
        }
    }
}

#[derive(Debug)]
pub struct AccountUpdateCircuit<F, C, const D: usize>
where
    F: RichField + Extendable<D>,
    C: GenericConfig<D, F = F>,
{
    pub(crate) data: CircuitData<F, C, D>,
    pub(crate) target: AccountUpdateTarget,
    pub(crate) dummy_proof: DummyProof<F, C, D>,
}

impl<F, C, const D: usize> AccountUpdateCircuit<F, C, D>
where
    F: RichField + Extendable<D>,
    C: GenericConfig<D, F = F> + 'static,
    C::Hasher: AlgebraicHasher<F>,
{
    pub(crate) fn new() -> Self {
        let config = CircuitConfig::default();
        let mut builder = CircuitBuilder::<F, D>::new(config.clone());
        let target = AccountUpdateTarget::new::<F, C, D>(&mut builder);
        let pis = AccountTransitionPublicInputsTarget {
            prev_account_tree_root: target.prev_account_tree_root.clone(),
            prev_next_account_id: target.next_account_id.clone(),
            new_account_tree_root: target.new_account_tree_root.clone(),
            new_next_account_id: target.next_account_id.clone(),
            sender_tree_root: target.sender_tree_root.clone(),
            block_number: target.block_number.clone(),
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

    pub(crate) fn prove(
        &self,
        value: &AccountUpdateValue,
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
        common::trees::{account_tree::AccountTree, sender_tree::get_sender_leaves},
        ethereum_types::{bytes16::Bytes16, u256::U256, u32limb_trait::U32LimbTrait as _},
    };

    use super::*;
    type F = GoldilocksField;
    const D: usize = 2;
    type C = PoseidonGoldilocksConfig;

    #[test]
    fn account_update() {
        let mut rng = rand::thread_rng();
        let mut tree = AccountTree::initialize();
        let mut next_account_id = 2;
        let pubkeys = (0..NUM_SENDERS_IN_BLOCK)
            .map(|_| U256::rand(&mut rng))
            .collect::<Vec<_>>();
        for punkey in &pubkeys {
            tree.insert(*punkey, 10).unwrap();
            next_account_id += 1;
        }
        let prev_account_tree_root = tree.get_root();

        let sender_flag = Bytes16::rand(&mut rng);
        let sender_leaves = get_sender_leaves(&pubkeys, sender_flag);
        let block_number: u32 = 1000;
        let mut account_update_proofs = Vec::new();
        for sender_leaf in sender_leaves.iter() {
            let account_id = tree.index(sender_leaf.sender).unwrap();
            let prev_leaf = tree.get_leaf(account_id);
            let prev_last_block_number = prev_leaf.value as u32;
            let last_block_number = if sender_leaf.did_return_sig {
                block_number
            } else {
                prev_last_block_number
            };
            let proof = tree.prove_and_update(sender_leaf.sender, last_block_number as u64);
            account_update_proofs.push(proof);
        }
        let new_account_tree_root = tree.get_root();

        let account_registration_value = AccountUpdateValue::new(
            prev_account_tree_root,
            next_account_id,
            block_number,
            sender_leaves,
            account_update_proofs,
        );
        assert_eq!(
            account_registration_value.new_account_tree_root,
            new_account_tree_root
        );

        let account_registration_circuit = AccountUpdateCircuit::<F, C, D>::new();
        let _proof = account_registration_circuit
            .prove(&account_registration_value)
            .unwrap();
    }
}
