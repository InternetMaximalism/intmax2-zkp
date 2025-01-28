use std::collections::HashMap;

use anyhow::bail;
use plonky2::{
    field::extension::Extendable,
    hash::hash_types::RichField,
    plonk::{
        config::{AlgebraicHasher, GenericConfig},
        proof::ProofWithPublicInputs,
    },
};

use crate::{
    circuits::proof_of_innocence::{
        address_list::AddressListTree, innocence_inner_target::InnocenceInnerValue,
    },
    common::{
        deposit::Deposit, private_state::FullPrivateState, trees::nullifier_tree::NullifierTree,
    },
    ethereum_types::{address::Address, bytes32::Bytes32},
    utils::poseidon_hash_out::PoseidonHashOut,
};

use super::{
    innocence_circuit::InnocenceCircuit,
    innocence_wrap_circuit::{InnocenceWrapCircuit, InnocenceWrapPublicInputs},
};

pub struct InnocenceProcessor<F, C, const D: usize>
where
    F: RichField + Extendable<D>,
    C: GenericConfig<D, F = F>,
{
    innocence_circuit: InnocenceCircuit<F, C, D>,
    innocence_wrap_circuit: InnocenceWrapCircuit<F, C, D>,
}

impl<F, C, const D: usize> InnocenceProcessor<F, C, D>
where
    F: RichField + Extendable<D>,
    C: GenericConfig<D, F = F> + 'static,
    C::Hasher: AlgebraicHasher<F>,
{
    pub fn new() -> Self {
        let innocence_circuit = InnocenceCircuit::new();
        let innocence_wrap_circuit =
            InnocenceWrapCircuit::new(&innocence_circuit.data.verifier_data());
        Self {
            innocence_circuit,
            innocence_wrap_circuit,
        }
    }

    pub fn prove(
        &self,
        allow_list: Option<&[Address]>,
        deny_list: &[Address],
        full_private_state: &FullPrivateState,
        deposits: &[Deposit],
    ) -> anyhow::Result<ProofWithPublicInputs<F, C, D>> {
        let mut nullifier_map = HashMap::<Bytes32, Deposit>::new();
        for deposit in deposits {
            nullifier_map.insert(deposit.poseidon_hash().into(), deposit.clone());
        }

        let mut sorted_deposits = Vec::new();
        for nullifier in full_private_state.nullifier_tree.nullifiers() {
            if !nullifier_map.contains_key(&nullifier) {
                bail!(
                    "corresponding deposit not found for nullifier {}",
                    nullifier
                );
            } else {
                sorted_deposits.push(nullifier_map.get(&nullifier).unwrap());
            }
        }
        if sorted_deposits.is_empty() {
            bail!("at least one deposit is required");
        }
        // verification
        let use_allow_list = allow_list.is_some();
        {
            let mut nullifier_tree = NullifierTree::new();
            for deposit in &sorted_deposits {
                if use_allow_list && !allow_list.unwrap().contains(&deposit.depositor) {
                    bail!("depositor is not in the allow list");
                }
                if deny_list.contains(&deposit.depositor) {
                    bail!("depositor is in the deny list");
                }
                let nullifier: Bytes32 = deposit.poseidon_hash().into();
                nullifier_tree
                    .prove_and_insert(nullifier)
                    .map_err(|e| anyhow::anyhow!("Failed to prove and insert nullifier: {}", e))?;
            }
            if nullifier_tree.get_root() != full_private_state.nullifier_tree.get_root() {
                bail!("Invalid nullifier tree root");
            }
        }

        let allow_list_tree = AddressListTree::new(allow_list.unwrap_or_default())
            .map_err(|e| anyhow::anyhow!("Failed to create allow list tree: {}", e))?;
        let deny_list_tree = AddressListTree::new(deny_list)
            .map_err(|e| anyhow::anyhow!("Failed to create deny list tree: {}", e))?;
        let allow_list_tree_root = allow_list_tree.get_root();
        let deny_list_tree_root = deny_list_tree.get_root();

        let mut nullifier_tree = NullifierTree::new();
        let mut innocence_proof = None;
        for deposit in sorted_deposits {
            let prev_nullifier_tree_root = nullifier_tree.get_root();
            let nullifier_proof = nullifier_tree
                .prove_and_insert(deposit.poseidon_hash().into())
                .map_err(|e| anyhow::anyhow!("Failed to prove and insert nullifier: {}", e))?;
            let allow_list_membership_proof = allow_list_tree.prove_membership(deposit.depositor);
            let deny_list_membership_proof = deny_list_tree.prove_membership(deposit.depositor);
            let value = InnocenceInnerValue::new(
                use_allow_list,
                allow_list_tree_root,
                deny_list_tree_root,
                prev_nullifier_tree_root,
                deposit.clone(),
                nullifier_proof,
                allow_list_membership_proof,
                deny_list_membership_proof,
            )
            .map_err(|e| anyhow::anyhow!("Failed to create innocence inner value: {}", e))?;
            innocence_proof = Some(
                self.innocence_circuit
                    .prove(&value, &innocence_proof)
                    .map_err(|e| anyhow::anyhow!("Failed to prove innocence circuit: {}", e))?,
            );
        }

        let private_state = full_private_state.to_private_state();
        let innocence_wrap_proof = self
            .innocence_wrap_circuit
            .prove(innocence_proof.as_ref().unwrap(), private_state)
            .map_err(|e| anyhow::anyhow!("Failed to prove innocence wrap circuit: {}", e))?;

        Ok(innocence_wrap_proof)
    }

    pub fn verify(
        &self,
        allow_list: Option<&[Address]>,
        deny_list: &[Address],
        private_commitment: PoseidonHashOut,
        innocence_wrap_proof: &ProofWithPublicInputs<F, C, D>,
    ) -> anyhow::Result<()> {
        self.innocence_wrap_circuit
            .verify(innocence_wrap_proof)
            .map_err(|e| anyhow::anyhow!("Failed to verify innocence wrap circuit: {}", e))?;
        let pis = InnocenceWrapPublicInputs::from_pis(&innocence_wrap_proof.public_inputs);
        let use_allow_list = allow_list.is_some();
        let allow_list_tree = AddressListTree::new(allow_list.unwrap_or_default()).unwrap();
        let deny_list_tree = AddressListTree::new(deny_list).unwrap();
        let allow_list_tree_root = allow_list_tree.get_root();
        let deny_list_tree_root = deny_list_tree.get_root();

        if pis.use_allow_list != use_allow_list {
            bail!("use_allow_list is not equal to the expected value");
        }
        if pis.allow_list_tree_root != allow_list_tree_root {
            bail!("allow_list_tree_root is not equal to the expected value");
        }
        if pis.deny_list_tree_root != deny_list_tree_root {
            bail!("deny_list_tree_root is not equal to the expected value");
        }
        if pis.private_commitment != private_commitment {
            bail!("private_commitment is not equal to the expected value");
        }
        Ok(())
    }
}
