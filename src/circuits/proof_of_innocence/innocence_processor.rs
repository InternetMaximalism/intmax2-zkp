use std::collections::HashMap;

use plonky2::{
    field::extension::Extendable,
    hash::hash_types::RichField,
    plonk::{
        config::{AlgebraicHasher, GenericConfig},
        proof::ProofWithPublicInputs,
    },
};

use super::error::InnocenceError;

use crate::{
    circuits::proof_of_innocence::{
        address_list_tree::AddressListTree, innocence_inner_target::InnocenceInnerValue,
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

impl<F, C, const D: usize> Default for InnocenceProcessor<F, C, D>
where
    F: RichField + Extendable<D>,
    C: GenericConfig<D, F = F> + 'static,
    C::Hasher: AlgebraicHasher<F>,
{
    fn default() -> Self {
        Self::new()
    }
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
    ) -> Result<ProofWithPublicInputs<F, C, D>, InnocenceError> {
        let mut nullifier_map = HashMap::<Bytes32, Deposit>::new();
        for deposit in deposits {
            nullifier_map.insert(deposit.poseidon_hash().into(), deposit.clone());
        }

        let mut sorted_deposits = Vec::new();
        for nullifier in full_private_state.nullifier_tree.nullifiers() {
            if !nullifier_map.contains_key(&nullifier) {
                return Err(InnocenceError::DepositNotFound(nullifier));
            } else {
                sorted_deposits.push(nullifier_map.get(&nullifier).unwrap());
            }
        }
        if sorted_deposits.is_empty() {
            return Err(InnocenceError::NoDeposits);
        }
        // verification
        let use_allow_list = allow_list.is_some();
        {
            let mut nullifier_tree = NullifierTree::new();
            for deposit in &sorted_deposits {
                if use_allow_list && !allow_list.unwrap().contains(&deposit.depositor) {
                    return Err(InnocenceError::DepositorNotInAllowList(deposit.depositor));
                }
                if deny_list.contains(&deposit.depositor) {
                    return Err(InnocenceError::DepositorInDenyList(deposit.depositor));
                }
                let nullifier: Bytes32 = deposit.poseidon_hash().into();
                nullifier_tree
                    .prove_and_insert(nullifier)
                    .map_err(|e| InnocenceError::NullifierInsertionFailed(e.to_string()))?;
            }
            if nullifier_tree.get_root() != full_private_state.nullifier_tree.get_root() {
                return Err(InnocenceError::InvalidNullifierTreeRoot {
                    expected: nullifier_tree.get_root().to_string(),
                    actual: full_private_state.nullifier_tree.get_root().to_string(),
                });
            }
        }

        let allow_list_tree = AddressListTree::new(allow_list.unwrap_or_default())
            .map_err(|e| InnocenceError::AllowListTreeCreationFailed(e.to_string()))?;
        let deny_list_tree = AddressListTree::new(deny_list)
            .map_err(|e| InnocenceError::DenyListTreeCreationFailed(e.to_string()))?;
        let allow_list_tree_root = allow_list_tree.get_root();
        let deny_list_tree_root = deny_list_tree.get_root();

        let mut nullifier_tree = NullifierTree::new();
        let mut innocence_proof = None;
        for deposit in sorted_deposits {
            let prev_nullifier_tree_root = nullifier_tree.get_root();
            let nullifier_proof = nullifier_tree
                .prove_and_insert(deposit.poseidon_hash().into())
                .map_err(|e| InnocenceError::NullifierInsertionFailed(e.to_string()))?;
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
            .map_err(|e| InnocenceError::InnocenceInnerValueCreationFailed(e.to_string()))?;
            innocence_proof = Some(
                self.innocence_circuit
                    .prove(&value, &innocence_proof)
                    .map_err(|e| InnocenceError::InnocenceCircuitProofFailed(e.to_string()))?,
            );
        }

        let private_state = full_private_state.to_private_state();
        let innocence_wrap_proof = self
            .innocence_wrap_circuit
            .prove(innocence_proof.as_ref().unwrap(), private_state)
            .map_err(|e| InnocenceError::InnocenceWrapCircuitProofFailed(e.to_string()))?;

        Ok(innocence_wrap_proof)
    }

    pub fn verify(
        &self,
        allow_list: Option<&[Address]>,
        deny_list: &[Address],
        private_commitment: PoseidonHashOut,
        innocence_wrap_proof: &ProofWithPublicInputs<F, C, D>,
    ) -> Result<(), InnocenceError> {
        self.innocence_wrap_circuit
            .verify(innocence_wrap_proof)
            .map_err(|e| InnocenceError::InnocenceWrapCircuitVerificationFailed(e.to_string()))?;
        let pis = InnocenceWrapPublicInputs::from_pis(&innocence_wrap_proof.public_inputs);
        let use_allow_list = allow_list.is_some();
        let allow_list_tree = AddressListTree::new(allow_list.unwrap_or_default())
            .map_err(|e| InnocenceError::AllowListTreeCreationFailed(e.to_string()))?;
        let deny_list_tree = AddressListTree::new(deny_list)
            .map_err(|e| InnocenceError::DenyListTreeCreationFailed(e.to_string()))?;
        let allow_list_tree_root = allow_list_tree.get_root();
        let deny_list_tree_root = deny_list_tree.get_root();

        if pis.use_allow_list != use_allow_list {
            return Err(InnocenceError::UseAllowListMismatch {
                expected: use_allow_list,
                actual: pis.use_allow_list,
            });
        }
        if pis.allow_list_tree_root != allow_list_tree_root {
            return Err(InnocenceError::AllowListTreeRootMismatch {
                expected: allow_list_tree_root.to_string(),
                actual: pis.allow_list_tree_root.to_string(),
            });
        }
        if pis.deny_list_tree_root != deny_list_tree_root {
            return Err(InnocenceError::DenyListTreeRootMismatch {
                expected: deny_list_tree_root.to_string(),
                actual: pis.deny_list_tree_root.to_string(),
            });
        }
        if pis.private_commitment != private_commitment {
            return Err(InnocenceError::PrivateCommitmentMismatch {
                expected: private_commitment.to_string(),
                actual: pis.private_commitment.to_string(),
            });
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use plonky2::{
        field::goldilocks_field::GoldilocksField, plonk::config::PoseidonGoldilocksConfig,
    };
    use rand::seq::SliceRandom;

    use crate::{
        common::{
            deposit::Deposit,
            private_state::FullPrivateState,
            salt::Salt,
            trees::{asset_tree::AssetTree, nullifier_tree::NullifierTree},
        },
        constants::ASSET_TREE_HEIGHT,
        ethereum_types::{address::Address, u32limb_trait::U32LimbTrait},
        utils::poseidon_hash_out::PoseidonHashOut,
    };

    use super::InnocenceProcessor;

    type F = GoldilocksField;
    type C = PoseidonGoldilocksConfig;
    const D: usize = 2;

    #[test]
    fn test_innocence_processor_use_allowlist() {
        let mut rng = rand::thread_rng();
        let deposits = [(); 10].map(|_| Deposit::rand(&mut rng));
        let mut allow_list = deposits
            .iter()
            .map(|d| d.depositor)
            .chain([(); 10].map(|_| Address::rand(&mut rng))) // add some random addresses
            .collect::<Vec<_>>();
        allow_list.shuffle(&mut rng);
        let deny_list = [(); 5].map(|_| Address::rand(&mut rng)); // some random addresses

        let mut nullifier_tree = NullifierTree::new();
        for deposit in &deposits {
            nullifier_tree
                .prove_and_insert(deposit.poseidon_hash().into())
                .unwrap();
        }
        let full_private_state = FullPrivateState {
            asset_tree: AssetTree::new(ASSET_TREE_HEIGHT),
            nullifier_tree,
            prev_private_commitment: PoseidonHashOut::rand(&mut rng),
            nonce: 0,
            salt: Salt::rand(&mut rng),
        };

        let mut shuffled_deposits = deposits.to_vec();
        shuffled_deposits.shuffle(&mut rng);

        let processor = InnocenceProcessor::<F, C, D>::new();
        let proof = processor
            .prove(
                Some(&allow_list),
                &deny_list,
                &full_private_state,
                &shuffled_deposits,
            )
            .unwrap();

        let private_commitment = full_private_state.to_private_state().commitment();

        processor
            .verify(Some(&allow_list), &deny_list, private_commitment, &proof)
            .unwrap();
    }

    #[test]
    fn test_innocence_processor_not_use_allowlist() {
        let mut rng = rand::thread_rng();
        let deposits = [(); 10].map(|_| Deposit::rand(&mut rng));
        let deny_list = [(); 5].map(|_| Address::rand(&mut rng)); // some random addresses

        let mut nullifier_tree = NullifierTree::new();
        for deposit in &deposits {
            nullifier_tree
                .prove_and_insert(deposit.poseidon_hash().into())
                .unwrap();
        }
        let full_private_state = FullPrivateState {
            asset_tree: AssetTree::new(ASSET_TREE_HEIGHT),
            nullifier_tree,
            prev_private_commitment: PoseidonHashOut::rand(&mut rng),
            nonce: 0,
            salt: Salt::rand(&mut rng),
        };

        let mut suffled_deposits = deposits.to_vec();
        suffled_deposits.shuffle(&mut rng);

        let processor = InnocenceProcessor::<F, C, D>::new();
        let proof = processor
            .prove(None, &deny_list, &full_private_state, &suffled_deposits)
            .unwrap();

        let private_commitment = full_private_state.to_private_state().commitment();

        processor
            .verify(None, &deny_list, private_commitment, &proof)
            .unwrap();
    }
}
