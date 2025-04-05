use std::collections::HashMap;

use anyhow::ensure;
use plonky2::{
    field::goldilocks_field::GoldilocksField,
    plonk::{config::PoseidonGoldilocksConfig, proof::ProofWithPublicInputs},
};

use crate::{
    circuits::validity::validity_pis::ValidityPublicInputs,
    common::{
        block::Block,
        block_builder::{construct_signature, SenderWithSignature},
        private_state::FullPrivateState,
        salt::Salt,
        signature::{
            block_sign_payload::BlockSignPayload, key_set::KeySet, utils::get_pubkey_hash,
        },
        transfer::Transfer,
        trees::{
            account_tree::AccountTree, block_hash_tree::BlockHashTree, deposit_tree::DepositTree,
            transfer_tree::TransferTree, tx_tree::TxTree,
        },
        tx::Tx,
        witness::{
            full_block::FullBlock, spent_witness::SpentWitness, transfer_witness::TransferWitness,
            tx_witness::TxWitness, update_witness::UpdateWitness,
            validity_witness::ValidityWitness,
        },
    },
    constants::{NUM_SENDERS_IN_BLOCK, NUM_TRANSFERS_IN_TX, TRANSFER_TREE_HEIGHT, TX_TREE_HEIGHT},
    ethereum_types::{
        account_id::{AccountId, AccountIdPacked},
        address::Address,
        bytes32::Bytes32,
        u256::U256,
    },
};

type F = GoldilocksField;
type C = PoseidonGoldilocksConfig;
const D: usize = 2;

#[derive(Debug, Clone)]
pub struct MockTxRequest {
    pub tx: Tx,
    pub sender_key: KeySet,
    pub will_return_sig: bool,
}

// Receives an array of tuples consisting of tx and its sender's address, generates a block,
// and constructs the validity witness of that block.
#[allow(clippy::too_many_arguments)]
pub fn construct_validity_and_tx_witness(
    prev_validity_pis: ValidityPublicInputs,
    account_tree: &mut AccountTree,
    block_tree: &mut BlockHashTree,
    deposit_tree: &DepositTree,
    is_registration_block: bool,
    expiry: u64,
    block_builder_address: Address,
    block_builder_nonce: u32,
    tx_requests: &[MockTxRequest],
    timestamp: u64,
) -> anyhow::Result<(ValidityWitness, Vec<TxWitness>)> {
    let mut normalized_requests = tx_requests.to_vec();
    normalized_requests.sort_by(|a, b| b.sender_key.pubkey.cmp(&a.sender_key.pubkey));
    normalized_requests.resize(
        NUM_SENDERS_IN_BLOCK,
        MockTxRequest {
            tx: Tx::default(),
            sender_key: KeySet::dummy(),
            will_return_sig: false,
        },
    );

    let pubkeys = normalized_requests
        .iter()
        .map(|r| r.sender_key.pubkey)
        .collect::<Vec<_>>();
    let pubkey_hash = get_pubkey_hash(&pubkeys);

    let mut tx_tree = TxTree::new(TX_TREE_HEIGHT);
    for r in normalized_requests.iter() {
        tx_tree.push(r.tx);
    }
    let tx_tree_root: Bytes32 = tx_tree.get_root().into();

    let mut tx_info = Vec::new();
    for r in tx_requests.iter() {
        let tx_index = normalized_requests
            .iter()
            .position(|nr| nr.sender_key.pubkey == r.sender_key.pubkey)
            .unwrap() as u32;
        let tx_merkle_proof = tx_tree.prove(tx_index as u64);
        tx_info.push((r.tx, tx_index, tx_merkle_proof));
    }

    // construct block
    let block_sign_payload = BlockSignPayload {
        is_registration_block,
        tx_tree_root,
        expiry: expiry.into(),
        block_builder_address,
        block_builder_nonce,
    };

    // get account ids
    let account_ids = if is_registration_block {
        // assertion
        for r in normalized_requests.iter() {
            let account_id = account_tree.index(r.sender_key.pubkey);
            ensure!(
                account_id.is_none() || r.sender_key.pubkey.is_dummy_pubkey(),
                "account already exists but registration block"
            );
        }
        None
    } else {
        let mut account_ids = Vec::new();
        for r in normalized_requests.iter() {
            let account_id = account_tree
                .index(r.sender_key.pubkey)
                .expect("account not found");
            account_ids.push(AccountId(account_id));
        }
        Some(AccountIdPacked::pack(&account_ids))
    };
    let account_id_hash = account_ids.map_or(Bytes32::default(), |ids| ids.hash());

    let sender_with_signatures = normalized_requests
        .iter()
        .map(|r| {
            let signature = if r.will_return_sig {
                Some(block_sign_payload.sign(r.sender_key.privkey, pubkey_hash))
            } else {
                None
            };
            SenderWithSignature {
                sender: r.sender_key.pubkey,
                signature,
            }
        })
        .collect::<Vec<_>>();
    let signature = construct_signature(
        &block_sign_payload,
        pubkey_hash,
        account_id_hash,
        &sender_with_signatures,
    );

    let block = Block {
        prev_block_hash: prev_validity_pis.public_state.block_hash,
        deposit_tree_root: deposit_tree.get_root(),
        signature_hash: signature.hash(),
        timestamp,
        block_number: prev_validity_pis.public_state.block_number + 1,
    };
    let trimmed_pubkeys = pubkeys
        .into_iter()
        .filter(|pubkey| !pubkey.is_dummy_pubkey())
        .collect::<Vec<_>>();
    let trimmed_account_ids = account_ids.map(|ids| ids.to_trimmed_bytes());
    let full_block = FullBlock {
        block: block.clone(),
        signature,
        pubkeys: if is_registration_block {
            Some(trimmed_pubkeys)
        } else {
            None
        },
        account_ids: trimmed_account_ids,
    };
    let block_witness = full_block.to_block_witness(account_tree, block_tree)?;
    let validity_witness = block_witness.update_trees(account_tree, block_tree)?;
    let validity_pis = validity_witness.to_validity_pis()?;
    let sender_leaves = block_witness.get_sender_tree().leaves();

    let tx_witnesses = tx_info
        .iter()
        .map(|(tx, index, proof)| TxWitness {
            validity_pis: validity_pis.clone(),
            sender_leaves: sender_leaves.clone(),
            tx: *tx,
            tx_index: *index,
            tx_merkle_proof: proof.clone(),
        })
        .collect::<Vec<_>>();
    Ok((validity_witness, tx_witnesses))
}

pub fn construct_spent_and_transfer_witness(
    full_private_state: &mut FullPrivateState,
    transfers: &[Transfer],
) -> anyhow::Result<(SpentWitness, Vec<TransferWitness>)> {
    assert!(transfers.len() < NUM_TRANSFERS_IN_TX);
    let mut transfers = transfers.to_vec();
    transfers.resize(NUM_TRANSFERS_IN_TX, Transfer::default());

    let mut transfer_tree = TransferTree::new(TRANSFER_TREE_HEIGHT);
    for transfer in &transfers {
        transfer_tree.push(*transfer);
    }
    let tx = Tx {
        transfer_tree_root: transfer_tree.get_root(),
        nonce: full_private_state.nonce,
    };

    let mut transfer_witnesses = Vec::new();
    for (index, transfer) in transfers.iter().enumerate() {
        let transfer_merkle_proof = transfer_tree.prove(index as u64);
        transfer_witnesses.push(TransferWitness {
            tx,
            transfer: *transfer,
            transfer_index: index as u32,
            transfer_merkle_proof,
        });
    }

    let mut rng = rand::thread_rng();
    let new_private_state_salt = Salt::rand(&mut rng);
    let spent_witness = SpentWitness::new(
        &full_private_state.asset_tree,
        &full_private_state.to_private_state(),
        &transfers,
        tx,
        new_private_state_salt,
    )?;
    spent_witness.update_private_state(full_private_state)?;
    Ok((spent_witness, transfer_witnesses))
}

pub fn construct_update_witness(
    historical_account_trees: &HashMap<u32, AccountTree>,
    historical_block_trees: &HashMap<u32, BlockHashTree>,
    historical_validity_proofs: &HashMap<u32, ProofWithPublicInputs<F, C, D>>,
    pubkey: U256,
    root_block_number: u32,
    leaf_block_number: u32,
    is_prev_account_tree: bool,
) -> anyhow::Result<UpdateWitness<F, C, D>> {
    let block_merkle_proof = historical_block_trees
        .get(&root_block_number)
        .ok_or(anyhow::anyhow!("block tree not found"))?
        .prove(leaf_block_number as u64);
    let validity_proof = historical_validity_proofs
        .get(&root_block_number)
        .ok_or(anyhow::anyhow!("validity proof not found"))?;
    let account_tree_block_number = if is_prev_account_tree {
        root_block_number - 1
    } else {
        root_block_number
    };
    let account_tree = historical_account_trees
        .get(&account_tree_block_number)
        .ok_or(anyhow::anyhow!("account tree not found"))?;
    let account_membership_proof = account_tree.prove_membership(pubkey);

    let update_witness = UpdateWitness {
        is_prev_account_tree,
        validity_proof: validity_proof.clone(),
        block_merkle_proof,
        account_membership_proof,
    };

    Ok(update_witness)
}

#[cfg(test)]
mod tests {
    use crate::{
        circuits::validity::validity_pis::ValidityPublicInputs,
        common::{
            signature::key_set::KeySet,
            trees::{
                account_tree::AccountTree, block_hash_tree::BlockHashTree,
                deposit_tree::DepositTree,
            },
            tx::Tx,
        },
        constants::DEPOSIT_TREE_HEIGHT,
        ethereum_types::{address::Address, u32limb_trait::U32LimbTrait},
    };

    use super::MockTxRequest;

    #[test]
    fn test_construct_validity_witness() {
        let mut rng = rand::thread_rng();
        let block_builder_address = Address::rand(&mut rng);
        let mut account_tree = AccountTree::initialize();
        let mut block_tree = BlockHashTree::initialize();
        let deposit_tree = DepositTree::new(DEPOSIT_TREE_HEIGHT);

        let mut prev_validity_pis = ValidityPublicInputs::genesis();
        for _ in 0..10 {
            let sender_key = KeySet::rand(&mut rng);
            let tx = Tx::rand(&mut rng);
            let tx_requests = vec![MockTxRequest {
                tx,
                sender_key,
                will_return_sig: true,
            }];
            let (validity_witness, _) = super::construct_validity_and_tx_witness(
                prev_validity_pis.clone(),
                &mut account_tree,
                &mut block_tree,
                &deposit_tree,
                true,
                0,
                block_builder_address,
                0,
                &tx_requests,
                0,
            )
            .unwrap();
            prev_validity_pis = validity_witness.to_validity_pis().unwrap();
        }
    }
}
