use anyhow::ensure;

use crate::{
    circuits::validity::validity_pis::ValidityPublicInputs,
    common::{
        block::Block,
        block_builder::{construct_signature, SenderWithSignature},
        signature::{key_set::KeySet, sign::sign_to_tx_root_and_expiry, utils::get_pubkey_hash},
        trees::{
            account_tree::AccountTree, block_hash_tree::BlockHashTree, deposit_tree::DepositTree,
            tx_tree::TxTree,
        },
        tx::Tx,
        witness::{
            full_block::FullBlock, tx_witness::TxWitness, validity_witness::ValidityWitness,
        },
    },
    constants::{NUM_SENDERS_IN_BLOCK, TX_TREE_HEIGHT},
    ethereum_types::{account_id_packed::AccountIdPacked, bytes32::Bytes32},
};

#[derive(Debug, Clone)]
pub struct MockTxRequest {
    pub tx: Tx,
    pub sender_key: KeySet,
    pub will_return_sig: bool,
}

// Receives an array of tuples consisting of tx and its sender's address, generates a block,
// and constructs the validity witness of that block.
pub fn construct_validity_witness(
    prev_validity_pis: ValidityPublicInputs,
    account_tree: &mut AccountTree,
    block_tree: &mut BlockHashTree,
    deposit_tree: &DepositTree,
    is_registration_block: bool,
    tx_requests: &[MockTxRequest],
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
        tx_tree.push(r.tx.clone());
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
    let expiry = 0; // dummy value

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
            account_ids.push(account_id);
        }
        Some(AccountIdPacked::pack(&account_ids))
    };
    let account_id_hash = account_ids.map_or(Bytes32::default(), |ids| ids.hash());

    let sender_with_signatures = normalized_requests
        .iter()
        .map(|r| {
            let signature = if r.will_return_sig {
                Some(
                    sign_to_tx_root_and_expiry(
                        r.sender_key.privkey,
                        tx_tree_root,
                        expiry,
                        pubkey_hash,
                    )
                    .into(),
                )
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
        tx_tree_root,
        expiry,
        pubkey_hash,
        account_id_hash,
        is_registration_block,
        &sender_with_signatures,
    );

    let block = Block {
        prev_block_hash: prev_validity_pis.public_state.block_hash,
        deposit_tree_root: deposit_tree.get_root(),
        signature_hash: signature.hash(),
        timestamp: 0.into(), // dummy value
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
            tx: tx.clone(),
            tx_index: *index,
            tx_merkle_proof: proof.clone(),
        })
        .collect::<Vec<_>>();
    Ok((validity_witness, tx_witnesses))
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
    };

    #[test]
    fn test_construct_validity_witness() {
        let mut account_tree = AccountTree::initialize();
        let mut block_tree = BlockHashTree::initialize();
        let deposit_tree = DepositTree::new(DEPOSIT_TREE_HEIGHT);
        let mut rng = rand::thread_rng();

        let mut prev_validity_pis = ValidityPublicInputs::genesis();
        for _ in 0..10 {
            let sender_key = KeySet::rand(&mut rng);
            let tx = Tx::rand(&mut rng);
            let tx_requests = vec![super::MockTxRequest {
                tx,
                sender_key,
                will_return_sig: true,
            }];
            let (validity_witness, _) = super::construct_validity_witness(
                prev_validity_pis.clone(),
                &mut account_tree,
                &mut block_tree,
                &deposit_tree,
                true,
                &tx_requests,
            )
            .unwrap();
            prev_validity_pis = validity_witness.to_validity_pis().unwrap();
        }
    }
}
