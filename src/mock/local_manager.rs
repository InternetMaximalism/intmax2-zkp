use rand::Rng;

use crate::{
    common::{
        private_state::PrivateState,
        salt::Salt,
        signature::key_set::KeySet,
        transfer::Transfer,
        trees::{
            asset_tree::{AssetLeaf, AssetTree},
            nullifier_tree::NullifierTree,
            transfer_tree::TransferTree,
        },
        tx::Tx,
        witness::{transfer_witness::TransferWitness, tx_witness::TxWitness},
    },
    constants::{ASSET_TREE_HEIGHT, NUM_TRANSFERS_IN_TX, TRANSFER_TREE_HEIGHT},
    ethereum_types::u256::U256,
    mock::tx_request::TxRequest,
};

use super::block_builder::MockBlockBuilder;

#[derive(Debug, Clone)]
pub struct LocalManager {
    pub key_set: KeySet,
    pub asset_tree: AssetTree,
    pub nullifier_tree: NullifierTree,
    pub nonce: u32,
    pub salt: Salt,
    pub sent_tx: Vec<TxWitness>,
}

impl LocalManager {
    /// Create a new LocalManager with random key set, asset tree, nullifier tree, nonce, and salt.
    pub fn new_rand<R: Rng>(rng: &mut R) -> Self {
        Self {
            key_set: KeySet::rand(rng),
            asset_tree: AssetTree::new(ASSET_TREE_HEIGHT),
            nullifier_tree: NullifierTree::new(),
            nonce: 0,
            salt: Salt::rand(rng),
            sent_tx: Vec::new(),
        }
    }

    pub fn private_state(&self) -> PrivateState {
        PrivateState {
            asset_tree_root: self.asset_tree.get_root(),
            nullifier_tree_root: self.nullifier_tree.get_root(),
            nonce: self.nonce,
            salt: self.salt,
        }
    }

    /// Fund the account with the given amount.
    /// This is only used for testing.
    pub fn forced_fund(&mut self, token_index: u32, amount: U256<u32>) {
        self.asset_tree.update(
            token_index as usize,
            AssetLeaf {
                is_sufficient: true,
                amount,
            },
        );
    }

    /// Send a transaction.
    /// Side effect: a block that contains the transaction is posted.
    pub fn send_tx(
        &self,
        block_builder: &mut MockBlockBuilder,
        transfers: &[Transfer],
    ) -> Vec<TransferWitness> {
        assert!(transfers.len() < NUM_TRANSFERS_IN_TX);
        let mut transfer_tree = TransferTree::new(TRANSFER_TREE_HEIGHT);
        for transfer in transfers {
            transfer_tree.push(transfer.clone());
        }
        let tx = Tx {
            transfer_tree_root: transfer_tree.get_root(),
            nonce: self.nonce,
        };
        let validity_witness = block_builder.post_block(
            self.nonce == 0,
            vec![TxRequest {
                tx,
                sender: self.key_set,
                will_return_signature: true,
            }],
        );
        let block_number = validity_witness.block_witness.block.block_number;
        let tx_tree = block_builder.aux_info.tx_trees.get(&block_number).unwrap();
        let tx_index = tx_tree.get_tx_index(&tx).unwrap();
        let tx_merkle_proof = tx_tree.prove(tx_index);
        let tx_witness = TxWitness {
            block_witness: validity_witness.block_witness,
            tx,
            tx_index,
            tx_merkle_proof,
        };
        let transfer_witnesses = transfers
            .iter()
            .enumerate()
            .map(|(transfer_index, transfer)| {
                let transfer_merkle_proof = transfer_tree.prove(transfer_index);
                TransferWitness {
                    tx_witness: tx_witness.clone(),
                    transfer: transfer.clone(),
                    transfer_index,
                    transfer_merkle_proof,
                }
            })
            .collect::<Vec<_>>();
        transfer_witnesses
    }
}

#[cfg(test)]
mod tests {
    use crate::common::generic_address::GenericAddress;

    use super::*;

    #[test]
    fn local_manager() {
        let mut rng = rand::thread_rng();
        let mut local_manager = LocalManager::new_rand(&mut rng);
        let mut block_builder = MockBlockBuilder::new();

        local_manager.forced_fund(0, U256::<u32>::rand(&mut rng));
        let transfer = Transfer {
            recipient: GenericAddress::from_pubkey(KeySet::rand(&mut rng).pubkey_x),
            token_index: 0,
            amount: U256::<u32>::rand_small(&mut rng),
            salt: Salt::rand(&mut rng),
        };
        let _transfer_witnesses = local_manager.send_tx(&mut block_builder, &[transfer]);
    }
}
