use serde::{Deserialize, Serialize};

use crate::{
    common::{
        block::Block, signature::SignatureContent, trees::account_tree::AccountTree,
        witness::block_witness::BlockWitness,
    },
    ethereum_types::{bytes32::Bytes32, u256::U256},
};

// A subset of `BlockWitness` that only contains the information to be submitted to the contract
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct FullBlock {
    pub block: Block,
    pub signature: SignatureContent,
    pub pubkeys: Option<Vec<U256>>,   // pubkeys trimmed dummy pubkeys
    pub account_ids: Option<Vec<u8>>, // account ids trimmed dummy pubkeys
    pub block_hash: Bytes32,
}

impl FullBlock {
    pub fn to_block_witness(&self, account_tree: &AccountTree) -> BlockWitness {
        let is_registration_block = self.signature.is_registration_block;

        // let pubkey_hash = get_pubkey_hash(&pubkeys);

        // // account lookup
        // let (account_id_packed, account_merkle_proofs, account_membership_proofs) =
        //     if is_registration_block {
        //         let mut account_membership_proofs = Vec::new();
        //         for pubkey in pubkeys.iter() {
        //             let is_dummy = pubkey.is_dummy_pubkey();
        //             assert!(
        //                 self.account_tree.index(*pubkey).is_none() || is_dummy,
        //                 "account already exists"
        //             );
        //             let proof = self.account_tree.prove_membership(*pubkey);
        //             account_membership_proofs.push(proof);
        //         }
        //         (None, None, Some(account_membership_proofs))
        //     } else {
        //         let mut account_ids = Vec::new();
        //         let mut account_merkle_proofs = Vec::new();
        //         for pubkey in pubkeys.iter() {
        //             let account_id = self.account_tree.index(*pubkey).expect("account not found");
        //             let proof = self.account_tree.prove_inclusion(account_id);
        //             account_ids.push(account_id);
        //             account_merkle_proofs.push(proof);
        //         }
        //         let account_id_packed = AccountIdPacked::pack(&account_ids);
        //         (Some(account_id_packed), Some(account_merkle_proofs), None)
        //     };
        // let account_id_hash = account_id_packed.map(|x| x.hash()).unwrap_or_default();

        // // construct tx tree root
        // let mut tx_tree = TxTree::new(TX_TREE_HEIGHT);
        // for tx in txs.iter() {
        //     tx_tree.push(tx.tx.clone());
        // }
        // let tx_tree_root: Bytes32 = tx_tree.get_root().into();

        // let signature = construct_signature(
        //     tx_tree_root,
        //     pubkey_hash,
        //     account_id_hash,
        //     is_registration_block,
        //     &sorted_txs,
        // );
        // let signature_hash = signature.hash();

        // let prev_block = self.last_validity_witness.block_witness.block.clone();
        // let block = Block {
        //     prev_block_hash: prev_block.hash(),
        //     deposit_tree_root: self.deposit_tree.get_root(),
        //     signature_hash,
        //     block_number: prev_block.block_number + 1,
        // };
        // let prev_account_tree_root = self.account_tree.get_root();
        // let prev_block_tree_root = self.block_tree.get_root();
        // let block_witness = BlockWitness {
        //     block,
        //     signature: signature.clone(),
        //     pubkeys: pubkeys.clone(),
        //     prev_account_tree_root,
        //     prev_block_tree_root,
        //     account_id_packed,
        //     account_merkle_proofs,
        //     account_membership_proofs,
        // };

        todo!()
    }
}

// impl BlockWitness {
//     pub fn to_full_block(&self) -> FullBlock {
//         let pubkeys = if self.signature.is_registration_block {
//             let pubkey_trimmed_dummy = self
//                 .pubkeys
//                 .iter()
//                 .filter(|p| !p.is_dummy_pubkey())
//                 .cloned()
//                 .collect::<Vec<_>>();
//             Some(pubkey_trimmed_dummy)
//         } else {
//             None
//         };
//         let account_ids = if self.account_id_packed.is_some() {
//             let account_id_packed = self.account_id_packed.unwrap();
//             let dummy_account_id_start_at = account_id_packed
//                 .unpack()
//                 .iter()
//                 .position(|account_id| *account_id == 1);
//             if dummy_account_id_start_at.is_none() {
//                 Some(account_id_packed.to_hex()) // account ids are full
//             } else {
//                 let hex = account_id_packed.to_hex();
//                 let start_index = dummy_account_id_start_at.unwrap();
//                 //  a little dirty implementation to slice until 5bytes * start_index = 10hex
//                 // *start_index
//                 Some(hex[..2 + 10 * start_index].to_string())
//             }
//         } else {
//             None
//         };

//         FullBlock {
//             block: self.block.clone(),
//             signature: self.signature.clone(),
//             pubkeys,
//             account_ids,
//             block_hash: self.block.hash(),
//         }
//     }
// }
