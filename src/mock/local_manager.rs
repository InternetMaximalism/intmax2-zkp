use hashbrown::HashMap;
use rand::Rng;

use crate::{
    circuits::balance::balance_pis::BalancePublicInputs,
    common::{
        hash::get_pubkey_salt_hash,
        insufficient_flags::InsufficientFlags,
        private_state::PrivateState,
        public_state::PublicState,
        salt::Salt,
        signature::key_set::KeySet,
        transfer::Transfer,
        trees::{
            asset_tree::{AssetLeaf, AssetTree},
            deposit_tree::DepositLeaf,
            nullifier_tree::NullifierTree,
            transfer_tree::TransferTree,
        },
        tx::Tx,
        witness::{
            deposit_witness::{DepositCase, DepositWitness},
            private_state_transition_witness::PrivateStateTransitionWitness,
            receive_deposit_witness::ReceiveDepositWitness,
            send_witness::SendWitness,
            transfer_witness::TransferWitness,
            tx_witness::TxWitness,
        },
    },
    constants::{ASSET_TREE_HEIGHT, NUM_TRANSFERS_IN_TX, TRANSFER_TREE_HEIGHT},
    ethereum_types::{bytes32::Bytes32, u256::U256, u32limb_trait::U32LimbTrait},
    mock::tx_request::TxRequest,
    utils::poseidon_hash_out::PoseidonHashOut,
};

use super::block_builder::MockBlockBuilder;

#[derive(Debug, Clone)]
pub struct LocalManager {
    pub key_set: KeySet,
    pub asset_tree: AssetTree,
    pub nullifier_tree: NullifierTree,
    pub nonce: u32,
    pub salt: Salt,
    pub public_state: PublicState,
    pub send_witnesses: Vec<SendWitness>,
    pub deposit_cases: Vec<DepositCase>,
    pub transfer_witnesses: HashMap<u32, Vec<TransferWitness>>,
}

impl LocalManager {
    /// Create a new LocalManager with random key set, asset tree, nullifier tree, nonce, and salt.
    pub fn new_rand<R: Rng>(rng: &mut R) -> Self {
        Self {
            key_set: KeySet::rand(rng),
            asset_tree: AssetTree::new(ASSET_TREE_HEIGHT),
            nullifier_tree: NullifierTree::new(),
            nonce: 0,
            salt: Salt::default(),
            public_state: PublicState::genesis(),
            send_witnesses: Vec::new(),
            deposit_cases: Vec::new(),
            transfer_witnesses: HashMap::new(),
        }
    }

    pub fn get_private_state(&self) -> PrivateState {
        PrivateState {
            asset_tree_root: self.asset_tree.get_root(),
            nullifier_tree_root: self.nullifier_tree.get_root(),
            nonce: self.nonce,
            salt: self.salt,
        }
    }

    pub fn get_last_send_witness(&self) -> Option<SendWitness> {
        self.send_witnesses.last().cloned()
    }

    /// Get all block numbers that contain transactions sent by this manager.
    pub fn get_all_block_numbers(&self) -> Vec<u32> {
        self.send_witnesses
            .iter()
            .map(|w| w.get_included_block_number())
            .collect()
    }

    pub fn get_send_witness(&self, block_number: u32) -> Option<SendWitness> {
        self.send_witnesses
            .iter()
            .find(|w| w.get_included_block_number() == block_number)
            .cloned()
    }

    pub fn get_transfer_witnesses(&self, block_number: u32) -> Option<Vec<TransferWitness>> {
        self.transfer_witnesses.get(&block_number).cloned()
    }

    pub fn get_pubkey(&self) -> U256<u32> {
        self.key_set.pubkey_x
    }

    pub fn get_balance_pis(&self) -> BalancePublicInputs {
        let last_send_witness = self.get_last_send_witness();

        BalancePublicInputs {
            pubkey: self.key_set.pubkey_x,
            private_commitment: self.get_private_state().commitment(),
            last_tx_hash: last_send_witness
                .clone()
                .map_or(PoseidonHashOut::default(), |send_witness| {
                    send_witness.get_next_last_tx().last_tx_hash
                }),
            last_tx_insufficient_flags: last_send_witness
                .map_or(InsufficientFlags::default(), |send_witness| {
                    send_witness.get_next_last_tx().last_tx_insufficient_flags
                }),
            public_state: self.public_state.clone(),
        }
    }

    /// Fund the account with the given amount.
    /// This is only used for testing.
    pub fn forced_fund(&mut self, token_index: u32, amount: U256<u32>) {
        self.asset_tree.update(
            token_index as usize,
            AssetLeaf {
                is_insufficient: false,
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
    ) -> (TxWitness, Vec<TransferWitness>) {
        assert!(transfers.len() < NUM_TRANSFERS_IN_TX);
        let mut transfers = transfers.to_vec();
        transfers.resize(NUM_TRANSFERS_IN_TX, Transfer::default());

        let mut transfer_tree = TransferTree::new(TRANSFER_TREE_HEIGHT);
        for transfer in &transfers {
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
        let tx_tree = &block_builder.aux_info.get(&block_number).unwrap().tx_tree;
        let tx_index = tx_tree.get_tx_index(&tx).unwrap();
        let tx_merkle_proof = tx_tree.prove(tx_index);
        let tx_witness = TxWitness {
            validity_witness,
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

        (tx_witness, transfer_witnesses)
    }

    pub fn deposit<R: Rng>(
        &mut self,
        rng: &mut R,
        block_builder: &mut MockBlockBuilder,
        token_index: u32,
        amount: U256<u32>,
    ) {
        let pubkey = self.get_pubkey();
        let salt = Salt::rand(rng);
        let pubkey_salt_hash = get_pubkey_salt_hash(pubkey, salt);

        let deposit = DepositLeaf {
            pubkey_salt_hash,
            token_index,
            amount,
        };
        let deposit_index = block_builder.deposit(&deposit);

        let deposit_case = DepositCase {
            deposit_salt: salt,
            deposit_index,
            deposit,
        };
        self.deposit_cases.push(deposit_case);
    }

    pub fn generate_deposit_witness<R: Rng>(
        &mut self,
        rng: &mut R,
        block_builder: &MockBlockBuilder,
    ) -> ReceiveDepositWitness {
        let deposit_case = self.deposit_cases.remove(0);
        let deposit_merkle_proof = block_builder.deposit_tree.prove(deposit_case.deposit_index);
        let deposit_witness = DepositWitness {
            deposit_merkle_proof,
            deposit_salt: deposit_case.deposit_salt,
            deposit_index: deposit_case.deposit_index,
            deposit: deposit_case.deposit,
        };
        let deposit = deposit_witness.deposit.clone();
        let nullifier: Bytes32<u32> = deposit.poseidon_hash().into();
        let private_witness =
            self.generate_witness_for_receive(rng, deposit.token_index, deposit.amount, nullifier);
        ReceiveDepositWitness {
            deposit_witness,
            private_witness,
        }
    }

    fn update(
        &mut self,
        new_salt: Salt,
        tx_witness: &TxWitness,
        transfer_witness: &[TransferWitness],
    ) -> SendWitness {
        let prev_private_state = self.get_private_state();
        let prev_balance_pis = self.get_balance_pis();

        assert_eq!(tx_witness.tx.nonce, self.nonce);
        self.nonce += 1;
        self.salt = new_salt;
        self.public_state = tx_witness.validity_witness.to_validity_pis().public_state;
        let transfers = transfer_witness
            .iter()
            .map(|w| w.transfer.clone())
            .collect::<Vec<_>>();
        let mut asset_merkle_proofs = vec![];
        let mut prev_balances = vec![];
        let mut insufficient_bits = vec![];
        for transfer in &transfers {
            let prev_balance = self.asset_tree.get_leaf(transfer.token_index as usize);
            let proof = self.asset_tree.prove(transfer.token_index as usize);
            let new_balance = prev_balance.sub(transfer.amount);
            self.asset_tree
                .update(transfer.token_index as usize, new_balance);
            prev_balances.push(prev_balance);
            asset_merkle_proofs.push(proof);
            insufficient_bits.push(new_balance.is_insufficient);
        }
        let insufficient_flags = InsufficientFlags::from_bits_le(&insufficient_bits);
        let send_witness = SendWitness {
            prev_balance_pis,
            prev_private_state,
            prev_balances,
            asset_merkle_proofs,
            insufficient_flags,
            transfers,
            tx_witness: tx_witness.clone(),
            new_salt,
        };
        self.send_witnesses.push(send_witness.clone());
        self.transfer_witnesses.insert(
            send_witness.get_included_block_number(),
            transfer_witness.to_vec(),
        );
        send_witness
    }

    pub fn send_tx_and_update<R: Rng>(
        &mut self,
        rng: &mut R,
        block_builder: &mut MockBlockBuilder,
        transfers: &[Transfer],
    ) -> SendWitness {
        let (tx_witness, transfer_witnesses) = self.send_tx(block_builder, transfers);
        let new_salt = Salt::rand(rng);
        self.update(new_salt, &tx_witness, &transfer_witnesses)
    }

    pub fn generate_witness_for_receive<R: Rng>(
        &self,
        rng: &mut R,
        token_index: u32,
        amount: U256<u32>,
        nullifier: Bytes32<u32>,
    ) -> PrivateStateTransitionWitness {
        let new_salt = Salt::rand(rng);
        let mut asset_tree = self.asset_tree.clone();
        let mut nullifier_tree = self.nullifier_tree.clone();
        let prev_private_state = self.get_private_state();

        let prev_asset_leaf = asset_tree.get_leaf(token_index as usize);
        let asset_merkle_proof = asset_tree.prove(token_index as usize);
        let new_asset_leaf = prev_asset_leaf.add(amount);
        asset_tree.update(token_index as usize, new_asset_leaf);
        let nullifier_proof = nullifier_tree
            .prove_and_insert(nullifier)
            .expect("nullifier already exists");
        PrivateStateTransitionWitness {
            token_index,
            amount,
            nullifier,
            new_salt,
            prev_private_state,
            nullifier_proof,
            prev_asset_leaf,
            asset_merkle_proof,
        }
    }

    pub fn generate_witness_for_receive_transfer<R: Rng>(
        &self,
        rng: &mut R,
        transfer: &Transfer,
    ) -> PrivateStateTransitionWitness {
        assert_eq!(
            transfer.recipient.to_pubkey().unwrap(),
            self.get_pubkey(),
            "recipient pubkey"
        );
        let nullifier: Bytes32<u32> = transfer.commitment().into();
        self.generate_witness_for_receive(rng, transfer.token_index, transfer.amount, nullifier)
    }

    pub fn update_on_receive(&mut self, witness: &PrivateStateTransitionWitness) {
        // verify proofs
        let new_nullifier_tree_root = witness
            .nullifier_proof
            .get_new_root(self.nullifier_tree.get_root(), witness.nullifier)
            .expect("Invalid nullifier proof");
        witness
            .asset_merkle_proof
            .verify(
                &witness.prev_asset_leaf,
                witness.token_index as usize,
                self.asset_tree.get_root(),
            )
            .expect("Invalid asset merkle proof");
        let new_asset_leaf = witness.prev_asset_leaf.add(witness.amount);
        let new_asset_tree_root = witness
            .asset_merkle_proof
            .get_root(&new_asset_leaf, witness.token_index as usize);
        self.nullifier_tree
            .prove_and_insert(witness.nullifier)
            .unwrap();
        self.asset_tree
            .update(witness.token_index as usize, new_asset_leaf);
        assert_eq!(self.nullifier_tree.get_root(), new_nullifier_tree_root);
        assert_eq!(self.asset_tree.get_root(), new_asset_tree_root);
        self.salt = witness.new_salt;
    }
}

#[cfg(test)]
mod tests {
    use plonky2::{
        field::goldilocks_field::GoldilocksField, plonk::config::PoseidonGoldilocksConfig,
    };

    use crate::{
        circuits::validity::validity_processor::ValidityProcessor,
        common::generic_address::GenericAddress,
    };

    use super::*;

    type F = GoldilocksField;
    const D: usize = 2;
    type C = PoseidonGoldilocksConfig;

    #[test]
    fn local_manager_post_two() {
        let mut rng = rand::thread_rng();
        let mut local_manager = LocalManager::new_rand(&mut rng);
        let mut block_builder = MockBlockBuilder::new();

        local_manager.forced_fund(0, U256::<u32>::rand(&mut rng));
        let transfer = Transfer {
            recipient: GenericAddress::rand_pubkey(&mut rng),
            token_index: 0,
            amount: U256::<u32>::rand_small(&mut rng),
            salt: Salt::rand(&mut rng),
        };
        // post register block

        let _transfer_witnesses1 = local_manager.send_tx(&mut block_builder, &[transfer]);
        local_manager.nonce += 1;
        // post account id block
        let _transfer_witnesses2 = local_manager.send_tx(&mut block_builder, &[transfer]);
    }

    #[test]
    fn test_prove_local_manager() {
        let mut rng = rand::thread_rng();
        let mut local_manager = LocalManager::new_rand(&mut rng);
        let mut block_builder = MockBlockBuilder::new();

        local_manager.forced_fund(0, U256::<u32>::rand(&mut rng));
        let transfer = Transfer {
            recipient: GenericAddress::rand_pubkey(&mut rng),
            token_index: 0,
            amount: U256::<u32>::rand_small(&mut rng),
            salt: Salt::rand(&mut rng),
        };

        for block_number in 1..3 {
            let send_witness =
                local_manager.send_tx_and_update(&mut rng, &mut block_builder, &[transfer]);
            assert_eq!(send_witness.get_included_block_number(), block_number);
        }

        let validity_processor = ValidityProcessor::<F, C, D>::new();
        let mut prev_proof = None;
        for block_number in 1..3 {
            let aux_info = block_builder.aux_info.get(&block_number).unwrap();
            prev_proof = validity_processor
                .prove(&prev_proof, &aux_info.validity_witness)
                .map_or(None, Some);
        }
    }
}
