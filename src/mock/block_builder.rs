use crate::{
    common::{
        block_builder::{construct_signature, BlockProposal, SenderWithSignature, UserSignature},
        signature::utils::get_pubkey_hash,
        trees::tx_tree::TxTree,
        tx::Tx,
    },
    constants::{NUM_SENDERS_IN_BLOCK, TX_TREE_HEIGHT},
    ethereum_types::{account_id::AccountIdPacked, bytes32::Bytes32, u256::U256},
};
use anyhow::ensure;
use hashbrown::HashMap;
use plonky2::{
    field::extension::Extendable,
    hash::hash_types::RichField,
    plonk::config::{AlgebraicHasher, GenericConfig},
};

use super::{block_validity_prover::BlockValidityProver, contract::MockContract};

pub struct BlockBuilder {
    status: BlockBuilderStatus,

    is_registration_block: Option<bool>,
    senders: HashMap<U256, usize>, // pubkey -> tx request order
    tx_requests: Vec<(U256, Tx)>,

    memo: Option<ProposalMemo>,

    signatures: Vec<UserSignature>,
}

#[derive(Debug, Clone)]
struct ProposalMemo {
    tx_tree_root: Bytes32,
    expiry: u64,
    pubkeys: Vec<U256>, // padded pubkeys
    pubkey_hash: Bytes32,
    proposals: Vec<BlockProposal>,
}

#[derive(Clone, Copy, Debug, PartialEq)]
enum BlockBuilderStatus {
    AcceptingTxs, // accepting tx requests
    Proposing,    // after constructed the block, accepting signatures
}

impl Default for BlockBuilder {
    fn default() -> Self {
        Self::new()
    }
}

impl BlockBuilder {
    pub fn new() -> Self {
        Self {
            status: BlockBuilderStatus::AcceptingTxs,
            is_registration_block: None,
            senders: HashMap::new(),
            tx_requests: Vec::new(),
            memo: None,
            signatures: Vec::new(),
        }
    }

    // Send a tx request by the user.
    pub fn send_tx_request<F, C, const D: usize>(
        &mut self,
        validity_prover: &BlockValidityProver<F, C, D>, // used to get the account id
        pubkey: U256,
        tx: Tx,
    ) -> anyhow::Result<()>
    where
        F: RichField + Extendable<D>,
        C: GenericConfig<D, F = F> + 'static,
        <C as GenericConfig<D>>::Hasher: AlgebraicHasher<F>,
    {
        ensure!(
            self.status == BlockBuilderStatus::AcceptingTxs,
            "not accepting txs"
        );
        ensure!(
            self.tx_requests.len() < NUM_SENDERS_IN_BLOCK,
            "too many txs"
        );

        // duplication check
        ensure!(
            self.senders
                .insert(pubkey, self.tx_requests.len())
                .is_none(),
            "duplicated pubkey in the txs"
        );

        // registration check
        let account_id = validity_prover.get_account_id(pubkey);
        let is_registration_block = account_id.is_none();
        if self.is_registration_block.is_none() {
            self.is_registration_block = Some(is_registration_block);
        } else {
            ensure!(
                self.is_registration_block.unwrap() == is_registration_block,
                "block type mismatch"
            );
        }

        self.tx_requests.push((pubkey, tx));

        Ok(())
    }

    // Construct a block with the given tx requests by the block builder.
    pub fn construct_block(&mut self) -> anyhow::Result<()> {
        ensure!(
            self.status == BlockBuilderStatus::AcceptingTxs,
            "not accepting txs"
        );
        if self.tx_requests.is_empty() {
            // if there is no tx request, it is a non-registration block
            self.is_registration_block = Some(false);
        }

        let mut sorted_txs = self.tx_requests.clone();
        sorted_txs.sort_by(|a, b| b.0.cmp(&a.0));
        sorted_txs.resize(NUM_SENDERS_IN_BLOCK, (U256::dummy_pubkey(), Tx::default()));

        let pubkeys = sorted_txs.iter().map(|tx| tx.0).collect::<Vec<_>>();
        let pubkey_hash = get_pubkey_hash(&pubkeys);

        let mut tx_tree = TxTree::new(TX_TREE_HEIGHT);
        for (_, tx) in sorted_txs.iter() {
            tx_tree.push(*tx);
        }
        let tx_tree_root: Bytes32 = tx_tree.get_root().into();
        let expiry = 0; // dummy value

        let mut proposals = Vec::new();
        for (pubkey, _tx) in self.tx_requests.iter() {
            let tx_index = sorted_txs.iter().position(|(p, _)| p == pubkey).unwrap() as u32;
            let tx_merkle_proof = tx_tree.prove(tx_index as u64);
            proposals.push(BlockProposal {
                expiry,
                tx_tree_root,
                tx_index,
                tx_merkle_proof,
                pubkeys: pubkeys.clone(),
                pubkeys_hash: pubkey_hash,
            });
        }

        let memo = ProposalMemo {
            tx_tree_root,
            expiry,
            pubkeys,
            pubkey_hash,
            proposals,
        };

        self.status = BlockBuilderStatus::Proposing;
        self.memo = Some(memo);

        Ok(())
    }

    // Query the constructed proposal by the user.
    pub fn query_proposal(&self, pubkey: U256) -> anyhow::Result<Option<BlockProposal>> {
        if self.status == BlockBuilderStatus::AcceptingTxs {
            // not constructed yet
            return Ok(None);
        }
        let position = self
            .senders
            .get(&pubkey)
            .ok_or(anyhow::anyhow!("pubkey not found"))?;
        let proposal = &self.memo.as_ref().unwrap().proposals[*position];
        Ok(Some(proposal.clone()))
    }

    // Post the signature by the user.
    pub fn post_signature(&mut self, signature: UserSignature) -> anyhow::Result<()> {
        ensure!(
            self.status == BlockBuilderStatus::Proposing,
            "not proposing"
        );
        self.senders
            .get(&signature.pubkey)
            .ok_or(anyhow::anyhow!("pubkey not found"))?;

        let memo = self.memo.as_ref().unwrap();
        signature
            .verify(memo.tx_tree_root, memo.expiry, memo.pubkey_hash)
            .map_err(|e| {
                anyhow::anyhow!("Invalid signature for pubkey {}: {}", signature.pubkey, e)
            })?;
        self.signatures.push(signature);
        Ok(())
    }

    // Post the block with the given signatures.
    pub fn post_block<F, C, const D: usize>(
        &mut self,
        contract: &mut MockContract,
        validity_prover: &BlockValidityProver<F, C, D>, // used to get the account id
    ) -> anyhow::Result<()>
    where
        F: RichField + Extendable<D>,
        C: GenericConfig<D, F = F> + 'static,
        <C as GenericConfig<D>>::Hasher: AlgebraicHasher<F>,
    {
        ensure!(self.status == BlockBuilderStatus::Proposing);
        let memo = self.memo.clone().unwrap();
        let mut sender_with_signatures = memo
            .pubkeys
            .iter()
            .map(|pubkey| SenderWithSignature {
                sender: *pubkey,
                signature: None,
            })
            .collect::<Vec<_>>();

        for signature in self.signatures.iter() {
            let tx_index = memo
                .pubkeys
                .iter()
                .position(|pubkey| pubkey == &signature.pubkey)
                .ok_or(anyhow::anyhow!("pubkey not found"))?;
            sender_with_signatures[tx_index].signature = Some(signature.signature.clone());
        }

        let account_ids = if self.is_registration_block.unwrap() {
            // assertion
            for pubkey in memo.pubkeys.iter() {
                let not_exists = validity_prover.get_account_id(*pubkey).is_none();
                ensure!(
                    not_exists || pubkey.is_dummy_pubkey(),
                    "account already exists"
                );
            }
            None
        } else {
            let mut account_ids = Vec::new();
            for pubkey in memo.pubkeys.iter() {
                let account_id = validity_prover
                    .get_account_id(*pubkey)
                    .ok_or(anyhow::anyhow!("account not found"))?;
                account_ids.push(account_id);
            }
            Some(AccountIdPacked::pack(&account_ids))
        };
        let account_id_hash = account_ids.map_or(Bytes32::default(), |ids| ids.hash());

        let signature = construct_signature(
            memo.tx_tree_root,
            memo.expiry,
            memo.pubkey_hash,
            account_id_hash,
            self.is_registration_block.unwrap(),
            &sender_with_signatures,
        );

        if self.is_registration_block.unwrap() {
            let trimmed_pubkeys = memo
                .pubkeys
                .into_iter()
                .filter(|pubkey| !pubkey.is_dummy_pubkey())
                .collect::<Vec<_>>();
            contract.post_registration_block(
                memo.tx_tree_root,
                memo.expiry.into(),
                signature.sender_flag,
                signature.agg_pubkey,
                signature.agg_signature,
                signature.message_point,
                trimmed_pubkeys,
            )?;
        } else {
            contract.post_non_registration_block(
                memo.tx_tree_root,
                memo.expiry.into(),
                signature.sender_flag,
                signature.agg_pubkey,
                signature.agg_signature,
                signature.message_point,
                memo.pubkey_hash,
                account_ids.unwrap().to_trimmed_bytes(),
            )?;
        }

        self.reset();

        Ok(())
    }

    pub fn post_empty_block<F, C, const D: usize>(
        &mut self,
        contract: &mut MockContract,
        validity_prover: &BlockValidityProver<F, C, D>, // used to get the account id
    ) -> anyhow::Result<()>
    where
        F: RichField + Extendable<D>,
        C: GenericConfig<D, F = F> + 'static,
        <C as GenericConfig<D>>::Hasher: AlgebraicHasher<F>,
    {
        ensure!(
            self.status == BlockBuilderStatus::AcceptingTxs,
            "Block builder is not accepting tx"
        );
        ensure!(self.tx_requests.is_empty(), "Block builder has tx requests");
        ensure!(self.signatures.is_empty(), "Block builder has signatures");
        self.construct_block()?;
        self.post_block(contract, validity_prover)?;
        Ok(())
    }

    pub fn reset(&mut self) {
        *self = Self::new();
    }
}

#[cfg(test)]
mod tests {
    use super::BlockBuilder;
    use crate::{
        common::{signature::key_set::KeySet, tx::Tx},
        mock::{block_validity_prover::BlockValidityProver, contract::MockContract},
    };
    use plonky2::{
        field::goldilocks_field::GoldilocksField, plonk::config::PoseidonGoldilocksConfig,
    };

    type F = GoldilocksField;
    type C = PoseidonGoldilocksConfig;
    const D: usize = 2;

    #[test]
    fn block_builder() {
        let mut rng = rand::thread_rng();
        let mut block_builder = BlockBuilder::new();
        let mut validity_prover = BlockValidityProver::<F, C, D>::new();
        let mut contract = MockContract::new();

        let user = KeySet::rand(&mut rng);

        for _ in 0..3 {
            let tx = Tx::rand(&mut rng);

            // send tx request
            block_builder
                .send_tx_request(&validity_prover, user.pubkey, tx)
                .unwrap();

            // Block builder constructs a block
            block_builder.construct_block().unwrap();

            // query proposal and verify
            let proposal = block_builder.query_proposal(user.pubkey).unwrap().unwrap();
            proposal.verify(tx).unwrap(); // verify the proposal
            let signature = proposal.sign(user);

            // post signature
            block_builder.post_signature(signature).unwrap();

            // post block
            block_builder
                .post_block(&mut contract, &validity_prover)
                .unwrap();

            validity_prover.sync(&contract).unwrap();
        }
    }
}
