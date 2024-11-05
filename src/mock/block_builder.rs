use crate::{
    common::{
        block_builder::{tx_tree_root_to_message_point, BlockProposal, UserSignature},
        signature::{
            flatten::FlatG2, sign::hash_to_weight, utils::get_pubkey_hash, SignatureContent,
        },
        trees::tx_tree::TxTree,
        tx::Tx,
    },
    constants::{NUM_SENDERS_IN_BLOCK, TX_TREE_HEIGHT},
    ethereum_types::{
        account_id_packed::AccountIdPacked, bytes16::Bytes16, bytes32::Bytes32, u256::U256,
        u32limb_trait::U32LimbTrait,
    },
};
use anyhow::ensure;
use ark_bn254::{Bn254, Fr, G1Affine, G2Affine};
use ark_ec::{pairing::Pairing as _, AffineRepr as _};
use num::BigUint;
use plonky2::{
    field::extension::Extendable,
    hash::hash_types::RichField,
    plonk::config::{AlgebraicHasher, GenericConfig},
};
use plonky2_bn254::fields::recover::RecoverFromX as _;

use super::{block_validity_prover::BlockValidityProver, contract::MockContract};

pub struct BlockBuilder {
    is_accepting_tx: bool,

    // intermidiate data
    is_registration_block: bool,
    tx_tree_root: Bytes32,
    sorted_txs: Vec<(U256, Tx)>,
}

impl BlockBuilder {
    pub fn new() -> Self {
        Self {
            is_accepting_tx: true,
            is_registration_block: false,
            tx_tree_root: Bytes32::default(),
            sorted_txs: Vec::new(),
        }
    }

    // Propose a block with the given transactions.
    pub fn propose<F, C, const D: usize>(
        &mut self,
        contract: &mut MockContract,
        sync_validity_prover: &BlockValidityProver<F, C, D>, // used to get the account id
        is_registration_block: bool,
        txs: Vec<(U256, Tx)>,
    ) -> anyhow::Result<Vec<BlockProposal>>
    where
        F: RichField + Extendable<D>,
        C: GenericConfig<D, F = F> + 'static,
        <C as GenericConfig<D>>::Hasher: AlgebraicHasher<F>,
    {
        ensure!(self.is_accepting_tx, "not accepting txs");
        ensure!(
            contract.get_next_block_number() == sync_validity_prover.block_number() + 1,
            "sync validity prover is not up to date"
        );
        ensure!(txs.len() <= NUM_SENDERS_IN_BLOCK, "too many txs");
        // duplication check
        let mut seen = std::collections::HashSet::new();
        for (pubkey, _) in txs.iter() {
            ensure!(seen.insert(*pubkey), "duplicated pubkey in the txs");
        }
        // registration check
        if is_registration_block {
            for (pubkey, _) in txs.iter() {
                let not_exists = sync_validity_prover.get_account_id(*pubkey).is_none();
                ensure!(
                    not_exists || pubkey.is_dummy_pubkey(),
                    "account already exists"
                );
            }
        } else {
            for (pubkey, _) in txs.iter() {
                sync_validity_prover
                    .get_account_id(*pubkey)
                    .ok_or(anyhow::anyhow!("account not found"))?;
            }
        }

        let mut sorted_txs = txs.clone();
        sorted_txs.sort_by(|a, b| b.0.cmp(&a.0));
        sorted_txs.resize(NUM_SENDERS_IN_BLOCK, (U256::dummy_pubkey(), Tx::default()));

        let pubkeys = sorted_txs.iter().map(|tx| tx.0).collect::<Vec<_>>();
        let pubkey_hash = get_pubkey_hash(&pubkeys);

        let mut tx_tree = TxTree::new(TX_TREE_HEIGHT);
        for tx in txs.iter() {
            tx_tree.push(tx.1.clone());
        }
        let tx_tree_root: Bytes32 = tx_tree.get_root().into();

        let mut proposals = Vec::new();
        for (pubkey, _tx) in txs.iter() {
            let tx_index = sorted_txs.iter().position(|(p, _)| p == pubkey).unwrap();
            let tx_merkle_proof = tx_tree.prove(tx_index);
            proposals.push(BlockProposal {
                tx_tree_root,
                tx_index,
                tx_merkle_proof,
                pubkeys: pubkeys.clone(),
                pubkeys_hash: pubkey_hash,
            });
        }

        self.is_accepting_tx = false;
        self.is_registration_block = is_registration_block;
        self.sorted_txs = sorted_txs;

        Ok(proposals)
    }

    // Post the block with the given signatures.
    pub fn post_block<F, C, const D: usize>(
        &mut self,
        contract: &mut MockContract,
        sync_validity_prover: &BlockValidityProver<F, C, D>, // used to get the account id
        signatures: Vec<UserSignature>,
    ) -> anyhow::Result<()>
    where
        F: RichField + Extendable<D>,
        C: GenericConfig<D, F = F> + 'static,
        <C as GenericConfig<D>>::Hasher: AlgebraicHasher<F>,
    {
        ensure!(!self.is_accepting_tx, "not accepting txs");
        let mut sender_with_signatures = self
            .sorted_txs
            .iter()
            .map(|(pubkey, _)| SenderWithSignature {
                sender: *pubkey,
                signature: None,
            })
            .collect::<Vec<_>>();

        for signature in signatures.iter() {
            let tx_index = self
                .sorted_txs
                .iter()
                .position(|(pubkey, _)| pubkey == &signature.pubkey)
                .ok_or(anyhow::anyhow!("pubkey not found"))?;
            signature.verify(self.tx_tree_root).map_err(|e| {
                anyhow::anyhow!("Invalid signature for pubkey {}: {}", signature.pubkey, e)
            })?;
            sender_with_signatures[tx_index].signature = Some(signature.signature.clone());
        }

        let pubkeys = sender_with_signatures
            .iter()
            .map(|s| s.sender)
            .collect::<Vec<_>>();
        let pubkey_hash = get_pubkey_hash(&pubkeys);

        let account_ids = if self.is_registration_block {
            // assertion
            for pubkey in pubkeys.iter() {
                let not_exists = sync_validity_prover.get_account_id(*pubkey).is_none();
                ensure!(
                    not_exists || pubkey.is_dummy_pubkey(),
                    "account already exists"
                );
            }
            None
        } else {
            let mut account_ids = Vec::new();
            for pubkey in pubkeys.iter() {
                let account_id = sync_validity_prover
                    .get_account_id(*pubkey)
                    .ok_or(anyhow::anyhow!("account not found"))?;
                account_ids.push(account_id);
            }
            Some(AccountIdPacked::pack(&account_ids))
        };
        let account_id_hash = account_ids.map_or(Bytes32::default(), |ids| ids.hash());

        let signature = construct_signature(
            self.tx_tree_root,
            pubkey_hash,
            account_id_hash,
            self.is_registration_block,
            &sender_with_signatures,
        );

        if self.is_registration_block {
            let trimmed_pubkeys = pubkeys
                .into_iter()
                .filter(|pubkey| !pubkey.is_dummy_pubkey())
                .collect::<Vec<_>>();
            contract.post_registration_block(
                self.tx_tree_root,
                signature.sender_flag,
                signature.agg_pubkey,
                signature.agg_signature,
                signature.message_point,
                trimmed_pubkeys,
            )?;
        } else {
            contract.post_non_registration_block(
                self.tx_tree_root,
                signature.sender_flag,
                signature.agg_pubkey,
                signature.agg_signature,
                signature.message_point,
                pubkey_hash,
                account_ids.unwrap().to_trimmed_bytes(),
            )?;
        }

        // reset
        self.is_accepting_tx = true;
        self.is_registration_block = false;
        self.tx_tree_root = Bytes32::default();
        self.sorted_txs = Vec::new();
        Ok(())
    }

    pub fn post_empty_block<F, C, const D: usize>(
        &mut self,
        contract: &mut MockContract,
        sync_validity_prover: &BlockValidityProver<F, C, D>, // used to get the account id
    ) -> anyhow::Result<()>
    where
        F: RichField + Extendable<D>,
        C: GenericConfig<D, F = F> + 'static,
        <C as GenericConfig<D>>::Hasher: AlgebraicHasher<F>,
    {
        self.propose(contract, sync_validity_prover, false, vec![])
            .map_err(|e| anyhow::anyhow!("Failed to propose empty block: {}", e))?;
        self.post_block(contract, sync_validity_prover, vec![])
            .map_err(|e| anyhow::anyhow!("Failed to post empty block: {}", e))?;
        Ok(())
    }
}

struct SenderWithSignature {
    sender: U256,
    signature: Option<FlatG2>,
}

fn construct_signature(
    tx_tree_root: Bytes32,
    pubkey_hash: Bytes32,
    account_id_hash: Bytes32,
    is_registration_block: bool,
    sender_with_signatures: &[SenderWithSignature],
) -> SignatureContent {
    assert_eq!(sender_with_signatures.len(), NUM_SENDERS_IN_BLOCK);
    let sender_flag_bits = sender_with_signatures
        .iter()
        .map(|s| s.signature.is_some())
        .collect::<Vec<_>>();
    let sender_flag = Bytes16::from_bits_be(&sender_flag_bits);
    let agg_pubkey = sender_with_signatures
        .iter()
        .map(|s| {
            let weight = hash_to_weight(s.sender, pubkey_hash);
            if s.signature.is_some() {
                let pubkey_g1: G1Affine = G1Affine::recover_from_x(s.sender.into());
                (pubkey_g1 * Fr::from(BigUint::from(weight))).into()
            } else {
                G1Affine::zero()
            }
        })
        .fold(G1Affine::zero(), |acc: G1Affine, x: G1Affine| {
            (acc + x).into()
        });
    let agg_signature = sender_with_signatures
        .iter()
        .map(|s| {
            if let Some(signature) = s.signature.clone() {
                signature.into()
            } else {
                G2Affine::zero()
            }
        })
        .fold(G2Affine::zero(), |acc: G2Affine, x: G2Affine| {
            (acc + x).into()
        });
    // message point
    let message_point = tx_tree_root_to_message_point(tx_tree_root);
    assert!(
        Bn254::pairing(agg_pubkey, message_point)
            == Bn254::pairing(G1Affine::generator(), agg_signature)
    );
    SignatureContent {
        tx_tree_root,
        is_registration_block,
        sender_flag,
        pubkey_hash,
        account_id_hash,
        agg_pubkey: agg_pubkey.into(),
        agg_signature: agg_signature.into(),
        message_point: message_point.into(),
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
        let mut sync_validity_prover = BlockValidityProver::<F, C, D>::new();
        let mut contract = MockContract::new();

        let user = KeySet::rand(&mut rng);

        for i in 0..3 {
            let tx = Tx::rand(&mut rng);

            let proposals = block_builder
                .propose(
                    &mut contract,
                    &sync_validity_prover,
                    i == 0, // Use registration block for the first tx
                    vec![(user.pubkey, tx)],
                )
                .unwrap();
            let proposal = &proposals[0]; // first tx
            proposal.verify(tx).unwrap(); // verify the proposal
            let signature = proposal.sign(user);
            block_builder
                .post_block(&mut contract, &sync_validity_prover, vec![signature])
                .unwrap();
            sync_validity_prover.sync(&contract).unwrap();
        }
    }
}
