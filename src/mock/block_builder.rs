use crate::{
    common::{
        signature::{
            sign::{hash_to_weight, sign_to_tx_root},
            utils::get_pubkey_hash,
            SignatureContent,
        },
        trees::tx_tree::TxTree,
    },
    constants::{NUM_SENDERS_IN_BLOCK, TX_TREE_HEIGHT},
    ethereum_types::{
        account_id_packed::AccountIdPacked, bytes16::Bytes16, bytes32::Bytes32,
        u32limb_trait::U32LimbTrait,
    },
};
use anyhow::ensure;
use ark_bn254::{Bn254, Fr, G1Affine, G2Affine};
use ark_ec::{pairing::Pairing as _, AffineRepr as _};
use num::BigUint;
use plonky2::{
    field::{extension::Extendable, goldilocks_field::GoldilocksField, types::Field},
    hash::hash_types::RichField,
    plonk::config::{AlgebraicHasher, GenericConfig},
};
use plonky2_bn254::{curves::g2::G2Target, utils::hash_to_g2::HashToG2 as _};

use super::{
    contract::MockContract, sync_validity_prover::SyncValidityProver, tx_request::MockTxRequest,
};

pub struct BlockBuilder;

impl BlockBuilder {
    pub fn post_block<F, C, const D: usize>(
        &self,
        contract: &mut MockContract,
        sync_validity_prover: &SyncValidityProver<F, C, D>, // used to get the account id
        is_registration_block: bool,
        txs: Vec<MockTxRequest>,
    ) -> anyhow::Result<TxTree>
    where
        F: RichField + Extendable<D>,
        C: GenericConfig<D, F = F> + 'static,
        <C as GenericConfig<D>>::Hasher: AlgebraicHasher<F>,
    {
        ensure!(
            contract.get_block_number() == sync_validity_prover.last_block_number + 1,
            "sync validity prover is not up to date"
        );
        ensure!(txs.len() <= NUM_SENDERS_IN_BLOCK, "too many txs");
        // sort and pad txs
        let mut sorted_txs = txs.clone();
        sorted_txs.sort_by(|a, b| b.sender.pubkey.cmp(&a.sender.pubkey));
        sorted_txs.resize(NUM_SENDERS_IN_BLOCK, MockTxRequest::dummy());

        let pubkeys = sorted_txs
            .iter()
            .map(|tx| tx.sender.pubkey)
            .collect::<Vec<_>>();
        let pubkey_hash = get_pubkey_hash(&pubkeys);

        let account_ids = if is_registration_block {
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

        // construct tx tree root
        let mut tx_tree = TxTree::new(TX_TREE_HEIGHT);
        for tx in txs.iter() {
            tx_tree.push(tx.tx.clone());
        }
        let tx_tree_root: Bytes32 = tx_tree.get_root().into();

        let signature = construct_signature(
            tx_tree_root,
            pubkey_hash,
            account_id_hash,
            is_registration_block,
            &sorted_txs,
        );

        if is_registration_block {
            let trimmed_pubkeys = pubkeys
                .into_iter()
                .filter(|pubkey| !pubkey.is_dummy_pubkey())
                .collect::<Vec<_>>();
            contract.post_registration_block(
                tx_tree_root,
                signature.sender_flag,
                signature.agg_pubkey,
                signature.agg_signature,
                signature.message_point,
                trimmed_pubkeys,
            )?;
        } else {
            contract.post_non_registration_block(
                tx_tree_root,
                signature.sender_flag,
                signature.agg_pubkey,
                signature.agg_signature,
                signature.message_point,
                pubkey_hash,
                account_ids.unwrap().to_trimmed_bytes(),
            )?;
        }

        Ok(tx_tree)
    }
}

fn construct_signature(
    tx_tree_root: Bytes32,
    pubkey_hash: Bytes32,
    account_id_hash: Bytes32,
    is_registration_block: bool,
    sorted_txs: &[MockTxRequest],
) -> SignatureContent {
    assert_eq!(sorted_txs.len(), NUM_SENDERS_IN_BLOCK);
    let sender_flag_bits = sorted_txs
        .iter()
        .map(|tx| tx.will_return_signature)
        .collect::<Vec<_>>();
    let sender_flag = Bytes16::from_bits_be(&sender_flag_bits);
    let agg_pubkey = sorted_txs
        .iter()
        .map(|tx| {
            let weight = hash_to_weight(tx.sender.pubkey, pubkey_hash);
            if tx.will_return_signature {
                (tx.sender.pubkey_g1 * Fr::from(BigUint::from(weight))).into()
            } else {
                G1Affine::zero()
            }
        })
        .fold(G1Affine::zero(), |acc: G1Affine, x: G1Affine| {
            (acc + x).into()
        });
    let agg_signature = sorted_txs
        .iter()
        .map(|tx| {
            if tx.will_return_signature {
                sign_to_tx_root(tx.sender.privkey, tx_tree_root, pubkey_hash)
            } else {
                G2Affine::zero()
            }
        })
        .fold(G2Affine::zero(), |acc: G2Affine, x: G2Affine| {
            (acc + x).into()
        });
    // message point
    let tx_tree_root_f = tx_tree_root
        .to_u32_vec()
        .iter()
        .map(|x| GoldilocksField::from_canonical_u32(*x))
        .collect::<Vec<_>>();
    let message_point = G2Target::<GoldilocksField, 2>::hash_to_g2(&tx_tree_root_f);
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
        mock::{
            contract::MockContract, sync_validity_prover::SyncValidityProver,
            tx_request::MockTxRequest,
        },
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
        let block_builder = BlockBuilder;
        let mut sync_validity_prover = SyncValidityProver::<F, C, D>::new();
        let mut contract = MockContract::new();

        let user = KeySet::rand(&mut rng);

        for i in 0..3 {
            let tx_request = MockTxRequest {
                tx: Tx::rand(&mut rng),
                sender: user,
                will_return_signature: true,
            };
            block_builder
                .post_block(
                    &mut contract,
                    &sync_validity_prover,
                    i == 0, // Use registration block for the first tx
                    vec![tx_request],
                )
                .unwrap();
            sync_validity_prover.sync(&contract).unwrap();
        }
    }
}
