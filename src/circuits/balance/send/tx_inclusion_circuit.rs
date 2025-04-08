use super::error::SendError;
use plonky2::{
    field::extension::Extendable,
    hash::hash_types::RichField,
    iop::{
        target::{BoolTarget, Target},
        witness::{PartialWitness, WitnessWrite},
    },
    plonk::{
        circuit_builder::CircuitBuilder,
        circuit_data::{CircuitConfig, CircuitData, VerifierCircuitData},
        config::{AlgebraicHasher, GenericConfig},
        proof::{ProofWithPublicInputs, ProofWithPublicInputsTarget},
    },
};

use crate::{
    circuits::validity::validity_pis::{
        ValidityPublicInputs, ValidityPublicInputsTarget, VALIDITY_PUBLIC_INPUTS_LEN,
    },
    common::{
        public_state::{PublicState, PublicStateTarget, PUBLIC_STATE_LEN},
        trees::{
            account_tree::{AccountMembershipProof, AccountMembershipProofTarget},
            block_hash_tree::{BlockHashMerkleProof, BlockHashMerkleProofTarget},
            sender_tree::{
                SenderLeaf, SenderLeafTarget, SenderMerkleProof, SenderMerkleProofTarget,
            },
            tx_tree::{TxMerkleProof, TxMerkleProofTarget},
        },
        tx::{Tx, TxTarget, TX_LEN},
    },
    constants::{ACCOUNT_TREE_HEIGHT, BLOCK_HASH_TREE_HEIGHT, SENDER_TREE_HEIGHT, TX_TREE_HEIGHT},
    ethereum_types::{
        u256::{U256Target, U256, U256_LEN},
        u32limb_trait::{U32LimbTargetTrait, U32LimbTrait},
    },
    utils::{
        conversion::ToU64,
        poseidon_hash_out::{PoseidonHashOut, PoseidonHashOutTarget},
        recursively_verifiable::add_proof_target_and_verify_cyclic,
    },
};

pub const TX_INCLUSION_PUBLIC_INPUTS_LEN: usize = PUBLIC_STATE_LEN * 2 + U256_LEN + TX_LEN + 1;

#[derive(Clone, Debug)]
pub struct TxInclusionPublicInputs {
    pub prev_public_state: PublicState,
    pub new_public_state: PublicState,
    pub pubkey: U256,
    pub tx: Tx,
    pub is_valid: bool,
}

impl TxInclusionPublicInputs {
    pub fn from_u64_slice(input: &[u64]) -> Self {
        assert_eq!(input.len(), TX_INCLUSION_PUBLIC_INPUTS_LEN);
        let prev_public_state = PublicState::from_u64_slice(&input[0..PUBLIC_STATE_LEN]);
        let new_public_state =
            PublicState::from_u64_slice(&input[PUBLIC_STATE_LEN..PUBLIC_STATE_LEN * 2]);
        let pubkey =
            U256::from_u64_slice(&input[PUBLIC_STATE_LEN * 2..PUBLIC_STATE_LEN * 2 + U256_LEN])
                .unwrap();
        let tx = Tx::from_u64_slice(
            &input[PUBLIC_STATE_LEN * 2 + U256_LEN..PUBLIC_STATE_LEN * 2 + U256_LEN + TX_LEN],
        );
        let is_valid = input[PUBLIC_STATE_LEN * 2 + U256_LEN + TX_LEN] == 1;
        Self {
            prev_public_state,
            new_public_state,
            pubkey,
            tx,
            is_valid,
        }
    }
}

#[derive(Clone, Debug)]
pub struct TxInclusionPublicInputsTarget {
    pub prev_public_state: PublicStateTarget,
    pub new_public_state: PublicStateTarget,
    pub pubkey: U256Target,
    pub tx: TxTarget,
    pub is_valid: BoolTarget,
}

impl TxInclusionPublicInputsTarget {
    pub fn to_vec(&self) -> Vec<Target> {
        let mut vec = Vec::new();
        vec.extend_from_slice(&self.prev_public_state.to_vec());
        vec.extend_from_slice(&self.new_public_state.to_vec());
        vec.extend_from_slice(&self.pubkey.to_vec());
        vec.extend_from_slice(&self.tx.to_vec());
        vec.push(self.is_valid.target);
        assert_eq!(vec.len(), TX_INCLUSION_PUBLIC_INPUTS_LEN);
        vec
    }

    pub fn from_slice(input: &[Target]) -> Self {
        assert_eq!(input.len(), TX_INCLUSION_PUBLIC_INPUTS_LEN);
        let prev_public_state = PublicStateTarget::from_slice(&input[0..PUBLIC_STATE_LEN]);
        let new_public_state =
            PublicStateTarget::from_slice(&input[PUBLIC_STATE_LEN..PUBLIC_STATE_LEN * 2]);
        let pubkey =
            U256Target::from_slice(&input[PUBLIC_STATE_LEN * 2..PUBLIC_STATE_LEN * 2 + U256_LEN]);
        let tx = TxTarget::from_slice(
            &input[PUBLIC_STATE_LEN * 2 + U256_LEN..PUBLIC_STATE_LEN * 2 + U256_LEN + TX_LEN],
        );
        let is_valid = BoolTarget::new_unsafe(input[PUBLIC_STATE_LEN * 2 + U256_LEN + TX_LEN]);
        Self {
            prev_public_state,
            new_public_state,
            pubkey,
            tx,
            is_valid,
        }
    }
}

pub struct TxInclusionValue<
    F: RichField + Extendable<D>,
    C: GenericConfig<D, F = F> + 'static,
    const D: usize,
> where
    <C as GenericConfig<D>>::Hasher: AlgebraicHasher<F>,
{
    pub pubkey: U256,
    pub prev_public_state: PublicState,
    pub new_public_state: PublicState,
    pub validity_proof: ProofWithPublicInputs<F, C, D>,
    pub block_merkle_proof: BlockHashMerkleProof,
    pub prev_account_membership_proof: AccountMembershipProof,
    pub sender_index: u32,
    pub tx: Tx,
    pub tx_merkle_proof: TxMerkleProof,
    pub sender_leaf: SenderLeaf,
    pub sender_merkle_proof: SenderMerkleProof,
    pub is_valid: bool,
}

impl<F: RichField + Extendable<D>, C: GenericConfig<D, F = F>, const D: usize>
    TxInclusionValue<F, C, D>
where
    <C as GenericConfig<D>>::Hasher: AlgebraicHasher<F>,
{
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        validity_vd: &VerifierCircuitData<F, C, D>,
        pubkey: U256,
        prev_public_state: &PublicState, // public state of the old balance proof
        validity_proof: &ProofWithPublicInputs<F, C, D>, /* validity proof of the new public
                                          * state which contains the tx */
        block_merkle_proof: &BlockHashMerkleProof, /* block merkle proof that shows the
                                                    * block of prev_public_state is included in
                                                    * the
                                                    * block tree of validity_proof */
        prev_account_membership_proof: &AccountMembershipProof, /* account membership proof that
                                                                 * shows no tx has been sent
                                                                 * before
                                                                 * the block of validity proof. */
        sender_index: u32,
        tx: &Tx,
        tx_merkle_proof: &TxMerkleProof,
        sender_leaf: &SenderLeaf,
        sender_merkle_proof: &SenderMerkleProof,
    ) -> Result<Self, SendError> {
        validity_vd
            .verify(validity_proof.clone())
            .map_err(|e| SendError::VerificationFailed(
                format!("Validity proof is invalid: {:?}", e)
            ))?;
            
        let validity_pis = ValidityPublicInputs::from_u64_slice(
            &validity_proof.public_inputs[0..VALIDITY_PUBLIC_INPUTS_LEN].to_u64_vec(),
        );
        
        block_merkle_proof
            .verify(
                &prev_public_state.block_hash,
                prev_public_state.block_number as u64,
                validity_pis.public_state.block_tree_root,
            )
            .map_err(|e| SendError::VerificationFailed(
                format!("Block merkle proof is invalid: {:?}", e)
            ))?;
            
        prev_account_membership_proof
            .verify(pubkey, validity_pis.public_state.prev_account_tree_root)
            .map_err(|e| SendError::VerificationFailed(
                format!("Account membership proof is invalid: {:?}", e)
            ))?;
            
        let last_block_number = prev_account_membership_proof.get_value() as u32;
        
        if last_block_number > prev_public_state.block_number {
            return Err(SendError::VerificationFailed(
                format!(
                    "There is a sent tx before the last block: last_block_number={}, prev_block_number={}", 
                    last_block_number, 
                    prev_public_state.block_number
                )
            ));
        }

        let tx_tree_root: PoseidonHashOut = validity_pis
            .tx_tree_root
            .try_into()
            .map_err(|e| SendError::VerificationFailed(
                format!("Tx tree root is invalid: {:?}", e)
            ))?;
            
        tx_merkle_proof
            .verify(tx, sender_index as u64, tx_tree_root)
            .map_err(|e| SendError::VerificationFailed(
                format!("Tx merkle proof is invalid: {:?}", e)
            ))?;
            
        sender_merkle_proof
            .verify(
                sender_leaf,
                sender_index as u64,
                validity_pis.sender_tree_root,
            )
            .map_err(|e| SendError::VerificationFailed(
                format!("Sender merkle proof is invalid: {:?}", e)
            ))?;

        if sender_leaf.sender != pubkey {
            return Err(SendError::VerificationFailed(
                format!(
                    "Sender pubkey mismatch: expected {:?}, got {:?}", 
                    pubkey, 
                    sender_leaf.sender
                )
            ));
        }
        
        let is_valid = sender_leaf.signature_included && validity_pis.is_valid_block;

        Ok(Self {
            pubkey,
            prev_public_state: prev_public_state.clone(),
            new_public_state: validity_pis.public_state.clone(),
            validity_proof: validity_proof.clone(),
            block_merkle_proof: block_merkle_proof.clone(),
            prev_account_membership_proof: prev_account_membership_proof.clone(),
            sender_index,
            tx: *tx,
            tx_merkle_proof: tx_merkle_proof.clone(),
            sender_leaf: sender_leaf.clone(),
            sender_merkle_proof: sender_merkle_proof.clone(),
            is_valid,
        })
    }
}

pub struct TxInclusionTarget<const D: usize> {
    pub pubkey: U256Target,
    pub prev_public_state: PublicStateTarget,
    pub new_public_state: PublicStateTarget,
    pub validity_proof: ProofWithPublicInputsTarget<D>,
    pub block_merkle_proof: BlockHashMerkleProofTarget,
    pub prev_account_membership_proof: AccountMembershipProofTarget,
    pub sender_index: Target,
    pub tx: TxTarget,
    pub tx_merkle_proof: TxMerkleProofTarget,
    pub sender_leaf: SenderLeafTarget,
    pub sender_merkle_proof: SenderMerkleProofTarget,
    pub is_valid: BoolTarget,
}

impl<const D: usize> TxInclusionTarget<D> {
    pub fn new<F: RichField + Extendable<D>, C: GenericConfig<D, F = F> + 'static>(
        validity_vd: &VerifierCircuitData<F, C, D>,
        builder: &mut CircuitBuilder<F, D>,
        is_checked: bool,
    ) -> Self
    where
        <C as GenericConfig<D>>::Hasher: AlgebraicHasher<F>,
    {
        let pubkey = U256Target::new(builder, is_checked);
        let prev_public_state = PublicStateTarget::new(builder, is_checked);
        let block_merkle_proof = BlockHashMerkleProofTarget::new(builder, BLOCK_HASH_TREE_HEIGHT);
        let prev_account_membership_proof =
            AccountMembershipProofTarget::new(builder, ACCOUNT_TREE_HEIGHT, is_checked);
        let sender_index = builder.add_virtual_target();
        let tx = TxTarget::new(builder);
        let tx_merkle_proof = TxMerkleProofTarget::new(builder, TX_TREE_HEIGHT);
        let sender_leaf = SenderLeafTarget::new(builder, is_checked);
        let sender_merkle_proof = SenderMerkleProofTarget::new(builder, SENDER_TREE_HEIGHT);

        let validity_proof = add_proof_target_and_verify_cyclic(validity_vd, builder);
        let validity_pis = ValidityPublicInputsTarget::from_slice(
            &validity_proof.public_inputs[0..VALIDITY_PUBLIC_INPUTS_LEN],
        );
        block_merkle_proof.verify::<F, C, D>(
            builder,
            &prev_public_state.block_hash,
            prev_public_state.block_number,
            validity_pis.public_state.block_tree_root,
        );
        prev_account_membership_proof.verify::<F, C, D>(
            builder,
            pubkey,
            validity_pis.public_state.prev_account_tree_root,
        );
        let last_block_number = prev_account_membership_proof.get_value(builder);
        let diff = builder.sub(prev_public_state.block_number, last_block_number);
        builder.range_check(diff, 32);

        let tx_tree_root: PoseidonHashOutTarget =
            validity_pis.tx_tree_root.reduce_to_hash_out(builder);
        tx_merkle_proof.verify::<F, C, D>(builder, &tx, sender_index, tx_tree_root);
        sender_merkle_proof.verify::<F, C, D>(
            builder,
            &sender_leaf,
            sender_index,
            validity_pis.sender_tree_root,
        );
        sender_leaf.sender.connect(builder, pubkey);
        let is_valid = builder.and(sender_leaf.signature_included, validity_pis.is_valid_block);
        Self {
            pubkey,
            prev_public_state,
            new_public_state: validity_pis.public_state,
            validity_proof,
            block_merkle_proof,
            prev_account_membership_proof,
            sender_index,
            tx,
            tx_merkle_proof,
            sender_leaf,
            sender_merkle_proof,
            is_valid,
        }
    }

    pub fn set_witness<
        F: RichField + Extendable<D>,
        C: GenericConfig<D, F = F> + 'static,
        W: WitnessWrite<F>,
    >(
        &self,
        witness: &mut W,
        value: &TxInclusionValue<F, C, D>,
    ) where
        <C as GenericConfig<D>>::Hasher: AlgebraicHasher<F>,
    {
        self.prev_public_state
            .set_witness(witness, &value.prev_public_state);
        self.new_public_state
            .set_witness(witness, &value.new_public_state);
        witness.set_proof_with_pis_target(&self.validity_proof, &value.validity_proof);
        self.block_merkle_proof
            .set_witness(witness, &value.block_merkle_proof);
        self.prev_account_membership_proof
            .set_witness(witness, &value.prev_account_membership_proof);
        witness.set_target(self.sender_index, F::from_canonical_u32(value.sender_index));
        self.tx.set_witness(witness, value.tx);
        self.tx_merkle_proof
            .set_witness(witness, &value.tx_merkle_proof);
        self.sender_leaf.set_witness(witness, &value.sender_leaf);
        self.sender_merkle_proof
            .set_witness(witness, &value.sender_merkle_proof);
        witness.set_bool_target(self.is_valid, value.is_valid);
    }
}

pub struct TxInclusionCircuit<F, C, const D: usize>
where
    F: RichField + Extendable<D>,
    C: GenericConfig<D, F = F>,
{
    pub data: CircuitData<F, C, D>,
    pub target: TxInclusionTarget<D>,
}

impl<F, C, const D: usize> TxInclusionCircuit<F, C, D>
where
    F: RichField + Extendable<D>,
    C: GenericConfig<D, F = F> + 'static,
    C::Hasher: AlgebraicHasher<F>,
{
    pub fn new(validity_vd: &VerifierCircuitData<F, C, D>) -> Self {
        let mut builder = CircuitBuilder::<F, D>::new(CircuitConfig::default());
        let target = TxInclusionTarget::new::<F, C>(validity_vd, &mut builder, true);
        let pis = TxInclusionPublicInputsTarget {
            prev_public_state: target.prev_public_state.clone(),
            new_public_state: target.new_public_state.clone(),
            pubkey: target.pubkey,
            tx: target.tx.clone(),
            is_valid: target.is_valid,
        };
        builder.register_public_inputs(&pis.to_vec());
        let data = builder.build();
        Self { data, target }
    }

    pub fn prove(
        &self,
        value: &TxInclusionValue<F, C, D>,
    ) -> Result<ProofWithPublicInputs<F, C, D>, SendError> {
        let mut pw = PartialWitness::<F>::new();
        self.target.set_witness(&mut pw, value);
        self.data.prove(pw).map_err(|e| SendError::ProofGenerationError(format!("{:?}", e)))
    }
}

// #[cfg(test)]
// mod tests {
//     use plonky2::{
//         field::goldilocks_field::GoldilocksField, plonk::config::PoseidonGoldilocksConfig,
//     };

//     use crate::{
//         common::{generic_address::GenericAddress, salt::Salt, transfer::Transfer},
//         ethereum_types::u256::U256,
//     };

//     use super::TxInclusionValue;

//     type F = GoldilocksField;
//     type C = PoseidonGoldilocksConfig;
//     const D: usize = 2;

//     #[test]
//     fn tx_inclusion_circuit() {
//         let mut rng = rand::thread_rng();
//         let transfer = Transfer {
//             recipient: GenericAddress::rand_pubkey(&mut rng),
//             token_index: 0,
//             amount: U256::rand_small(&mut rng),
//             salt: Salt::rand(&mut rng),
//         };
        
//         // send tx
//         let send_witness = wallet.send_tx_and_update(&mut rng, &mut block_builder, &[transfer]);
//         // update validity proofs
//         sync_prover.sync(&block_builder);

//         let prev_public_state = wallet.get_balance_pis().public_state;
//         let update_witness = sync_prover.get_update_witness(
//             &block_builder,
//             wallet.get_pubkey(),
//             block_builder.last_block_number(),
//             prev_public_state.block_number,
//             true,
//         );

//         let pubkey = wallet.key_set.pubkey;
//         let tx_index = send_witness.tx_witness.tx_index;
//         let sender_tree = send_witness.tx_witness.get_sender_tree();
//         let sender_leaf = sender_tree.get_leaf(tx_index);
//         let sender_merkle_proof = sender_tree.prove(tx_index);
//         let value = TxInclusionValue::new(
//             &sync_prover.validity_processor.validity_circuit,
//             pubkey,
//             &prev_public_state,
//             &update_witness.validity_proof,
//             &update_witness.block_merkle_proof,
//             &update_witness.account_membership_proof,
//             send_witness.tx_witness.tx_index,
//             &send_witness.tx_witness.tx,
//             &send_witness.tx_witness.tx_merkle_proof,
//             &sender_leaf,
//             &sender_merkle_proof,
//         )
//         .expect("failed to create tx inclusion value");
//         let tx_inclusion_circuit = super::TxInclusionCircuit::<F, C, D>::new(
//             &sync_prover.validity_processor.validity_circuit,
//         );
//         let _ = tx_inclusion_circuit.prove(&value).unwrap();
//     }
// }
