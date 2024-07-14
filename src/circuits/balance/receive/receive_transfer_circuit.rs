use crate::{
    circuits::{
        balance::{
            balance_circuit::common_data_for_balance_circuit,
            balance_pis::{
                BalancePublicInputs, BalancePublicInputsTarget, BALANCE_PUBLIC_INPUTS_LEN,
            },
        },
        utils::cyclic::{vd_from_pis_slice, vd_from_pis_slice_target, vd_to_vec, vd_to_vec_target},
    },
    common::{
        private_state::{PrivateState, PrivateStateTarget},
        public_state::{PublicState, PublicStateTarget, PUBLIC_STATE_LEN},
        transfer::{Transfer, TransferTarget},
        trees::{
            asset_tree::{AssetLeaf, AssetLeafTarget, AssetMerkleProof, AssetMerkleProofTarget},
            block_hash_tree::{BlockHashMerkleProof, BlockHashMerkleProofTarget},
            nullifier_tree::{NullifierInsersionProof, NullifierInsersionProofTarget},
            transfer_tree::{TransferMerkleProof, TransferMerkleProofTarget},
        },
        tx::{Tx, TxTarget},
    },
    constants::{ASSET_TREE_HEIGHT, BLOCK_HASH_TREE_HEIGHT, TRANSFER_TREE_HEIGHT},
    ethereum_types::{
        bytes32::Bytes32,
        u256::U256,
        u32limb_trait::{U32LimbTargetTrait as _, U32LimbTrait},
    },
    utils::{
        conversion::ToU64 as _,
        dummy::DummyProof,
        leafable::{Leafable as _, LeafableTarget},
        poseidon_hash_out::{PoseidonHashOut, PoseidonHashOutTarget},
        recursivable::Recursivable,
    },
};
use plonky2::{
    field::extension::Extendable,
    hash::hash_types::RichField,
    iop::{
        target::Target,
        witness::{PartialWitness, WitnessWrite},
    },
    plonk::{
        circuit_builder::CircuitBuilder,
        circuit_data::{
            CircuitConfig, CircuitData, VerifierCircuitData, VerifierCircuitTarget,
            VerifierOnlyCircuitData,
        },
        config::{AlgebraicHasher, GenericConfig},
        proof::{ProofWithPublicInputs, ProofWithPublicInputsTarget},
    },
};

#[derive(Debug, Clone)]
pub struct ReceiveTransferPublicInputs<
    F: RichField + Extendable<D>,
    C: GenericConfig<D, F = F>,
    const D: usize,
> {
    pub prev_private_commitment: PoseidonHashOut,
    pub new_private_commitment: PoseidonHashOut,
    pub pubkey: U256<u32>,
    pub public_state: PublicState,
    pub balance_circuit_vd: VerifierOnlyCircuitData<C, D>,
}

impl<F: RichField + Extendable<D>, C: GenericConfig<D, F = F>, const D: usize>
    ReceiveTransferPublicInputs<F, C, D>
where
    <C as GenericConfig<D>>::Hasher: AlgebraicHasher<F>,
{
    pub fn to_vec(&self, config: &CircuitConfig) -> Vec<F> {
        let mut vec = vec![
            self.prev_private_commitment.to_u64_vec(),
            self.new_private_commitment.to_u64_vec(),
            self.pubkey.to_u64_vec(),
            self.public_state.to_u64_vec(),
        ]
        .concat()
        .into_iter()
        .map(|x| F::from_canonical_u64(x))
        .collect::<Vec<_>>();
        vec.extend(vd_to_vec(config, &self.balance_circuit_vd));
        vec
    }

    pub fn from_vec(config: &CircuitConfig, input: &[F]) -> Self {
        let non_vd = input[0..16 + PUBLIC_STATE_LEN].to_u64_vec();
        let prev_private_commitment = PoseidonHashOut::from_u64_vec(&non_vd[0..4]);
        let new_private_commitment = PoseidonHashOut::from_u64_vec(&non_vd[4..8]);
        let pubkey = U256::from_u64_vec(&non_vd[8..16]);
        let public_state = PublicState::from_u64_vec(&non_vd[16..16 + PUBLIC_STATE_LEN]);
        let balance_circuit_vd = vd_from_pis_slice(input, config).unwrap();
        ReceiveTransferPublicInputs {
            prev_private_commitment,
            new_private_commitment,
            pubkey,
            public_state,
            balance_circuit_vd,
        }
    }
}

#[derive(Debug, Clone)]
pub struct ReceiveTransferPublicInputsTarget {
    pub prev_private_commitment: PoseidonHashOutTarget,
    pub new_private_commitment: PoseidonHashOutTarget,
    pub pubkey: U256<Target>,
    pub public_state: PublicStateTarget,
    pub balance_circuit_vd: VerifierCircuitTarget,
}

impl ReceiveTransferPublicInputsTarget {
    pub fn to_vec(&self, config: &CircuitConfig) -> Vec<Target> {
        let mut vec = vec![
            self.prev_private_commitment.to_vec(),
            self.new_private_commitment.to_vec(),
            self.pubkey.to_vec(),
            self.public_state.to_vec(),
        ]
        .concat();
        vec.extend(vd_to_vec_target(config, &self.balance_circuit_vd));
        vec
    }

    pub fn from_vec(config: &CircuitConfig, input: &[Target]) -> Self {
        let prev_private_commitment = PoseidonHashOutTarget::from_vec(&input[0..4]);
        let new_private_commitment = PoseidonHashOutTarget::from_vec(&input[4..8]);
        let pubkey = U256::<Target>::from_limbs(&input[8..16]);
        let public_state = PublicStateTarget::from_vec(&input[16..16 + PUBLIC_STATE_LEN]);
        let balance_circuit_vd = vd_from_pis_slice_target(input, config).unwrap();
        ReceiveTransferPublicInputsTarget {
            prev_private_commitment,
            new_private_commitment,
            pubkey,
            public_state,
            balance_circuit_vd,
        }
    }
}

#[derive(Debug, Clone)]
pub struct ReceiveTransferValue<
    F: RichField + Extendable<D>,
    C: GenericConfig<D, F = F> + 'static,
    const D: usize,
> {
    pub pubkey: U256<u32>,
    pub tx: Tx,
    pub transfer_merkle_proof: TransferMerkleProof,
    pub transfer_index: usize,
    pub transfer: Transfer,
    pub balance_circuit_vd: VerifierOnlyCircuitData<C, D>,
    pub balance_proof: ProofWithPublicInputs<F, C, D>,
    pub public_state: PublicState,
    pub prev_private_state: PrivateState,
    pub new_private_state: PrivateState,
    pub prev_private_commitment: PoseidonHashOut,
    pub new_private_commitment: PoseidonHashOut,
    pub block_merkle_proof: BlockHashMerkleProof,
    pub nullifier_proof: NullifierInsersionProof,
    pub prev_asset_leaf: AssetLeaf,
    pub asset_merkle_proof: AssetMerkleProof,
}

impl<F: RichField + Extendable<D>, C: GenericConfig<D, F = F>, const D: usize>
    ReceiveTransferValue<F, C, D>
{
    pub fn new(
        pubkey: U256<u32>,
        tx: Tx,
        transfer_merkle_proof: TransferMerkleProof,
        transfer_index: usize,
        transfer: Transfer,
        balance_proof: ProofWithPublicInputs<F, C, D>,
        public_state: PublicState,
        block_merkle_proof: BlockHashMerkleProof,
        prev_private_state: PrivateState,
        nullifier_proof: NullifierInsersionProof,
        prev_asset_leaf: AssetLeaf,
        asset_merkle_proof: AssetMerkleProof,
    ) -> Self
    where
        C::Hasher: AlgebraicHasher<F>,
    {
        // verify balance proof
        let balance_common_data = common_data_for_balance_circuit::<F, C, D>();
        let balance_pis = BalancePublicInputs::from_pis(&balance_proof.public_inputs);
        let balance_circuit_vd =
            vd_from_pis_slice::<F, C, D>(&balance_proof.public_inputs, &balance_common_data.config)
                .expect("Failed to parse balance vd");
        let balance_circuit_verifier_data = VerifierCircuitData {
            verifier_only: balance_circuit_vd.clone(),
            common: balance_common_data,
        };
        balance_circuit_verifier_data
            .verify(balance_proof.clone())
            .expect("Balance proof is invalid");
        // check block hash inclusion of balance proof
        block_merkle_proof
            .verify(
                &balance_pis.public_state.block_hash,
                balance_pis.public_state.block_number as usize,
                public_state.block_tree_root,
            )
            .expect("Invalid block merkle proof");

        // verify transfer inclusion
        assert_eq!(balance_pis.last_tx_hash, tx.hash());
        transfer_merkle_proof
            .verify(&transfer, transfer_index, tx.transfer_tree_root)
            .expect("Invalid transfer merkle proof");

        // verify private_state update
        let recipient = transfer
            .recipient
            .to_pubkey()
            .expect("generic address is not pubkey");
        assert_eq!(recipient, pubkey);
        let nullifier: Bytes32<u32> = transfer.hash().into();
        let new_nullifier_tree_root = nullifier_proof
            .get_new_root(prev_private_state.nullifier_tree_root, nullifier)
            .expect("Invalid nullifier proof");
        asset_merkle_proof
            .verify(
                &prev_asset_leaf,
                transfer.token_index as usize,
                prev_private_state.asset_tree_root,
            )
            .expect("Invalid asset merkle proof");
        let new_asset_leaf = AssetLeaf {
            is_insufficient: prev_asset_leaf.is_insufficient,
            amount: prev_asset_leaf.amount + transfer.amount,
        };
        let new_asset_tree_root =
            asset_merkle_proof.get_root(&new_asset_leaf, transfer.token_index as usize);

        let new_private_state = PrivateState {
            asset_tree_root: new_asset_tree_root,
            nullifier_tree_root: new_nullifier_tree_root,
            ..prev_private_state
        };
        let prev_private_commitment = prev_private_state.commitment();
        let new_private_commitment = new_private_state.commitment();

        ReceiveTransferValue {
            pubkey,
            tx,
            transfer_merkle_proof,
            transfer_index,
            transfer,
            balance_circuit_vd,
            balance_proof,
            public_state,
            prev_private_state,
            new_private_state,
            prev_private_commitment,
            new_private_commitment,
            block_merkle_proof,
            nullifier_proof,
            prev_asset_leaf,
            asset_merkle_proof,
        }
    }
}

#[derive(Debug, Clone)]
pub struct ReceiveTransferTarget<const D: usize> {
    pub pubkey: U256<Target>,
    pub tx: TxTarget,
    pub transfer_merkle_proof: TransferMerkleProofTarget,
    pub transfer_index: Target,
    pub transfer: TransferTarget,
    pub balance_circuit_vd: VerifierCircuitTarget,
    pub balance_proof: ProofWithPublicInputsTarget<D>,
    pub public_state: PublicStateTarget,
    pub prev_private_state: PrivateStateTarget,
    pub new_private_state: PrivateStateTarget,
    pub prev_private_commitment: PoseidonHashOutTarget,
    pub new_private_commitment: PoseidonHashOutTarget,
    pub block_merkle_proof: BlockHashMerkleProofTarget,
    pub nullifier_proof: NullifierInsersionProofTarget,
    pub prev_asset_leaf: AssetLeafTarget,
    pub asset_merkle_proof: AssetMerkleProofTarget,
}

impl<const D: usize> ReceiveTransferTarget<D> {
    pub fn new<F: RichField + Extendable<D>, C: GenericConfig<D, F = F> + 'static>(
        builder: &mut CircuitBuilder<F, D>,
        is_checked: bool,
    ) -> Self
    where
        <C as GenericConfig<D>>::Hasher: AlgebraicHasher<F>,
    {
        let pubkey = U256::<Target>::new(builder, is_checked);
        let tx = TxTarget::new(builder);
        let transfer_merkle_proof = TransferMerkleProofTarget::new(builder, TRANSFER_TREE_HEIGHT);
        let transfer_index = builder.add_virtual_target();
        let transfer = TransferTarget::new(builder, is_checked);
        let public_state = PublicStateTarget::new(builder, is_checked);
        let block_merkle_proof = BlockHashMerkleProofTarget::new(builder, BLOCK_HASH_TREE_HEIGHT);
        let prev_private_state = PrivateStateTarget::new(builder);
        let nullifier_proof = NullifierInsersionProofTarget::new(builder, is_checked);
        let prev_asset_leaf = AssetLeafTarget::new(builder, is_checked);
        let asset_merkle_proof = AssetMerkleProofTarget::new(builder, ASSET_TREE_HEIGHT);

        // verify balance proof
        let balance_common_data = common_data_for_balance_circuit::<F, C, D>();
        let balance_proof = builder.add_virtual_proof_with_pis(&balance_common_data);
        let balance_pis = BalancePublicInputsTarget::from_vec(
            &balance_proof.public_inputs[0..BALANCE_PUBLIC_INPUTS_LEN],
        );
        let balance_circuit_vd =
            vd_from_pis_slice_target(&balance_proof.public_inputs, &balance_common_data.config)
                .expect("Failed to parse balance vd");
        builder.verify_proof::<C>(&balance_proof, &balance_circuit_vd, &balance_common_data);
        // check block hash inclusion of balance proof
        block_merkle_proof.verify::<F, C, D>(
            builder,
            &balance_pis.public_state.block_hash,
            balance_pis.public_state.block_number,
            public_state.block_tree_root,
        );

        // verify transfer inclusion
        let recipient = transfer.recipient.to_pubkey(builder);
        recipient.connect(builder, pubkey);
        let tx_hash = tx.hash::<F, C, D>(builder);
        balance_pis.last_tx_hash.connect(builder, tx_hash);
        transfer_merkle_proof.verify::<F, C, D>(
            builder,
            &transfer,
            transfer_index,
            tx.transfer_tree_root,
        );

        // verify private_state update
        let transfer_hash = transfer.hash::<F, C, D>(builder);
        let nullifier: Bytes32<Target> = Bytes32::<Target>::from_hash_out(builder, transfer_hash);
        let new_nullifier_tree_root = nullifier_proof.get_new_root::<F, C, D>(
            builder,
            prev_private_state.nullifier_tree_root,
            nullifier,
        );
        asset_merkle_proof.verify::<F, C, D>(
            builder,
            &prev_asset_leaf,
            transfer.token_index,
            prev_private_state.asset_tree_root,
        );
        let new_asset_leaf = AssetLeafTarget {
            is_insufficient: prev_asset_leaf.is_insufficient,
            amount: prev_asset_leaf.amount.add(builder, &transfer.amount),
        };
        let new_asset_tree_root =
            asset_merkle_proof.get_root::<F, C, D>(builder, &new_asset_leaf, transfer.token_index);

        let new_private_state = PrivateStateTarget {
            asset_tree_root: new_asset_tree_root,
            nullifier_tree_root: new_nullifier_tree_root,
            ..prev_private_state
        };
        let prev_private_commitment = prev_private_state.commitment(builder);
        let new_private_commitment = new_private_state.commitment(builder);

        ReceiveTransferTarget {
            pubkey,
            tx,
            transfer_merkle_proof,
            transfer_index,
            transfer,
            balance_circuit_vd,
            balance_proof,
            public_state,
            prev_private_state,
            new_private_state,
            prev_private_commitment,
            new_private_commitment,
            block_merkle_proof,
            nullifier_proof,
            prev_asset_leaf,
            asset_merkle_proof,
        }
    }

    pub fn set_witness<
        F: RichField + Extendable<D>,
        C: GenericConfig<D, F = F>,
        W: WitnessWrite<F>,
    >(
        &self,
        witness: &mut W,
        value: &ReceiveTransferValue<F, C, D>,
    ) where
        <C as GenericConfig<D>>::Hasher: AlgebraicHasher<F>,
    {
        self.pubkey.set_witness(witness, value.pubkey);
        self.transfer_merkle_proof
            .set_witness(witness, &value.transfer_merkle_proof);
        witness.set_target(
            self.transfer_index,
            F::from_canonical_usize(value.transfer_index),
        );
        self.transfer.set_witness(witness, value.transfer);
        // todo set balance circuit vd witness
        witness.set_proof_with_pis_target(&self.balance_proof, &value.balance_proof);
        self.public_state.set_witness(witness, &value.public_state);
        self.prev_private_state
            .set_witness(witness, &value.prev_private_state);
        self.new_private_state
            .set_witness(witness, &value.new_private_state);
        self.prev_private_commitment
            .set_witness(witness, value.prev_private_commitment);
        self.new_private_commitment
            .set_witness(witness, value.new_private_commitment);
        self.block_merkle_proof
            .set_witness(witness, &value.block_merkle_proof);
        self.nullifier_proof
            .set_witness(witness, &value.nullifier_proof);
        self.prev_asset_leaf
            .set_witness(witness, value.prev_asset_leaf);
        self.asset_merkle_proof
            .set_witness(witness, &value.asset_merkle_proof);
    }
}

pub struct ReceiveTransferCircuit<F, C, const D: usize>
where
    F: RichField + Extendable<D>,
    C: GenericConfig<D, F = F>,
{
    pub data: CircuitData<F, C, D>,
    pub target: ReceiveTransferTarget<D>,
    pub dummy_proof: DummyProof<F, C, D>,
}

impl<F, C, const D: usize> ReceiveTransferCircuit<F, C, D>
where
    F: RichField + Extendable<D>,
    C: GenericConfig<D, F = F> + 'static,
    C::Hasher: AlgebraicHasher<F>,
{
    pub fn new() -> Self {
        let config = CircuitConfig::default();
        let mut builder = CircuitBuilder::<F, D>::new(config.clone());
        let target = ReceiveTransferTarget::new::<F, C>(&mut builder, true);
        let pis = ReceiveTransferPublicInputsTarget {
            pubkey: target.pubkey,
            prev_private_commitment: target.prev_private_commitment,
            new_private_commitment: target.new_private_commitment,
            public_state: target.public_state.clone(),
            balance_circuit_vd: target.balance_circuit_vd.clone(),
        };
        builder.register_public_inputs(&pis.to_vec(&config));
        let data = builder.build();
        let dummy_proof = DummyProof::new(&data.common);
        Self {
            data,
            target,
            dummy_proof,
        }
    }

    pub fn prove(
        &self,
        value: &ReceiveTransferValue<F, C, D>,
    ) -> anyhow::Result<ProofWithPublicInputs<F, C, D>> {
        let mut pw = PartialWitness::<F>::new();
        self.target.set_witness(&mut pw, value);
        self.data.prove(pw)
    }
}

impl<F, C, const D: usize> Recursivable<F, C, D> for ReceiveTransferCircuit<F, C, D>
where
    F: RichField + Extendable<D>,
    C: GenericConfig<D, F = F> + 'static,
    C::Hasher: AlgebraicHasher<F>,
{
    fn circuit_data(&self) -> &CircuitData<F, C, D> {
        &self.data
    }
}
