use crate::{
    common::{
        hash::{get_pubkey_salt_hash, get_pubkey_salt_hash_circuit},
        private_state::{PrivateState, PrivateStateTarget},
        public_state::{PublicState, PublicStateTarget, PUBLIC_STATE_LEN},
        salt::{Salt, SaltTarget},
        trees::{
            asset_tree::{AssetLeaf, AssetLeafTarget, AssetMerkleProof, AssetMerkleProofTarget},
            deposit_tree::{
                DepositLeaf, DepositLeafTarget, DepositMerkleProof, DepositMerkleProofTarget,
            },
            nullifier_tree::{NullifierInsersionProof, NullifierInsersionProofTarget},
        },
    },
    constants::{ASSET_TREE_HEIGHT, DEPOSIT_TREE_HEIGHT},
    ethereum_types::{
        bytes32::Bytes32,
        u256::{U256, U256_LEN},
        u32limb_trait::{U32LimbTargetTrait as _, U32LimbTrait as _},
    },
    utils::poseidon_hash_out::{PoseidonHashOut, PoseidonHashOutTarget, POSEIDON_HASH_OUT_LEN},
};
use plonky2::{
    field::{extension::Extendable, types::Field},
    hash::hash_types::RichField,
    iop::{
        target::Target,
        witness::{PartialWitness, WitnessWrite},
    },
    plonk::{
        circuit_builder::CircuitBuilder,
        circuit_data::{CircuitConfig, CircuitData},
        config::{AlgebraicHasher, GenericConfig},
        proof::ProofWithPublicInputs,
    },
};

pub const RECEIVE_DEPOSIT_PUBLIC_INPUTS_LEN: usize =
    POSEIDON_HASH_OUT_LEN * 2 + U256_LEN + PUBLIC_STATE_LEN;

#[derive(Debug, Clone)]
pub struct ReceiveDepositPublicInputs {
    pub prev_private_commitment: PoseidonHashOut,
    pub new_private_commitment: PoseidonHashOut,
    pub pubkey: U256<u32>,
    pub public_state: PublicState,
}

impl ReceiveDepositPublicInputs {
    pub fn to_u64_vec(&self) -> Vec<u64> {
        let vec = vec![
            self.prev_private_commitment.to_u64_vec(),
            self.new_private_commitment.to_u64_vec(),
            self.pubkey.to_u64_vec(),
            self.public_state.to_u64_vec(),
        ]
        .concat();
        assert_eq!(vec.len(), RECEIVE_DEPOSIT_PUBLIC_INPUTS_LEN);
        vec
    }

    pub fn from_u64_vec(input: &[u64]) -> Self {
        let prev_private_commitment = PoseidonHashOut::from_u64_vec(&input[0..4]);
        let new_private_commitment = PoseidonHashOut::from_u64_vec(&input[4..8]);
        let pubkey = U256::from_u64_vec(&input[8..16]);
        let public_state = PublicState::from_u64_vec(&input[16..16 + PUBLIC_STATE_LEN]);
        ReceiveDepositPublicInputs {
            prev_private_commitment,
            new_private_commitment,
            pubkey,
            public_state,
        }
    }
}

#[derive(Debug, Clone)]
pub struct ReceiveDepositPublicInputsTarget {
    pub prev_private_commitment: PoseidonHashOutTarget,
    pub new_private_commitment: PoseidonHashOutTarget,
    pub pubkey: U256<Target>,
    pub public_state: PublicStateTarget,
}

impl ReceiveDepositPublicInputsTarget {
    pub fn to_vec(&self) -> Vec<Target> {
        let vec = vec![
            self.prev_private_commitment.to_vec(),
            self.new_private_commitment.to_vec(),
            self.pubkey.to_vec(),
            self.public_state.to_vec(),
        ]
        .concat();
        assert_eq!(vec.len(), RECEIVE_DEPOSIT_PUBLIC_INPUTS_LEN);
        vec
    }

    pub fn from_vec(input: &[Target]) -> Self {
        let prev_private_commitment = PoseidonHashOutTarget::from_vec(&input[0..4]);
        let new_private_commitment = PoseidonHashOutTarget::from_vec(&input[4..8]);
        let pubkey = U256::<Target>::from_limbs(&input[8..16]);
        let public_state = PublicStateTarget::from_vec(&input[16..16 + PUBLIC_STATE_LEN]);
        ReceiveDepositPublicInputsTarget {
            prev_private_commitment,
            new_private_commitment,
            pubkey,
            public_state,
        }
    }
}

#[derive(Debug, Clone)]
pub struct ReceiveDepositValue {
    pub pubkey: U256<u32>,
    pub deposit_salt: Salt,
    pub deposit_index: usize,
    pub deposit: DepositLeaf,
    pub deposit_merkle_proof: DepositMerkleProof,
    pub public_state: PublicState,
    pub prev_private_state: PrivateState,
    pub new_private_state: PrivateState,
    pub prev_private_commitment: PoseidonHashOut,
    pub new_private_commitment: PoseidonHashOut,
    pub nullifier_proof: NullifierInsersionProof,
    pub prev_asset_leaf: AssetLeaf,
    pub asset_merkle_proof: AssetMerkleProof,
}

impl ReceiveDepositValue {
    pub fn new(
        pubkey: U256<u32>,
        deposit_salt: Salt,
        deposit_index: usize,
        deposit: DepositLeaf,
        deposit_merkle_proof: DepositMerkleProof,
        public_state: PublicState,
        prev_private_state: PrivateState,
        nullifier_proof: NullifierInsersionProof,
        prev_asset_leaf: AssetLeaf,
        asset_merkle_proof: AssetMerkleProof,
    ) -> Self {
        // verify deposit inclusion
        let pubkey_salt_hash = get_pubkey_salt_hash(pubkey, deposit_salt);
        assert_eq!(pubkey_salt_hash, deposit.pubkey_salt_hash);
        deposit_merkle_proof
            .verify(&deposit, deposit_index, public_state.deposit_tree_root)
            .expect("Invalid deposit merkle proof");

        // verify private_state update
        let nullifier: Bytes32<u32> = deposit.poseidon_hash().into();
        let new_nullifier_tree_root = nullifier_proof
            .get_new_root(prev_private_state.nullifier_tree_root, nullifier)
            .expect("Invalid nullifier proof");
        asset_merkle_proof
            .verify(
                &prev_asset_leaf,
                deposit.token_index as usize,
                prev_private_state.asset_tree_root,
            )
            .expect("Invalid asset merkle proof");
        let new_asset_leaf = AssetLeaf {
            is_sufficient: prev_asset_leaf.is_sufficient,
            amount: prev_asset_leaf.amount + deposit.amount,
        };
        let new_asset_tree_root =
            asset_merkle_proof.get_root(&new_asset_leaf, deposit.token_index as usize);

        let new_private_state = PrivateState {
            asset_tree_root: new_asset_tree_root,
            nullifier_tree_root: new_nullifier_tree_root,
            ..prev_private_state
        };
        let prev_private_commitment = prev_private_state.commitment();
        let new_private_commitment = new_private_state.commitment();

        ReceiveDepositValue {
            pubkey,
            deposit_salt,
            deposit_index,
            deposit,
            deposit_merkle_proof,
            public_state,
            prev_private_state,
            new_private_state,
            prev_private_commitment,
            new_private_commitment,
            nullifier_proof,
            prev_asset_leaf,
            asset_merkle_proof,
        }
    }
}

#[derive(Debug, Clone)]
pub struct ReceiveDepositTarget {
    pub pubkey: U256<Target>,
    pub deposit_salt: SaltTarget,
    pub deposit_index: Target,
    pub deposit: DepositLeafTarget,
    pub deposit_merkle_proof: DepositMerkleProofTarget,
    pub public_state: PublicStateTarget,
    pub prev_private_state: PrivateStateTarget,
    pub new_private_state: PrivateStateTarget,
    pub prev_private_commitment: PoseidonHashOutTarget,
    pub new_private_commitment: PoseidonHashOutTarget,
    pub nullifier_proof: NullifierInsersionProofTarget,
    pub prev_asset_leaf: AssetLeafTarget,
    pub asset_merkle_proof: AssetMerkleProofTarget,
}

impl ReceiveDepositTarget {
    pub fn new<F: RichField + Extendable<D>, C: GenericConfig<D, F = F> + 'static, const D: usize>(
        builder: &mut CircuitBuilder<F, D>,
        is_checked: bool,
    ) -> Self
    where
        <C as GenericConfig<D>>::Hasher: AlgebraicHasher<F>,
    {
        let pubkey = U256::<Target>::new(builder, is_checked);
        let deposit_salt = SaltTarget::new(builder);
        let deposit_index = builder.add_virtual_target();
        let deposit = DepositLeafTarget::new(builder, is_checked);
        let deposit_merkle_proof = DepositMerkleProofTarget::new(builder, DEPOSIT_TREE_HEIGHT);
        let public_state = PublicStateTarget::new(builder, is_checked);
        let prev_private_state = PrivateStateTarget::new(builder);
        let nullifier_proof = NullifierInsersionProofTarget::new(builder, is_checked);
        let prev_asset_leaf = AssetLeafTarget::new(builder, is_checked);
        let asset_merkle_proof = AssetMerkleProofTarget::new(builder, ASSET_TREE_HEIGHT);

        // verify deposit inclusion
        let pubkey_salt_hash = get_pubkey_salt_hash_circuit(builder, pubkey, deposit_salt);
        pubkey_salt_hash.connect(builder, deposit.pubkey_salt_hash);
        deposit_merkle_proof.verify::<F, C, D>(
            builder,
            &deposit,
            deposit_index,
            public_state.deposit_tree_root,
        );

        // verify private_state update
        let deposit_hash = deposit.poseidon_hash(builder);
        let nullifier: Bytes32<Target> = Bytes32::<Target>::from_hash_out(builder, deposit_hash);
        let new_nullifier_tree_root = nullifier_proof.get_new_root::<F, C, D>(
            builder,
            prev_private_state.nullifier_tree_root,
            nullifier,
        );
        asset_merkle_proof.verify::<F, C, D>(
            builder,
            &prev_asset_leaf,
            deposit.token_index,
            prev_private_state.asset_tree_root,
        );
        let new_asset_leaf = AssetLeafTarget {
            is_sufficient: prev_asset_leaf.is_sufficient,
            amount: prev_asset_leaf.amount.add(builder, &deposit.amount),
        };
        let new_asset_tree_root =
            asset_merkle_proof.get_root::<F, C, D>(builder, &new_asset_leaf, deposit.token_index);

        let new_private_state = PrivateStateTarget {
            asset_tree_root: new_asset_tree_root,
            nullifier_tree_root: new_nullifier_tree_root,
            ..prev_private_state
        };
        let prev_private_commitment = prev_private_state.commitment(builder);
        let new_private_commitment = new_private_state.commitment(builder);

        ReceiveDepositTarget {
            pubkey,
            deposit_salt,
            deposit_index,
            deposit,
            deposit_merkle_proof,
            public_state,
            prev_private_state,
            new_private_state,
            prev_private_commitment,
            new_private_commitment,
            nullifier_proof,
            prev_asset_leaf,
            asset_merkle_proof,
        }
    }

    pub fn set_witness<W: WitnessWrite<F>, F: Field>(
        &self,
        witness: &mut W,
        value: &ReceiveDepositValue,
    ) {
        self.pubkey.set_witness(witness, value.pubkey);
        self.deposit_salt.set_witness(witness, value.deposit_salt);
        witness.set_target(
            self.deposit_index,
            F::from_canonical_usize(value.deposit_index),
        );
        self.deposit.set_witness(witness, &value.deposit);
        self.deposit_merkle_proof
            .set_witness(witness, &value.deposit_merkle_proof);
        self.public_state.set_witness(witness, &value.public_state);
        self.prev_private_state
            .set_witness(witness, &value.prev_private_state);
        self.new_private_state
            .set_witness(witness, &value.new_private_state);
        self.prev_private_commitment
            .set_witness(witness, value.prev_private_commitment);
        self.new_private_commitment
            .set_witness(witness, value.new_private_commitment);
        self.nullifier_proof
            .set_witness(witness, &value.nullifier_proof);
        self.prev_asset_leaf
            .set_witness(witness, value.prev_asset_leaf);
        self.asset_merkle_proof
            .set_witness(witness, &value.asset_merkle_proof);
    }
}

pub struct ReceiveDepositCircuit<F, C, const D: usize>
where
    F: RichField + Extendable<D>,
    C: GenericConfig<D, F = F>,
{
    pub data: CircuitData<F, C, D>,
    pub target: ReceiveDepositTarget,
}

impl<F, C, const D: usize> ReceiveDepositCircuit<F, C, D>
where
    F: RichField + Extendable<D>,
    C: GenericConfig<D, F = F> + 'static,
    C::Hasher: AlgebraicHasher<F>,
{
    pub fn new() -> Self {
        let config = CircuitConfig::default();
        let mut builder = CircuitBuilder::<F, D>::new(config.clone());
        let target = ReceiveDepositTarget::new::<F, C, D>(&mut builder, true);
        let pis = ReceiveDepositPublicInputsTarget {
            pubkey: target.pubkey,
            prev_private_commitment: target.prev_private_commitment,
            new_private_commitment: target.new_private_commitment,
            public_state: target.public_state.clone(),
        };
        builder.register_public_inputs(&pis.to_vec());
        dbg!(builder.num_gates());
        let data = builder.build();
        Self { data, target }
    }

    pub fn prove(
        &self,
        value: &ReceiveDepositValue,
    ) -> anyhow::Result<ProofWithPublicInputs<F, C, D>> {
        let mut pw = PartialWitness::<F>::new();
        self.target.set_witness(&mut pw, value);
        self.data.prove(pw)
    }
}
