use crate::{
    common::{
        hash::{get_pubkey_salt_hash, get_pubkey_salt_hash_circuit},
        public_state::{PublicState, PublicStateTarget, PUBLIC_STATE_LEN},
        salt::{Salt, SaltTarget},
        trees::deposit_tree::{
            DepositLeaf, DepositLeafTarget, DepositMerkleProof, DepositMerkleProofTarget,
        },
    },
    constants::DEPOSIT_TREE_HEIGHT,
    ethereum_types::{
        bytes32::Bytes32,
        u256::{U256, U256_LEN},
        u32limb_trait::{U32LimbTargetTrait as _, U32LimbTrait as _},
    },
    utils::{
        dummy::DummyProof,
        poseidon_hash_out::{PoseidonHashOut, PoseidonHashOutTarget, POSEIDON_HASH_OUT_LEN},
        recursivable::Recursivable,
    },
};
use plonky2::{
    field::{extension::Extendable, types::Field},
    gates::constant::ConstantGate,
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

use super::receive_targets::private_state_transition::{
    PrivateStateTransitionTarget, PrivateStateTransitionValue,
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
    pub private_state_transition: PrivateStateTransitionValue,
    pub prev_private_commitment: PoseidonHashOut,
    pub new_private_commitment: PoseidonHashOut,
}

impl ReceiveDepositValue {
    pub fn new(
        pubkey: U256<u32>,
        deposit_salt: Salt,
        deposit_index: usize,
        deposit: &DepositLeaf,
        deposit_merkle_proof: &DepositMerkleProof,
        public_state: &PublicState,
        private_state_transition: &PrivateStateTransitionValue,
    ) -> Self {
        // verify deposit inclusion
        let pubkey_salt_hash = get_pubkey_salt_hash(pubkey, deposit_salt);
        assert_eq!(pubkey_salt_hash, deposit.pubkey_salt_hash);
        deposit_merkle_proof
            .verify(&deposit, deposit_index, public_state.deposit_tree_root)
            .expect("Invalid deposit merkle proof");

        let nullifier: Bytes32<u32> = deposit.poseidon_hash().into();
        assert_eq!(deposit.token_index, private_state_transition.token_index);
        assert_eq!(deposit.amount, private_state_transition.amount);
        assert_eq!(nullifier, private_state_transition.nullifier);

        let prev_private_commitment = private_state_transition.prev_private_state.commitment();
        let new_private_commitment = private_state_transition.new_private_state.commitment();

        ReceiveDepositValue {
            pubkey,
            deposit_salt,
            deposit_index,
            deposit: deposit.clone(),
            deposit_merkle_proof: deposit_merkle_proof.clone(),
            public_state: public_state.clone(),
            private_state_transition: private_state_transition.clone(),
            prev_private_commitment,
            new_private_commitment,
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
    pub private_state_transition: PrivateStateTransitionTarget,
    pub prev_private_commitment: PoseidonHashOutTarget,
    pub new_private_commitment: PoseidonHashOutTarget,
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
        let private_state_transition =
            PrivateStateTransitionTarget::new::<F, C, D>(builder, is_checked);

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
        builder.connect(deposit.token_index, private_state_transition.token_index);
        deposit
            .amount
            .connect(builder, private_state_transition.amount);
        nullifier.connect(builder, private_state_transition.nullifier);
        let prev_private_commitment = private_state_transition
            .prev_private_state
            .commitment(builder);
        let new_private_commitment = private_state_transition
            .new_private_state
            .commitment(builder);
        ReceiveDepositTarget {
            pubkey,
            deposit_salt,
            deposit_index,
            deposit,
            deposit_merkle_proof,
            public_state,
            private_state_transition,
            prev_private_commitment,
            new_private_commitment,
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
        self.private_state_transition
            .set_witness(witness, &value.private_state_transition);
        self.prev_private_commitment
            .set_witness(witness, value.prev_private_commitment);
        self.new_private_commitment
            .set_witness(witness, value.new_private_commitment);
    }
}

pub struct ReceiveDepositCircuit<F, C, const D: usize>
where
    F: RichField + Extendable<D>,
    C: GenericConfig<D, F = F>,
{
    pub data: CircuitData<F, C, D>,
    pub target: ReceiveDepositTarget,
    pub dummy_proof: DummyProof<F, C, D>,
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
        // add constant gate
        let constant_gate = ConstantGate::new(config.num_constants);
        builder.add_gate(constant_gate, vec![]);
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
        value: &ReceiveDepositValue,
    ) -> anyhow::Result<ProofWithPublicInputs<F, C, D>> {
        let mut pw = PartialWitness::<F>::new();
        self.target.set_witness(&mut pw, value);
        self.data.prove(pw)
    }
}

impl<F, C, const D: usize> Recursivable<F, C, D> for ReceiveDepositCircuit<F, C, D>
where
    F: RichField + Extendable<D>,
    C: GenericConfig<D, F = F> + 'static,
    C::Hasher: AlgebraicHasher<F>,
{
    fn circuit_data(&self) -> &CircuitData<F, C, D> {
        &self.data
    }
}
