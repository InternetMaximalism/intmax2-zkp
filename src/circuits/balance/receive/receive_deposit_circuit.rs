//! Receive Deposit Circuit for processing deposits into the private state.
//!
//! This circuit proves the correctness of adding a deposit to the asset tree and 
//! inserting the corresponding nullifier into the nullifier tree. The circuit ensures:
//! 1. Valid deposit merkle proof against the public state's deposit tree root
//! 2. Correct derivation of pubkey_salt_hash from the user's public key and salt
//! 3. Proper insertion of the nullifier into the nullifier tree
//! 4. Correct addition of the deposit to the asset tree
//!
//! This transition only updates the private state and does not modify the public state,
//! so no validity proof is required.

use super::error::ReceiveError;
use crate::{
    common::{
        deposit::{get_pubkey_salt_hash, get_pubkey_salt_hash_circuit, Deposit, DepositTarget},
        public_state::{PublicState, PublicStateTarget, PUBLIC_STATE_LEN},
        salt::{Salt, SaltTarget},
        trees::deposit_tree::{DepositMerkleProof, DepositMerkleProofTarget},
    },
    constants::DEPOSIT_TREE_HEIGHT,
    ethereum_types::{
        u256::{U256Target, U256, U256_LEN},
        u32limb_trait::{U32LimbTargetTrait as _, U32LimbTrait as _},
    },
    utils::{
        dummy::DummyProof,
        poseidon_hash_out::{PoseidonHashOut, PoseidonHashOutTarget, POSEIDON_HASH_OUT_LEN},
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

/// Public inputs for the receive deposit circuit.
///
/// These inputs are publicly verifiable and include:
/// - The previous and new private state commitments to prove valid state transition
/// - The user's public key for verification
/// - The public state containing the deposit tree root for deposit verification
#[derive(Debug, Clone)]
pub struct ReceiveDepositPublicInputs {
    pub prev_private_commitment: PoseidonHashOut,
    pub new_private_commitment: PoseidonHashOut,
    pub pubkey: U256,
    pub public_state: PublicState,
}

impl ReceiveDepositPublicInputs {
    pub fn to_u64_vec(&self) -> Result<Vec<u64>, ReceiveError> {
        let vec = [
            self.prev_private_commitment.to_u64_vec(),
            self.new_private_commitment.to_u64_vec(),
            self.pubkey.to_u64_vec(),
            self.public_state.to_u64_vec(),
        ]
        .concat();
        if vec.len() != RECEIVE_DEPOSIT_PUBLIC_INPUTS_LEN {
            return Err(ReceiveError::InvalidInput(format!(
                "ReceiveDepositPublicInputs length mismatch: expected {}, got {}",
                RECEIVE_DEPOSIT_PUBLIC_INPUTS_LEN,
                vec.len()
            )));
        }
        Ok(vec)
    }

    pub fn from_u64_slice(input: &[u64]) -> Result<Self, ReceiveError> {
        if input.len() != RECEIVE_DEPOSIT_PUBLIC_INPUTS_LEN {
            return Err(ReceiveError::InvalidInput(format!(
                "ReceiveDepositPublicInputs length mismatch: expected {}, got {}",
                RECEIVE_DEPOSIT_PUBLIC_INPUTS_LEN,
                input.len()
            )));
        }

        let prev_private_commitment = PoseidonHashOut::from_u64_slice(&input[0..4]);
        let new_private_commitment = PoseidonHashOut::from_u64_slice(&input[4..8]);
        let pubkey = U256::from_u64_slice(&input[8..16])
            .map_err(|e| ReceiveError::InvalidInput(format!("Failed to parse pubkey: {:?}", e)))?;
        let public_state = PublicState::from_u64_slice(&input[16..16 + PUBLIC_STATE_LEN]);

        Ok(ReceiveDepositPublicInputs {
            prev_private_commitment,
            new_private_commitment,
            pubkey,
            public_state,
        })
    }
}

/// Target version of ReceiveDepositPublicInputs for use in ZKP circuits.
///
/// Contains circuit targets for all public inputs needed to verify a deposit receipt,
/// matching the structure of ReceiveDepositPublicInputs.
#[derive(Debug, Clone)]
pub struct ReceiveDepositPublicInputsTarget {
    pub prev_private_commitment: PoseidonHashOutTarget,
    pub new_private_commitment: PoseidonHashOutTarget,
    pub pubkey: U256Target,
    pub public_state: PublicStateTarget,
}

impl ReceiveDepositPublicInputsTarget {
    pub fn to_vec(&self) -> Result<Vec<Target>, ReceiveError> {
        let vec = [
            self.prev_private_commitment.to_vec(),
            self.new_private_commitment.to_vec(),
            self.pubkey.to_vec(),
            self.public_state.to_vec(),
        ]
        .concat();
        if vec.len() != RECEIVE_DEPOSIT_PUBLIC_INPUTS_LEN {
            return Err(ReceiveError::InvalidInput(format!(
                "ReceiveDepositPublicInputsTarget length mismatch: expected {}, got {}",
                RECEIVE_DEPOSIT_PUBLIC_INPUTS_LEN,
                vec.len()
            )));
        }
        Ok(vec)
    }

    pub fn from_slice(input: &[Target]) -> Result<Self, ReceiveError> {
        if input.len() < RECEIVE_DEPOSIT_PUBLIC_INPUTS_LEN {
            return Err(ReceiveError::InvalidInput(
                format!("ReceiveDepositPublicInputsTarget input slice too short: expected at least {}, got {}", 
                    RECEIVE_DEPOSIT_PUBLIC_INPUTS_LEN, input.len())
            ));
        }

        let prev_private_commitment = PoseidonHashOutTarget::from_slice(&input[0..4]);
        let new_private_commitment = PoseidonHashOutTarget::from_slice(&input[4..8]);
        let pubkey = U256Target::from_slice(&input[8..16]);
        let public_state = PublicStateTarget::from_slice(&input[16..16 + PUBLIC_STATE_LEN]);
        Ok(ReceiveDepositPublicInputsTarget {
            prev_private_commitment,
            new_private_commitment,
            pubkey,
            public_state,
        })
    }
}

/// Value struct containing all data needed for the receive deposit circuit.
///
/// This struct holds all the values required to:
/// - Verify the deposit's inclusion in the deposit tree
/// - Verify the user's ownership of the deposit via pubkey and salt
/// - Process the private state transition (adding to asset tree and inserting nullifier)
#[derive(Debug, Clone)]
pub struct ReceiveDepositValue {
    pub pubkey: U256,                                   // User's public key
    pub deposit_salt: Salt,                             // Salt used to claim the deposit
    pub deposit_index: u32,                             // Index of the deposit in the deposit tree
    pub deposit: Deposit,                               // The deposit being claimed
    pub deposit_merkle_proof: DepositMerkleProof,       // Proof of deposit inclusion
    pub public_state: PublicState,                      // Current public state
    pub private_state_transition: PrivateStateTransitionValue, // Private state transition details
    pub prev_private_commitment: PoseidonHashOut,       // Previous private state commitment
    pub new_private_commitment: PoseidonHashOut,        // New private state commitment
}

impl ReceiveDepositValue {
    /// Creates a new ReceiveDepositValue by validating the deposit and private state transition.
    ///
    /// This function performs several critical verifications:
    /// 1. Verifies the pubkey and salt hash match the deposit's pubkey_salt_hash
    /// 2. Verifies the deposit's inclusion in the deposit tree using the merkle proof
    /// 3. Ensures the private state transition uses the correct token index, amount, and nullifier
    /// 4. Computes the previous and new private state commitments
    ///
    /// # Arguments
    /// * `pubkey` - User's public key claiming the deposit
    /// * `deposit_salt` - Salt used to claim the deposit
    /// * `deposit_index` - Index of the deposit in the deposit tree
    /// * `deposit` - The deposit being claimed
    /// * `deposit_merkle_proof` - Proof of deposit inclusion in the deposit tree
    /// * `public_state` - Current public state containing the deposit tree root
    /// * `private_state_transition` - Private state transition details
    ///
    /// # Returns
    /// A Result containing either the new ReceiveDepositValue or an error
    pub fn new(
        pubkey: U256,
        deposit_salt: Salt,
        deposit_index: u32,
        deposit: &Deposit,
        deposit_merkle_proof: &DepositMerkleProof,
        public_state: &PublicState,
        private_state_transition: &PrivateStateTransitionValue,
    ) -> Result<Self, ReceiveError> {
        // verify deposit inclusion
        let pubkey_salt_hash = get_pubkey_salt_hash(pubkey, deposit_salt);
        if pubkey_salt_hash != deposit.pubkey_salt_hash {
            return Err(ReceiveError::VerificationFailed(format!(
                "Invalid pubkey salt hash: expected {:?}, got {:?}",
                deposit.pubkey_salt_hash, pubkey_salt_hash
            )));
        }

        deposit_merkle_proof
            .verify(
                deposit,
                deposit_index as u64,
                public_state.deposit_tree_root,
            )
            .map_err(|e| {
                ReceiveError::VerificationFailed(format!("Invalid deposit merkle proof: {}", e))
            })?;

        let nullifier = deposit.nullifier();
        if deposit.token_index != private_state_transition.token_index {
            return Err(ReceiveError::VerificationFailed(format!(
                "Invalid token index: expected {}, got {}",
                private_state_transition.token_index, deposit.token_index
            )));
        }

        if deposit.amount != private_state_transition.amount {
            return Err(ReceiveError::VerificationFailed(format!(
                "Invalid amount: expected {}, got {}",
                private_state_transition.amount, deposit.amount
            )));
        }

        if nullifier != private_state_transition.nullifier {
            return Err(ReceiveError::VerificationFailed(format!(
                "Invalid nullifier: expected {:?}, got {:?}",
                private_state_transition.nullifier, nullifier
            )));
        }

        let prev_private_commitment = private_state_transition.prev_private_state.commitment();
        let new_private_commitment = private_state_transition.new_private_state.commitment();

        Ok(ReceiveDepositValue {
            pubkey,
            deposit_salt,
            deposit_index,
            deposit: deposit.clone(),
            deposit_merkle_proof: deposit_merkle_proof.clone(),
            public_state: public_state.clone(),
            private_state_transition: private_state_transition.clone(),
            prev_private_commitment,
            new_private_commitment,
        })
    }
}

/// Target version of ReceiveDepositValue for use in ZKP circuits.
///
/// Contains circuit targets for all components needed to verify a deposit receipt,
/// including deposit verification and private state transition.
#[derive(Debug, Clone)]
pub struct ReceiveDepositTarget {
    pub pubkey: U256Target,                             // User's public key target
    pub deposit_salt: SaltTarget,                       // Salt used to claim the deposit
    pub deposit_index: Target,                          // Index of the deposit in the tree
    pub deposit: DepositTarget,                         // The deposit being claimed
    pub deposit_merkle_proof: DepositMerkleProofTarget, // Proof of deposit inclusion
    pub public_state: PublicStateTarget,                // Current public state
    pub private_state_transition: PrivateStateTransitionTarget, // Private state transition
    pub prev_private_commitment: PoseidonHashOutTarget, // Previous private state commitment
    pub new_private_commitment: PoseidonHashOutTarget,  // New private state commitment
}

impl ReceiveDepositTarget {
    /// Creates a new ReceiveDepositTarget with circuit constraints that enforce
    /// the deposit receipt rules.
    ///
    /// The circuit enforces:
    /// 1. Valid pubkey_salt_hash derivation matching the deposit's pubkey_salt_hash
    /// 2. Valid deposit merkle proof against the public state's deposit tree root
    /// 3. Correct token index, amount, and nullifier in the private state transition
    /// 4. Proper computation of private state commitments
    ///
    /// # Arguments
    /// * `builder` - Circuit builder
    /// * `is_checked` - Whether to add constraints for checking the values
    ///
    /// # Returns
    /// A new ReceiveDepositTarget with all necessary targets and constraints
    pub fn new<F: RichField + Extendable<D>, C: GenericConfig<D, F = F> + 'static, const D: usize>(
        builder: &mut CircuitBuilder<F, D>,
        is_checked: bool,
    ) -> Self
    where
        <C as GenericConfig<D>>::Hasher: AlgebraicHasher<F>,
    {
        let pubkey = U256Target::new(builder, is_checked);
        let deposit_salt = SaltTarget::new(builder);
        let deposit_index = builder.add_virtual_target();
        let deposit = DepositTarget::new(builder, is_checked);
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
        let nullifier = deposit.nullifier(builder);
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

    /// Sets the witness values for all targets in this ReceiveDepositTarget.
    ///
    /// # Arguments
    /// * `witness` - Witness to set values in
    /// * `value` - ReceiveDepositValue containing the values to set
    pub fn set_witness<W: WitnessWrite<F>, F: Field>(
        &self,
        witness: &mut W,
        value: &ReceiveDepositValue,
    ) {
        self.pubkey.set_witness(witness, value.pubkey);
        self.deposit_salt.set_witness(witness, value.deposit_salt);
        witness.set_target(
            self.deposit_index,
            F::from_canonical_u32(value.deposit_index),
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

/// Main circuit for verifying deposit receipts and private state transitions.
///
/// This circuit combines all the components needed to verify that a deposit is:
/// 1. Valid and included in the deposit tree
/// 2. Owned by the user (via pubkey and salt)
/// 3. Correctly processed into the private state (asset tree and nullifier tree)
#[derive(Debug)]
pub struct ReceiveDepositCircuit<F, C, const D: usize>
where
    F: RichField + Extendable<D>,
    C: GenericConfig<D, F = F>,
{
    pub data: CircuitData<F, C, D>,           // Circuit data containing the compiled circuit
    pub target: ReceiveDepositTarget,          // Target containing all circuit constraints
    pub dummy_proof: DummyProof<F, C, D>,      // Dummy proof for testing
}

impl<F, C, const D: usize> Default for ReceiveDepositCircuit<F, C, D>
where
    F: RichField + Extendable<D>,
    C: GenericConfig<D, F = F> + 'static,
    C::Hasher: AlgebraicHasher<F>,
{
    fn default() -> Self {
        Self::new()
    }
}

impl<F, C, const D: usize> ReceiveDepositCircuit<F, C, D>
where
    F: RichField + Extendable<D>,
    C: GenericConfig<D, F = F> + 'static,
    C::Hasher: AlgebraicHasher<F>,
{
    /// Creates a new ReceiveDepositCircuit with all necessary constraints.
    ///
    /// This function:
    /// 1. Creates a new circuit builder with default configuration
    /// 2. Adds all targets and constraints via ReceiveDepositTarget
    /// 3. Registers the public inputs (prev/new commitments, pubkey, public state)
    /// 4. Builds the circuit and creates a dummy proof for testing
    ///
    /// # Returns
    /// A new ReceiveDepositCircuit ready for proving
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
        let pis_vec = pis
            .to_vec()
            .expect("Failed to convert public inputs to vector");
        builder.register_public_inputs(&pis_vec);
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

    /// Generates a ZK proof for the given ReceiveDepositValue.
    ///
    /// This function:
    /// 1. Creates a partial witness from the provided value
    /// 2. Sets all witness values in the circuit
    /// 3. Generates a proof that can be verified by anyone
    ///
    /// # Arguments
    /// * `value` - The ReceiveDepositValue containing all data needed for the proof
    ///
    /// # Returns
    /// A Result containing either the proof or an error if proof generation fails
    pub fn prove(
        &self,
        value: &ReceiveDepositValue,
    ) -> Result<ProofWithPublicInputs<F, C, D>, ReceiveError> {
        let mut pw = PartialWitness::<F>::new();
        self.target.set_witness(&mut pw, value);
        self.data.prove(pw).map_err(|e| {
            ReceiveError::ProofGenerationError(format!("Failed to generate proof: {:?}", e))
        })
    }
}

#[cfg(test)]
mod tests {
    use plonky2::{
        field::goldilocks_field::GoldilocksField, plonk::config::PoseidonGoldilocksConfig,
    };
    use rand::Rng as _;

    use crate::{
        circuits::{
            test_utils::witness_generator::construct_validity_and_tx_witness,
            validity::validity_pis::ValidityPublicInputs,
        },
        common::{
            deposit::{get_pubkey_salt_hash, Deposit},
            private_state::FullPrivateState,
            salt::Salt,
            signature_content::key_set::KeySet,
            trees::{
                account_tree::AccountTree, block_hash_tree::BlockHashTree,
                deposit_tree::DepositTree,
            },
            witness::private_transition_witness::PrivateTransitionWitness,
        },
        ethereum_types::{address::Address, u256::U256, u32limb_trait::U32LimbTrait as _},
    };

    use super::{ReceiveDepositCircuit, ReceiveDepositValue};

    type F = GoldilocksField;
    type C = PoseidonGoldilocksConfig;
    const D: usize = 2;

    #[test]
    fn test_receive_deposit_circuit() {
        let mut rng = rand::thread_rng();

        let mut account_tree = AccountTree::initialize();
        let mut block_tree = BlockHashTree::initialize();
        let mut deposit_tree = DepositTree::initialize();
        let prev_validity_pis = ValidityPublicInputs::genesis();

        let key = KeySet::rand(&mut rng);

        let deposit_salt = Salt::rand(&mut rng);
        let deposit_salt_hash = get_pubkey_salt_hash(key.pubkey, deposit_salt);
        let deposit = Deposit {
            depositor: Address::rand(&mut rng),
            pubkey_salt_hash: deposit_salt_hash,
            amount: U256::rand_small(&mut rng),
            token_index: rng.gen(),
            is_eligible: false,
        };
        let deposit_index = deposit_tree.len() as u32;
        deposit_tree.push(deposit.clone());

        // post empty block to sync account tree
        let (validity_witness, _) = construct_validity_and_tx_witness(
            prev_validity_pis,
            &mut account_tree,
            &mut block_tree,
            &deposit_tree,
            false,
            0,
            Address::default(),
            0,
            &[],
            0,
        )
        .unwrap();
        let validity_pis = validity_witness.to_validity_pis().unwrap();

        let mut full_private_state = FullPrivateState::new();
        let private_state_transition_witness = PrivateTransitionWitness::from_deposit(
            &mut full_private_state,
            &deposit,
            Salt::rand(&mut rng),
        )
        .unwrap();
        let deposit_merkle_proof = deposit_tree.prove(deposit_index as u64);
        let receive_deposit_value = ReceiveDepositValue::new(
            key.pubkey,
            deposit_salt,
            deposit_index,
            &deposit,
            &deposit_merkle_proof,
            &validity_pis.public_state,
            &private_state_transition_witness.to_value().unwrap(),
        )
        .unwrap();

        let receive_deposit_circuit = ReceiveDepositCircuit::<F, C, D>::new();
        let proof = receive_deposit_circuit
            .prove(&receive_deposit_value)
            .unwrap();
        receive_deposit_circuit.data.verify(proof.clone()).unwrap();
    }
}
