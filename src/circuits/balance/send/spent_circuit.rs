//! Spent circuit for validating and processing outgoing transfers.
//!
//! This circuit proves the transition of a private state by:
//! 1. Deducting transfer amounts from the sender's balance for each transfer in a transaction
//! 2. Setting insufficient_bit flags when balance is insufficient for a transfer
//! 3. Incrementing the nonce of the private state
//! 4. Validating that the transaction nonce matches the current private state nonce
//!
//! The spent circuit is a critical component in the sender verification process,
//! ensuring that users can only spend funds they actually have while maintaining
//! privacy. When insufficient balance is detected, the circuit continues processing
//! but flags the issue, allowing other assets in the same transaction to be processed
//! normally.

use plonky2::{
    field::{
        extension::Extendable,
        types::{Field, PrimeField64},
    },
    hash::hash_types::RichField,
    iop::{
        target::{BoolTarget, Target},
        witness::{PartialWitness, WitnessWrite},
    },
    plonk::{
        circuit_builder::CircuitBuilder,
        circuit_data::{CircuitConfig, CircuitData},
        config::{AlgebraicHasher, GenericConfig},
        proof::ProofWithPublicInputs,
    },
};

use crate::{
    common::{
        error::CommonError,
        insufficient_flags::{InsufficientFlags, InsufficientFlagsTarget, INSUFFICIENT_FLAGS_LEN},
        private_state::{PrivateState, PrivateStateTarget},
        salt::{Salt, SaltTarget},
        transfer::{Transfer, TransferTarget},
        trees::asset_tree::{AssetLeaf, AssetLeafTarget, AssetMerkleProof, AssetMerkleProofTarget},
        tx::{Tx, TxTarget, TX_LEN},
    },
    constants::{ASSET_TREE_HEIGHT, NUM_TRANSFERS_IN_TX, TRANSFER_TREE_HEIGHT},
    ethereum_types::u32limb_trait::{U32LimbTargetTrait, U32LimbTrait as _},
    utils::{
        conversion::ToU64,
        poseidon_hash_out::{PoseidonHashOut, PoseidonHashOutTarget, POSEIDON_HASH_OUT_LEN},
        trees::get_root::{get_merkle_root_from_leaves, get_merkle_root_from_leaves_circuit},
    },
};

/// Length of the public inputs for the spent circuit.
/// Includes commitments to previous and new private states, transaction data,
/// insufficient balance flags, and validity flag.
pub const SPENT_PUBLIC_INPUTS_LEN: usize =
    POSEIDON_HASH_OUT_LEN * 2 + TX_LEN + INSUFFICIENT_FLAGS_LEN + 1;

/// Public inputs for the spent circuit.
///
/// These values are publicly visible outputs of the circuit that can be verified
/// without knowing the private witness data.
#[derive(Clone, Debug)]
pub struct SpentPublicInputs {
    pub prev_private_commitment: PoseidonHashOut,
    pub new_private_commitment: PoseidonHashOut,
    pub tx: Tx,
    pub insufficient_flags: InsufficientFlags,
    pub is_valid: bool,
}

impl SpentPublicInputs {
    pub fn from_u64_slice(input: &[u64]) -> Result<Self, super::error::SendError> {
        if input.len() != SPENT_PUBLIC_INPUTS_LEN {
            return Err(super::error::SendError::InvalidInput(format!(
                "Invalid input length for SpentPublicInputs: expected {}, got {}",
                SPENT_PUBLIC_INPUTS_LEN,
                input.len()
            )));
        }
        let prev_private_commitment =
            PoseidonHashOut::from_u64_slice(&input[0..POSEIDON_HASH_OUT_LEN]).unwrap();
        let new_private_commitment = PoseidonHashOut::from_u64_slice(
            &input[POSEIDON_HASH_OUT_LEN..2 * POSEIDON_HASH_OUT_LEN],
        )
        .unwrap();
        let tx = Tx::from_u64_slice(
            &input[2 * POSEIDON_HASH_OUT_LEN..2 * POSEIDON_HASH_OUT_LEN + TX_LEN],
        )
        .unwrap();
        let insufficient_flags = InsufficientFlags::from_u64_slice(
            &input[2 * POSEIDON_HASH_OUT_LEN + TX_LEN
                ..2 * POSEIDON_HASH_OUT_LEN + TX_LEN + INSUFFICIENT_FLAGS_LEN],
        )
        .unwrap();
        let is_valid = input[2 * POSEIDON_HASH_OUT_LEN + TX_LEN + INSUFFICIENT_FLAGS_LEN] == 1;
        Ok(Self {
            prev_private_commitment,
            new_private_commitment,
            tx,
            insufficient_flags,
            is_valid,
        })
    }

    pub fn from_pis<F>(pis: &[F]) -> Result<Self, super::error::SendError>
    where
        F: PrimeField64,
    {
        Self::from_u64_slice(&pis.to_u64_vec())
    }
}

/// Target version of SpentPublicInputs for use in ZKP circuits.
///
/// This struct contains circuit targets for all components of the public inputs.
#[derive(Clone, Debug)]
pub struct SpentPublicInputsTarget {
    pub prev_private_commitment: PoseidonHashOutTarget,
    pub new_private_commitment: PoseidonHashOutTarget,
    pub tx: TxTarget,
    pub insufficient_flags: InsufficientFlagsTarget,
    pub is_valid: BoolTarget,
}

impl SpentPublicInputsTarget {
    /// Converts the target to a vector of individual targets.
    ///
    /// # Returns
    /// A vector of targets representing all public inputs
    pub fn to_vec(&self) -> Vec<Target> {
        let vec = [
            self.prev_private_commitment.to_vec(),
            self.new_private_commitment.to_vec(),
            self.tx.to_vec(),
            self.insufficient_flags.to_vec(),
            vec![self.is_valid.target],
        ]
        .concat();
        assert_eq!(vec.len(), SPENT_PUBLIC_INPUTS_LEN);
        vec
    }

    pub fn from_slice(input: &[Target]) -> Self {
        assert_eq!(input.len(), SPENT_PUBLIC_INPUTS_LEN);
        let prev_private_commitment =
            PoseidonHashOutTarget::from_slice(&input[0..POSEIDON_HASH_OUT_LEN]);
        let new_private_commitment = PoseidonHashOutTarget::from_slice(
            &input[POSEIDON_HASH_OUT_LEN..2 * POSEIDON_HASH_OUT_LEN],
        );
        let tx = TxTarget::from_slice(
            &input[2 * POSEIDON_HASH_OUT_LEN..2 * POSEIDON_HASH_OUT_LEN + TX_LEN],
        );
        let insufficient_flags = InsufficientFlagsTarget::from_slice(
            &input[2 * POSEIDON_HASH_OUT_LEN + TX_LEN
                ..2 * POSEIDON_HASH_OUT_LEN + TX_LEN + INSUFFICIENT_FLAGS_LEN],
        );
        let is_valid = BoolTarget::new_unsafe(
            input[2 * POSEIDON_HASH_OUT_LEN + TX_LEN + INSUFFICIENT_FLAGS_LEN],
        );
        Self {
            prev_private_commitment,
            new_private_commitment,
            tx,
            insufficient_flags,
            is_valid,
        }
    }
}

/// Witness values for the spent circuit.
///
/// This struct contains all the private witness data needed to prove the
/// validity of a transaction's spending operations.
#[derive(Clone, Debug)]
pub struct SpentValue {
    pub prev_private_state: PrivateState,
    pub new_private_state_salt: Salt,
    pub transfers: Vec<Transfer>,
    pub prev_balances: Vec<AssetLeaf>,
    pub asset_merkle_proofs: Vec<AssetMerkleProof>,
    pub prev_private_commitment: PoseidonHashOut,
    pub new_private_commitment: PoseidonHashOut,
    pub tx: Tx,
    pub insufficient_flags: InsufficientFlags,
    pub is_valid: bool,
}

/// Target version of SpentValue for use in ZKP circuits.
///
/// This struct contains circuit targets for all components needed to verify
/// the spending operations in a transaction.
#[derive(Clone, Debug)]
pub struct SpentTarget {
    pub prev_private_state: PrivateStateTarget,
    pub new_private_state_salt: SaltTarget,
    pub transfers: Vec<TransferTarget>,
    pub prev_balances: Vec<AssetLeafTarget>,
    pub asset_merkle_proofs: Vec<AssetMerkleProofTarget>,
    pub prev_private_commitment: PoseidonHashOutTarget,
    pub new_private_commitment: PoseidonHashOutTarget,
    pub tx: TxTarget,
    pub insufficient_flags: InsufficientFlagsTarget,
    pub is_valid: BoolTarget,
}

impl SpentValue {
    /// Creates a new SpentValue by validating and computing the state transition.
    ///
    /// This function:
    /// 1. Verifies all asset merkle proofs for the tokens being spent
    /// 2. Computes new balances by subtracting transfer amounts
    /// 3. Tracks insufficient balance cases with flags
    /// 4. Constructs the new private state with updated asset tree root and incremented nonce
    /// 5. Validates that the transaction nonce matches the current private state nonce
    ///
    /// # Arguments
    /// * `prev_private_state` - Previous private state
    /// * `prev_balances` - Previous asset leaves (balances) for the tokens
    /// * `new_private_state_salt` - New salt for the private state
    /// * `transfers` - Transfers to be processed
    /// * `asset_merkle_proofs` - Merkle proofs for the asset tree
    /// * `tx_nonce` - Nonce of the transaction
    ///
    /// # Returns
    /// A Result containing either the new SpentValue or an error
    pub fn new(
        prev_private_state: &PrivateState,
        prev_balances: &[AssetLeaf],
        new_private_state_salt: Salt,
        transfers: &[Transfer],
        asset_merkle_proofs: &[AssetMerkleProof],
        tx_nonce: u32,
    ) -> Result<Self, CommonError> {
        if prev_balances.len() != NUM_TRANSFERS_IN_TX {
            return Err(CommonError::InvalidData(
                "invalid number of balances".to_string(),
            ));
        }

        if transfers.len() != NUM_TRANSFERS_IN_TX {
            return Err(CommonError::InvalidData(
                "invalid number of transfers".to_string(),
            ));
        }

        if asset_merkle_proofs.len() != NUM_TRANSFERS_IN_TX {
            return Err(CommonError::InvalidData(
                "invalid number of proofs".to_string(),
            ));
        }
        let mut insufficient_bits = vec![];
        let mut asset_tree_root = prev_private_state.asset_tree_root;
        for ((transfer, proof), prev_balance) in transfers
            .iter()
            .zip(asset_merkle_proofs.iter())
            .zip(prev_balances.iter())
        {
            proof
                .verify(prev_balance, transfer.token_index as u64, asset_tree_root)
                .map_err(|e| {
                    CommonError::InvalidProof(format!(
                        "asset merkle proof verification failed: {}",
                        e
                    ))
                })?;
            let new_balance = prev_balance.sub(transfer.amount);
            asset_tree_root = proof.get_root(&new_balance, transfer.token_index as u64);
            insufficient_bits.push(new_balance.is_insufficient);
        }
        let insufficient_flags = InsufficientFlags::from_bits_be(&insufficient_bits).unwrap();
        let is_valid = tx_nonce == prev_private_state.nonce;
        let prev_private_commitment = prev_private_state.commitment();
        let new_private_state = PrivateState {
            asset_tree_root,
            prev_private_commitment,
            nonce: prev_private_state.nonce + 1,
            salt: new_private_state_salt,
            ..prev_private_state.clone()
        };
        let new_private_commitment = new_private_state.commitment();
        let transfer_tree_root = get_merkle_root_from_leaves(TRANSFER_TREE_HEIGHT, transfers)
            .map_err(|e| CommonError::InvalidData(e.to_string()))?;
        let tx = Tx {
            transfer_tree_root,
            nonce: tx_nonce,
        };
        Ok(Self {
            prev_private_state: prev_private_state.clone(),
            new_private_state_salt,
            transfers: transfers.to_vec(),
            prev_balances: prev_balances.to_vec(),
            asset_merkle_proofs: asset_merkle_proofs.to_vec(),
            prev_private_commitment,
            new_private_commitment,
            tx,
            insufficient_flags,
            is_valid,
        })
    }
}

impl SpentTarget {
    /// Creates a new SpentTarget with circuit constraints that enforce
    /// the spending rules and private state transition.
    ///
    /// The circuit enforces:
    /// 1. Valid asset merkle proofs for all tokens being spent
    /// 2. Correct computation of new balances by subtracting transfer amounts
    /// 3. Proper tracking of insufficient balance cases
    /// 4. Valid construction of the new private state with updated asset tree root
    /// 5. Correct nonce validation and incrementing
    ///
    /// # Arguments
    /// * `builder` - Circuit builder
    ///
    /// # Returns
    /// A new SpentTarget with all necessary targets and constraints
    pub fn new<F: RichField + Extendable<D>, C: GenericConfig<D, F = F> + 'static, const D: usize>(
        builder: &mut CircuitBuilder<F, D>,
    ) -> Self
    where
        <C as GenericConfig<D>>::Hasher: AlgebraicHasher<F>,
    {
        let tx_nonce = builder.add_virtual_target();
        let prev_private_state = PrivateStateTarget::new(builder);
        let new_private_state_salt = SaltTarget::new(builder);
        let transfers = (0..NUM_TRANSFERS_IN_TX)
            .map(|_| TransferTarget::new(builder, true))
            .collect::<Vec<_>>();
        let prev_balances = (0..NUM_TRANSFERS_IN_TX)
            .map(|_| AssetLeafTarget::new(builder, true))
            .collect::<Vec<_>>();
        let asset_merkle_proofs = (0..NUM_TRANSFERS_IN_TX)
            .map(|_| AssetMerkleProofTarget::new(builder, ASSET_TREE_HEIGHT))
            .collect::<Vec<_>>();
        let mut insufficient_bits = vec![];
        let mut asset_tree_root = prev_private_state.asset_tree_root;
        for ((transfer, proof), prev_balance) in transfers
            .iter()
            .zip(asset_merkle_proofs.iter())
            .zip(prev_balances.iter())
        {
            proof.verify::<F, C, D>(builder, prev_balance, transfer.token_index, asset_tree_root);
            let new_balance = prev_balance.sub(builder, transfer.amount);
            asset_tree_root =
                proof.get_root::<F, C, D>(builder, &new_balance, transfer.token_index);
            insufficient_bits.push(new_balance.is_insufficient);
        }
        let insufficient_flags = InsufficientFlagsTarget::from_bits_be(builder, &insufficient_bits);
        let is_valid = builder.is_equal(prev_private_state.nonce, tx_nonce);
        let prev_private_commitment = prev_private_state.commitment(builder);
        let one = builder.one();
        let new_private_state = PrivateStateTarget {
            asset_tree_root,
            prev_private_commitment,
            nonce: builder.add(prev_private_state.nonce, one),
            salt: new_private_state_salt,
            ..prev_private_state
        };
        let new_private_commitment = new_private_state.commitment(builder);
        let transfer_root = get_merkle_root_from_leaves_circuit::<F, C, D, _>(
            builder,
            TRANSFER_TREE_HEIGHT,
            &transfers,
        );
        let tx = TxTarget {
            transfer_tree_root: transfer_root,
            nonce: tx_nonce,
        };
        Self {
            prev_private_state,
            new_private_state_salt,
            transfers,
            prev_balances,
            asset_merkle_proofs,
            prev_private_commitment,
            new_private_commitment,
            tx,
            insufficient_flags,
            is_valid,
        }
    }

    /// Sets the witness values for all targets in this SpentTarget.
    ///
    /// # Arguments
    /// * `witness` - Witness to set values in
    /// * `value` - SpentValue containing the values to set
    pub fn set_witness<F: Field, W: WitnessWrite<F>>(&self, witness: &mut W, value: &SpentValue) {
        self.prev_private_state
            .set_witness(witness, &value.prev_private_state);
        self.new_private_state_salt
            .set_witness(witness, value.new_private_state_salt);
        for (transfer_t, transfer) in self.transfers.iter().zip(value.transfers.iter()) {
            transfer_t.set_witness(witness, *transfer);
        }
        for (balance_t, balance) in self.prev_balances.iter().zip(value.prev_balances.iter()) {
            balance_t.set_witness(witness, *balance);
        }
        for (proof_t, proof) in self
            .asset_merkle_proofs
            .iter()
            .zip(value.asset_merkle_proofs.iter())
        {
            proof_t.set_witness(witness, proof);
        }
        self.prev_private_commitment
            .set_witness(witness, value.prev_private_commitment);
        self.new_private_commitment
            .set_witness(witness, value.new_private_commitment);
        self.tx.set_witness(witness, value.tx);
        witness.set_bool_target(self.is_valid, value.is_valid);
    }
}

/// The spent circuit for validating and processing outgoing transfers.
///
/// This circuit proves that:
/// 1. Each transfer amount is deducted from the sender's balance
/// 2. Insufficient balance cases are properly flagged
/// 3. The nonce is incremented in the new private state
/// 4. The transaction nonce matches the current private state nonce (is_valid)
#[derive(Debug)]
pub struct SpentCircuit<F, C, const D: usize>
where
    F: RichField + Extendable<D>,
    C: GenericConfig<D, F = F>,
{
    pub data: CircuitData<F, C, D>,
    pub target: SpentTarget,
}

impl<F, C, const D: usize> Default for SpentCircuit<F, C, D>
where
    F: RichField + Extendable<D>,
    C: GenericConfig<D, F = F> + 'static,
    C::Hasher: AlgebraicHasher<F>,
{
    fn default() -> Self {
        Self::new()
    }
}

impl<F, C, const D: usize> SpentCircuit<F, C, D>
where
    F: RichField + Extendable<D>,
    C: GenericConfig<D, F = F> + 'static,
    C::Hasher: AlgebraicHasher<F>,
{
    pub fn new() -> Self {
        let mut builder =
            CircuitBuilder::<F, D>::new(CircuitConfig::standard_recursion_zk_config());
        let target = SpentTarget::new::<F, C, D>(&mut builder);
        let pis = SpentPublicInputsTarget {
            prev_private_commitment: target.prev_private_commitment,
            new_private_commitment: target.new_private_commitment,
            tx: target.tx.clone(),
            insufficient_flags: target.insufficient_flags,
            is_valid: target.is_valid,
        };
        builder.register_public_inputs(&pis.to_vec());
        let data = builder.build();
        Self { data, target }
    }

    pub fn prove(&self, value: &SpentValue) -> Result<ProofWithPublicInputs<F, C, D>, CommonError> {
        let mut pw = PartialWitness::<F>::new();
        self.target.set_witness(&mut pw, value);
        self.data
            .prove(pw)
            .map_err(|e| CommonError::InvalidProof(e.to_string()))
    }
}

#[cfg(test)]
mod tests {
    // Test module for the spent circuit
    use plonky2::{
        field::goldilocks_field::GoldilocksField, plonk::config::PoseidonGoldilocksConfig,
    };

    use crate::{
        common::{
            private_state::PrivateState,
            salt::Salt,
            transfer::Transfer,
            trees::asset_tree::{AssetLeaf, AssetTree},
        },
        constants::{ASSET_TREE_HEIGHT, NUM_TRANSFERS_IN_TX},
        ethereum_types::u256::U256,
    };

    use super::{SpentCircuit, SpentValue};

    type F = GoldilocksField;
    const D: usize = 2;
    type C = PoseidonGoldilocksConfig;

    /// Tests the spent circuit with randomly generated data.
    ///
    /// This test:
    /// 1. Creates a random asset tree with random balances
    /// 2. Creates random transfers for each token
    /// 3. Generates merkle proofs for each asset
    /// 4. Creates a SpentValue with valid nonce
    /// 5. Generates and verifies a ZK proof
    #[test]
    fn test_spent_circuit() {
        let mut rng = rand::thread_rng();
        let mut asset_tree = AssetTree::new(ASSET_TREE_HEIGHT);
        let prev_balances = (0..NUM_TRANSFERS_IN_TX)
            .map(|_| AssetLeaf::rand(&mut rng))
            .collect::<Vec<_>>();
        for (i, balance) in prev_balances.iter().enumerate() {
            asset_tree.update(i as u64, *balance);
        }
        let prev_private_state = PrivateState {
            asset_tree_root: asset_tree.get_root(),
            nonce: 12,
            ..PrivateState::new()
        };
        let transfers = (0..NUM_TRANSFERS_IN_TX)
            .map(|i| Transfer {
                recipient: U256::rand(&mut rng).into(),
                token_index: i as u32,
                amount: U256::rand_small(&mut rng), // small amount to avoid overflow
                salt: Salt::rand(&mut rng),
            })
            .collect::<Vec<_>>();
        let mut asset_merkle_proofs = Vec::with_capacity(NUM_TRANSFERS_IN_TX);
        for (index, (transfer, prev_balance)) in
            transfers.iter().zip(prev_balances.iter()).enumerate()
        {
            assert_eq!(*prev_balance, asset_tree.get_leaf(index as u64));
            let proof = asset_tree.prove(transfer.token_index as u64);
            let new_balance = prev_balance.sub(transfer.amount);
            asset_tree.update(transfer.token_index as u64, new_balance);
            asset_merkle_proofs.push(proof);
        }
        let new_private_state_salt = Salt::rand(&mut rng);
        let value = SpentValue::new(
            &prev_private_state,
            &prev_balances,
            new_private_state_salt,
            &transfers,
            &asset_merkle_proofs,
            prev_private_state.nonce,
        )
        .expect("failed to create spent value");
        assert!(value.is_valid);
        let circuit = SpentCircuit::<F, C, D>::new();
        let instant = std::time::Instant::now();
        let proof = circuit.prove(&value).unwrap();
        circuit.data.verify(proof).unwrap();
        dbg!(instant.elapsed());
        dbg!(circuit.data.common.degree_bits());
    }
}
