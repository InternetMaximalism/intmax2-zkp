use plonky2::{
    field::{extension::Extendable, types::Field},
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
        poseidon_hash_out::{PoseidonHashOut, PoseidonHashOutTarget, POSEIDON_HASH_OUT_LEN},
        recursivable::Recursivable,
        trees::get_root::{get_merkle_root_from_leaves, get_merkle_root_from_leaves_circuit},
    },
};

pub const SPENT_PUBLIC_INPUTS_LEN: usize =
    POSEIDON_HASH_OUT_LEN * 2 + TX_LEN + INSUFFICIENT_FLAGS_LEN + 1;

#[derive(Clone, Debug)]
pub struct SpentPublicInputs {
    pub prev_private_commitment: PoseidonHashOut,
    pub new_private_commitment: PoseidonHashOut,
    pub tx: Tx,
    pub insufficient_flags: InsufficientFlags,
    pub is_valid: bool,
}

impl SpentPublicInputs {
    pub fn from_u64_vec(input: &[u64]) -> Self {
        assert_eq!(input.len(), SPENT_PUBLIC_INPUTS_LEN);
        let prev_private_commitment =
            PoseidonHashOut::from_u64_vec(&input[0..POSEIDON_HASH_OUT_LEN]);
        let new_private_commitment =
            PoseidonHashOut::from_u64_vec(&input[POSEIDON_HASH_OUT_LEN..2 * POSEIDON_HASH_OUT_LEN]);
        let tx =
            Tx::from_u64_vec(&input[2 * POSEIDON_HASH_OUT_LEN..2 * POSEIDON_HASH_OUT_LEN + TX_LEN]);
        let insufficient_flags = InsufficientFlags::from_u64_vec(
            &input[2 * POSEIDON_HASH_OUT_LEN + TX_LEN
                ..2 * POSEIDON_HASH_OUT_LEN + TX_LEN + INSUFFICIENT_FLAGS_LEN],
        );
        let is_valid = input[2 * POSEIDON_HASH_OUT_LEN + TX_LEN + INSUFFICIENT_FLAGS_LEN] == 1;
        Self {
            prev_private_commitment,
            new_private_commitment,
            tx,
            insufficient_flags,
            is_valid,
        }
    }
}

#[derive(Clone, Debug)]
pub struct SpentPublicInputsTarget {
    pub prev_private_commitment: PoseidonHashOutTarget,
    pub new_private_commitment: PoseidonHashOutTarget,
    pub tx: TxTarget,
    pub insufficient_flags: InsufficientFlagsTarget,
    pub is_valid: BoolTarget,
}

impl SpentPublicInputsTarget {
    pub fn to_vec(&self) -> Vec<Target> {
        let vec = vec![
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

    pub fn from_vec(input: &[Target]) -> Self {
        assert_eq!(input.len(), SPENT_PUBLIC_INPUTS_LEN);
        let prev_private_commitment =
            PoseidonHashOutTarget::from_vec(&input[0..POSEIDON_HASH_OUT_LEN]);
        let new_private_commitment = PoseidonHashOutTarget::from_vec(
            &input[POSEIDON_HASH_OUT_LEN..2 * POSEIDON_HASH_OUT_LEN],
        );
        let tx = TxTarget::from_vec(
            &input[2 * POSEIDON_HASH_OUT_LEN..2 * POSEIDON_HASH_OUT_LEN + TX_LEN],
        );
        let insufficient_flags = InsufficientFlagsTarget::from_limbs(
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

#[derive(Clone, Debug)]
pub struct SpentValue {
    pub prev_private_state: PrivateState,
    pub new_salt: Salt,
    pub transfers: Vec<Transfer>,
    pub prev_balances: Vec<AssetLeaf>,
    pub asset_merkle_proofs: Vec<AssetMerkleProof>,
    pub prev_private_commitment: PoseidonHashOut,
    pub new_private_commitment: PoseidonHashOut,
    pub tx: Tx,
    pub insufficient_flags: InsufficientFlags,
    pub is_valid: bool,
}

#[derive(Clone, Debug)]
pub struct SpentTarget {
    pub prev_private_state: PrivateStateTarget,
    pub new_salt: SaltTarget,
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
    pub fn new(
        prev_private_state: &PrivateState,
        prev_balances: &[AssetLeaf],
        new_salt: Salt,
        transfers: &[Transfer],
        asset_merkle_proofs: &[AssetMerkleProof],
        tx_nonce: u32,
    ) -> Self {
        assert_eq!(prev_balances.len(), NUM_TRANSFERS_IN_TX);
        assert_eq!(transfers.len(), NUM_TRANSFERS_IN_TX);
        assert_eq!(asset_merkle_proofs.len(), NUM_TRANSFERS_IN_TX);
        let mut insufficient_bits = vec![];
        let mut asset_tree_root = prev_private_state.asset_tree_root;
        for ((transfer, proof), prev_balance) in transfers
            .iter()
            .zip(asset_merkle_proofs.iter())
            .zip(prev_balances.iter())
        {
            proof
                .verify(prev_balance, transfer.token_index as usize, asset_tree_root)
                .expect("asset merkle proof verification failed");
            let new_balance = prev_balance.sub(transfer.amount);
            asset_tree_root = proof.get_root(&new_balance, transfer.token_index as usize);
            insufficient_bits.push(new_balance.is_insufficient);
        }
        let insufficient_flags = InsufficientFlags::from_bits_le(&insufficient_bits);
        let is_valid = tx_nonce == prev_private_state.nonce;
        let new_private_state = PrivateState {
            asset_tree_root,
            nonce: prev_private_state.nonce + 1,
            salt: new_salt,
            ..prev_private_state.clone()
        };
        let prev_private_commitment = prev_private_state.commitment();
        let new_private_commitment = new_private_state.commitment();
        let transfer_root = get_merkle_root_from_leaves(TRANSFER_TREE_HEIGHT, &transfers);
        let tx = Tx {
            transfer_tree_root: transfer_root,
            nonce: tx_nonce,
        };
        Self {
            prev_private_state: prev_private_state.clone(),
            new_salt,
            transfers: transfers.to_vec(),
            prev_balances: prev_balances.to_vec(),
            asset_merkle_proofs: asset_merkle_proofs.to_vec(),
            prev_private_commitment,
            new_private_commitment,
            tx,
            insufficient_flags,
            is_valid,
        }
    }
}

impl SpentTarget {
    pub fn new<F: RichField + Extendable<D>, C: GenericConfig<D, F = F> + 'static, const D: usize>(
        builder: &mut CircuitBuilder<F, D>,
    ) -> Self
    where
        <C as GenericConfig<D>>::Hasher: AlgebraicHasher<F>,
    {
        let tx_nonce = builder.add_virtual_target();
        let prev_private_state = PrivateStateTarget::new(builder);
        let new_salt = SaltTarget::new(builder);
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
        let insufficient_flags = InsufficientFlagsTarget::from_bits_le(builder, &insufficient_bits);
        let is_valid = builder.is_equal(prev_private_state.nonce, tx_nonce);
        let one = builder.one();
        let new_private_state = PrivateStateTarget {
            asset_tree_root,
            nonce: builder.add(prev_private_state.nonce, one),
            salt: new_salt,
            ..prev_private_state
        };
        let prev_private_commitment = prev_private_state.commitment(builder);
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
            new_salt,
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

    pub fn set_witness<F: Field, W: WitnessWrite<F>>(&self, witness: &mut W, value: &SpentValue) {
        self.prev_private_state
            .set_witness(witness, &value.prev_private_state);
        self.new_salt.set_witness(witness, value.new_salt);
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

pub struct SpentCircuit<F, C, const D: usize>
where
    F: RichField + Extendable<D>,
    C: GenericConfig<D, F = F>,
{
    pub data: CircuitData<F, C, D>,
    pub target: SpentTarget,
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

    pub fn prove(&self, value: &SpentValue) -> anyhow::Result<ProofWithPublicInputs<F, C, D>> {
        let mut pw = PartialWitness::<F>::new();
        self.target.set_witness(&mut pw, value);
        self.data.prove(pw)
    }
}

impl<F, C, const D: usize> Recursivable<F, C, D> for SpentCircuit<F, C, D>
where
    F: RichField + Extendable<D>,
    C: GenericConfig<D, F = F> + 'static,
    C::Hasher: AlgebraicHasher<F>,
{
    fn circuit_data(&self) -> &CircuitData<F, C, D> {
        &self.data
    }
}

#[cfg(test)]
mod tests {
    use plonky2::{
        field::goldilocks_field::GoldilocksField, plonk::config::PoseidonGoldilocksConfig,
    };

    use crate::{
        common::{
            generic_address::GenericAddress,
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

    #[test]
    fn spent_circuit() {
        let mut rng = rand::thread_rng();
        let mut asset_tree = AssetTree::new(ASSET_TREE_HEIGHT);
        let prev_balances = (0..NUM_TRANSFERS_IN_TX)
            .map(|_| AssetLeaf::rand(&mut rng))
            .collect::<Vec<_>>();
        for (i, balance) in prev_balances.iter().enumerate() {
            asset_tree.update(i, *balance);
        }
        let prev_private_state = PrivateState {
            asset_tree_root: asset_tree.get_root(),
            nonce: 12,
            ..PrivateState::new()
        };
        let transfers = (0..NUM_TRANSFERS_IN_TX)
            .map(|i| Transfer {
                recipient: GenericAddress::rand_pubkey(&mut rng),
                token_index: i as u32,
                amount: U256::rand_small(&mut rng), // small amount to avoid overflow
                salt: Salt::rand(&mut rng),
            })
            .collect::<Vec<_>>();
        let mut asset_merkle_proofs = Vec::with_capacity(NUM_TRANSFERS_IN_TX);
        for (index, (transfer, prev_balance)) in
            transfers.iter().zip(prev_balances.iter()).enumerate()
        {
            assert_eq!(*prev_balance, asset_tree.get_leaf(index));
            let proof = asset_tree.prove(transfer.token_index as usize);
            let new_balance = prev_balance.sub(transfer.amount);
            asset_tree.update(transfer.token_index as usize, new_balance);
            asset_merkle_proofs.push(proof);
        }
        let new_salt = Salt::rand(&mut rng);
        let value = SpentValue::new(
            &prev_private_state,
            &prev_balances,
            new_salt,
            &transfers,
            &asset_merkle_proofs,
            prev_private_state.nonce,
        );
        assert!(value.is_valid);
        let circuit = SpentCircuit::<F, C, D>::new();
        let instant = std::time::Instant::now();
        let _proof = circuit.prove(&value).unwrap();
        dbg!(instant.elapsed());
        dbg!(value.insufficient_flags);
        dbg!(circuit.data.common.degree_bits());
    }
}
