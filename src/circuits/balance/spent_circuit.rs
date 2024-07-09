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

use crate::{
    common::{
        private_state::{PrivateState, PrivateStateTarget},
        transfer::{Transfer, TransferTarget},
        trees::asset_tree::{AssetLeaf, AssetLeafTarget, AssetMerkleProof, AssetMerkleProofTarget},
    },
    constants::{ASSET_TREE_HEIGHT, NUM_TRANSFERS_IN_TX, TRANSFER_TREE_HEIGHT},
    utils::{
        poseidon_hash_out::{PoseidonHashOut, PoseidonHashOutTarget, POSEIDON_HASH_OUT_LEN},
        trees::get_root::{get_merkle_root_from_leaves, get_merkle_root_from_leaves_circuit},
    },
};

pub const SPENT_PUBLIC_INPUTS_LEN: usize = POSEIDON_HASH_OUT_LEN * 3;

#[derive(Clone, Debug)]
pub struct SpentPublicInputs {
    pub prev_private_commitment: PoseidonHashOut,
    pub new_private_commitment: PoseidonHashOut,
    pub transfer_root: PoseidonHashOut,
}

#[derive(Clone, Debug)]
pub struct SpentPublicInputsTarget {
    pub prev_private_commitment: PoseidonHashOutTarget,
    pub new_private_commitment: PoseidonHashOutTarget,
    pub transfer_root: PoseidonHashOutTarget,
}

impl SpentPublicInputsTarget {
    pub fn to_vec(&self) -> Vec<Target> {
        let vec = vec![
            self.prev_private_commitment.to_vec(),
            self.new_private_commitment.to_vec(),
            self.transfer_root.to_vec(),
        ]
        .concat();
        assert_eq!(vec.len(), SPENT_PUBLIC_INPUTS_LEN);
        vec
    }
}

#[derive(Clone, Debug)]
pub struct SpentValue {
    pub prev_private_state: PrivateState,
    pub transfers: Vec<Transfer>,
    pub prev_balances: Vec<AssetLeaf>,
    pub asset_merkle_proofs: Vec<AssetMerkleProof>,
    pub prev_private_commitment: PoseidonHashOut,
    pub new_private_commitment: PoseidonHashOut,
    pub transfer_root: PoseidonHashOut,
}

#[derive(Clone, Debug)]
pub struct SpentTarget {
    pub prev_private_state: PrivateStateTarget,
    pub transfers: Vec<TransferTarget>,
    pub prev_balances: Vec<AssetLeafTarget>,
    pub asset_merkle_proofs: Vec<AssetMerkleProofTarget>,
    pub prev_private_commitment: PoseidonHashOutTarget,
    pub new_private_commitment: PoseidonHashOutTarget,
    pub transfer_root: PoseidonHashOutTarget,
}

impl SpentValue {
    pub fn new(
        prev_private_state: PrivateState,
        prev_balances: Vec<AssetLeaf>,
        transfers: Vec<Transfer>,
        asset_merkle_proofs: Vec<AssetMerkleProof>,
    ) -> Self {
        assert_eq!(prev_balances.len(), NUM_TRANSFERS_IN_TX);
        assert_eq!(transfers.len(), NUM_TRANSFERS_IN_TX);
        assert_eq!(asset_merkle_proofs.len(), NUM_TRANSFERS_IN_TX);
        let mut asset_tree_root = prev_private_state.asset_tree_root;
        for ((transfer, proof), prev_balance) in transfers
            .iter()
            .zip(asset_merkle_proofs.iter())
            .zip(prev_balances.iter())
        {
            let mut balance = *prev_balance;
            proof
                .verify(prev_balance, transfer.token_index as usize, asset_tree_root)
                .expect("asset merkle proof verification failed");
            balance.sub(transfer.amount);
            asset_tree_root = proof.get_root(&balance, transfer.token_index as usize);
        }
        let new_private_state = PrivateState {
            asset_tree_root,
            ..prev_private_state
        };
        let prev_private_commitment = prev_private_state.commitment();
        let new_private_commitment = new_private_state.commitment();
        let transfer_root = get_merkle_root_from_leaves(TRANSFER_TREE_HEIGHT, &transfers);
        Self {
            prev_private_state,
            transfers,
            prev_balances,
            asset_merkle_proofs,
            prev_private_commitment,
            new_private_commitment,
            transfer_root,
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
        let prev_private_state = PrivateStateTarget::new(builder);
        let transfers = (0..NUM_TRANSFERS_IN_TX)
            .map(|_| TransferTarget::new(builder, true))
            .collect::<Vec<_>>();
        let prev_balances = (0..NUM_TRANSFERS_IN_TX)
            .map(|_| AssetLeafTarget::new(builder, true))
            .collect::<Vec<_>>();
        let asset_merkle_proofs = (0..NUM_TRANSFERS_IN_TX)
            .map(|_| AssetMerkleProofTarget::new(builder, ASSET_TREE_HEIGHT))
            .collect::<Vec<_>>();
        let mut asset_tree_root = prev_private_state.asset_tree_root;
        for ((transfer, proof), prev_balance) in transfers
            .iter()
            .zip(asset_merkle_proofs.iter())
            .zip(prev_balances.iter())
        {
            let mut balance = prev_balance.clone();
            proof.verify::<F, C, D>(builder, prev_balance, transfer.token_index, asset_tree_root);
            balance.sub(builder, transfer.amount);
            asset_tree_root = proof.get_root::<F, C, D>(builder, &balance, transfer.token_index);
        }
        let new_private_state = PrivateStateTarget {
            asset_tree_root,
            ..prev_private_state
        };
        let prev_private_commitment = prev_private_state.commitment(builder);
        let new_private_commitment = new_private_state.commitment(builder);
        let transfer_root = get_merkle_root_from_leaves_circuit::<F, C, D, _>(
            builder,
            TRANSFER_TREE_HEIGHT,
            &transfers,
        );
        Self {
            prev_private_state,
            transfers,
            prev_balances,
            asset_merkle_proofs,
            prev_private_commitment,
            new_private_commitment,
            transfer_root,
        }
    }

    pub fn set_witness<F: Field, W: WitnessWrite<F>>(&self, witness: &mut W, value: &SpentValue) {
        self.prev_private_state
            .set_witness(witness, &value.prev_private_state);
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
        self.transfer_root.set_witness(witness, value.transfer_root);
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
            transfer_root: target.transfer_root,
        };
        builder.register_public_inputs(&pis.to_vec());
        dbg!(builder.num_gates());
        let data = builder.build();
        Self { data, target }
    }

    pub fn prove(&self, value: &SpentValue) -> anyhow::Result<ProofWithPublicInputs<F, C, D>> {
        let mut pw = PartialWitness::<F>::new();
        self.target.set_witness(&mut pw, value);
        self.data.prove(pw)
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
        for balance in prev_balances.iter() {
            asset_tree.push(*balance);
        }
        let prev_private_state = PrivateState {
            asset_tree_root: asset_tree.get_root(),
            ..PrivateState::default()
        };
        let transfers = (0..NUM_TRANSFERS_IN_TX)
            .map(|i| Transfer {
                recipient: GenericAddress::rand(&mut rng),
                token_index: i as u32,
                amount: U256::rand_small(&mut rng), // small amount to avoid overflow
                salt: Salt::rand(&mut rng),
            })
            .collect::<Vec<_>>();
        let mut asset_merkle_proofs = Vec::with_capacity(NUM_TRANSFERS_IN_TX);
        for (transfer, prev_balance) in transfers.iter().zip(prev_balances.iter()) {
            let mut balance = *prev_balance;
            let proof = asset_tree.prove(transfer.token_index as usize);
            balance.sub(transfer.amount);
            asset_tree.update(transfer.token_index as usize, balance);
            asset_merkle_proofs.push(proof);
        }
        let value = SpentValue::new(
            prev_private_state,
            prev_balances,
            transfers,
            asset_merkle_proofs,
        );
        let circuit = SpentCircuit::<F, C, D>::new();
        let instant = std::time::Instant::now();
        let _proof = circuit.prove(&value).unwrap();
        dbg!(instant.elapsed());

        dbg!(circuit.data.common.degree_bits());
    }
}
