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
    circuits::mining::{
        determine_lock_time::DetermineLockTimeValue,
        utils::{get_mining_deposit_nullifier, get_mining_deposit_nullifier_circuit},
    },
    common::{
        block::{Block, BlockTarget},
        deposit::{get_pubkey_salt_hash, get_pubkey_salt_hash_circuit, Deposit, DepositTarget},
        salt::{Salt, SaltTarget},
        trees::deposit_tree::{DepositMerkleProof, DepositMerkleProofTarget},
    },
    constants::DEPOSIT_TREE_HEIGHT,
    ethereum_types::{
        bytes32::{Bytes32, Bytes32Target, BYTES32_LEN},
        u256::{U256Target, U256, U256_LEN},
        u32limb_trait::{U32LimbTargetTrait as _, U32LimbTrait},
        u64::{U64Target, U64, U64_LEN},
    },
    utils::leafable::{Leafable, LeafableTarget},
};

use super::determine_lock_time::DetermineLockTimeTarget;

const START_TIME_PUBLIC_INPUTS_LEN: usize = U256_LEN + BYTES32_LEN + 1 + U64_LEN + BYTES32_LEN + 1;

#[derive(Debug, Clone)]
pub struct StartTimePublicInputs {
    pub pubkey: U256,
    pub nullifier: Bytes32,
    pub lock_time: u32,
    pub block_timestamp: u64,
    pub block_hash: Bytes32,
    pub block_number: u32,
}

impl StartTimePublicInputs {
    pub fn to_vec_u32(&self) -> Vec<u32> {
        let mut result = self.pubkey.to_u32_vec();
        result.push(self.lock_time);
        result.extend_from_slice(&self.nullifier.to_u32_vec());
        result.extend_from_slice(&U64::from(self.block_timestamp).to_u32_vec());
        result.extend_from_slice(&self.block_hash.to_u32_vec());
        result.push(self.block_number);
        assert_eq!(result.len(), START_TIME_PUBLIC_INPUTS_LEN);
        result
    }

    pub fn from_u32_slice(inputs: &[u32]) -> Self {
        assert_eq!(inputs.len(), START_TIME_PUBLIC_INPUTS_LEN);
        let pubkey = U256::from_u32_slice(&inputs[0..U256_LEN]);
        let nullifier = Bytes32::from_u32_slice(&inputs[U256_LEN..U256_LEN + BYTES32_LEN]);
        let lock_time = inputs[U256_LEN + BYTES32_LEN];
        let block_timestamp = U64::from_u32_slice(
            &inputs[U256_LEN + BYTES32_LEN + 1..U256_LEN + BYTES32_LEN + 1 + U64_LEN],
        );
        let block_hash = Bytes32::from_u32_slice(
            &inputs[U256_LEN + BYTES32_LEN + 1 + U64_LEN
                ..U256_LEN + BYTES32_LEN + 1 + U64_LEN + BYTES32_LEN],
        );
        let block_number = inputs[U256_LEN + BYTES32_LEN + 1 + U64_LEN + BYTES32_LEN];
        Self {
            pubkey,
            nullifier,
            lock_time,
            block_timestamp: block_timestamp.into(),
            block_hash,
            block_number,
        }
    }
}

#[derive(Debug, Clone)]
pub struct StartTimePublicInputsTarget {
    pub pubkey: U256Target,
    pub nullifier: Bytes32Target,
    pub lock_time: Target,
    pub block_timestamp: U64Target,
    pub block_hash: Bytes32Target,
    pub block_number: Target,
}

impl StartTimePublicInputsTarget {
    pub fn to_vec(&self) -> Vec<Target> {
        let mut result = self.pubkey.to_vec();
        result.push(self.lock_time);
        result.extend_from_slice(&self.nullifier.to_vec());
        result.extend_from_slice(&self.block_timestamp.to_vec());
        result.extend_from_slice(&self.block_hash.to_vec());
        result.push(self.block_number);
        assert_eq!(result.len(), START_TIME_PUBLIC_INPUTS_LEN);
        result
    }

    pub fn from_slice(inputs: &[Target]) -> Self {
        assert_eq!(inputs.len(), START_TIME_PUBLIC_INPUTS_LEN);
        let pubkey = U256Target::from_slice(&inputs[0..U256_LEN]);
        let nullifier = Bytes32Target::from_slice(&inputs[U256_LEN..U256_LEN + BYTES32_LEN]);
        let lock_time = inputs[U256_LEN + BYTES32_LEN];
        let block_timestamp = U64Target::from_slice(
            &inputs[U256_LEN + BYTES32_LEN + 1..U256_LEN + BYTES32_LEN + 1 + U64_LEN],
        );
        let block_hash = Bytes32Target::from_slice(
            &inputs[U256_LEN + BYTES32_LEN + 1 + U64_LEN
                ..U256_LEN + BYTES32_LEN + 1 + U64_LEN + BYTES32_LEN],
        );
        let block_number = inputs[U256_LEN + BYTES32_LEN + 1 + U64_LEN + BYTES32_LEN];
        Self {
            pubkey,
            nullifier,
            lock_time,
            block_timestamp: block_timestamp.into(),
            block_hash,
            block_number,
        }
    }
}

pub struct StartTimeValue {
    pub prev_block: Block,
    pub block: Block,
    pub prev_deposit_merkle_proof: DepositMerkleProof,
    pub deposit_merkle_proof: DepositMerkleProof,
    pub deposit: Deposit,
    pub deposit_index: u32,
    pub deposit_salt: Salt,
    pub block_hash: Bytes32,
    pub pubkey: U256,
    pub nullifier: Bytes32,
    pub determine_lock_time_value: DetermineLockTimeValue,
}

impl StartTimeValue {
    pub fn new(
        prev_block: Block,
        block: Block,
        prev_deposit_merkle_proof: DepositMerkleProof,
        deposit_merkle_proof: DepositMerkleProof,
        deposit: Deposit,
        deposit_index: u32,
        deposit_salt: Salt,
        pubkey: U256,
    ) -> anyhow::Result<Self> {
        // deposit non-inclusion proof of prev_deposit_merkle_proof
        prev_deposit_merkle_proof
            .verify(
                &Deposit::empty_leaf(),
                deposit_index as u64,
                prev_block.deposit_tree_root,
            )
            .map_err(|e| anyhow::anyhow!("prev_deposit_merkle_proof.verify failed: {:?}", e))?;
        // deposit inclusion proof of deposit_merkle_proof
        deposit_merkle_proof
            .verify(&deposit, deposit_index as u64, block.deposit_tree_root)
            .map_err(|e| anyhow::anyhow!("deposit_merkle_proof.verify failed: {:?}", e))?;
        // ensure that prev_block is the parent of block
        if prev_block.hash() != block.prev_block_hash {
            return Err(anyhow::anyhow!(
                "prev_block.hash() != block.prev_block_hash"
            ));
        }
        // proving that the deposit is bound to the pubkey
        let pubkey_salt_hash = get_pubkey_salt_hash(pubkey, deposit_salt);
        if pubkey_salt_hash != deposit.pubkey_salt_hash {
            return Err(anyhow::anyhow!(
                "pubkey_salt_hash != deposit.pubkey_salt_hash"
            ));
        }

        let nullifier = get_mining_deposit_nullifier(&deposit, deposit_salt);
        let block_hash = block.hash();
        let determine_lock_time_value = DetermineLockTimeValue::new(block_hash, deposit_salt);

        Ok(Self {
            prev_block,
            block,
            prev_deposit_merkle_proof,
            deposit_merkle_proof,
            deposit,
            deposit_index,
            deposit_salt,
            block_hash,
            pubkey,
            nullifier,
            determine_lock_time_value,
        })
    }
}

#[derive(Debug, Clone)]
pub struct StartTimeTarget {
    pub prev_block: BlockTarget,
    pub block: BlockTarget,
    pub prev_deposit_merkle_proof: DepositMerkleProofTarget,
    pub deposit_merkle_proof: DepositMerkleProofTarget,
    pub deposit: DepositTarget,
    pub deposit_index: Target,
    pub deposit_salt: SaltTarget,
    pub block_hash: Bytes32Target,
    pub pubkey: U256Target,
    pub nullifier: Bytes32Target,
    pub determine_lock_time_target: DetermineLockTimeTarget,
}

impl StartTimeTarget {
    pub fn new<F: RichField + Extendable<D>, C: GenericConfig<D, F = F> + 'static, const D: usize>(
        builder: &mut CircuitBuilder<F, D>,
        is_checked: bool,
    ) -> Self
    where
        <C as GenericConfig<D>>::Hasher: AlgebraicHasher<F>,
    {
        let prev_block = BlockTarget::new(builder, is_checked);
        let block = BlockTarget::new(builder, is_checked);
        let prev_deposit_merkle_proof = DepositMerkleProofTarget::new(builder, DEPOSIT_TREE_HEIGHT);
        let deposit_merkle_proof = DepositMerkleProofTarget::new(builder, DEPOSIT_TREE_HEIGHT);
        let deposit = DepositTarget::new(builder, is_checked);
        let deposit_index = builder.add_virtual_target();
        if is_checked {
            builder.range_check(deposit_index, 32);
        }
        let deposit_salt = SaltTarget::new(builder);
        let pubkey = U256Target::new(builder, is_checked);

        let empty_deposit = DepositTarget::empty_leaf(builder);
        prev_deposit_merkle_proof.verify::<F, C, D>(
            builder,
            &empty_deposit,
            deposit_index,
            prev_block.deposit_tree_root,
        );
        deposit_merkle_proof.verify::<F, C, D>(
            builder,
            &deposit,
            deposit_index,
            block.deposit_tree_root,
        );
        let prev_block_hash = prev_block.hash::<F, C, D>(builder);
        prev_block_hash.connect(builder, block.prev_block_hash);
        let pubkey_salt_hash = get_pubkey_salt_hash_circuit(builder, pubkey, deposit_salt);
        pubkey_salt_hash.connect(builder, deposit.pubkey_salt_hash);

        let nullifier = get_mining_deposit_nullifier_circuit(builder, &deposit, deposit_salt);
        let block_hash = block.hash::<F, C, D>(builder);

        let determine_lock_time_target = DetermineLockTimeTarget::new(builder, is_checked);
        determine_lock_time_target
            .block_hash
            .connect(builder, block_hash);
        determine_lock_time_target
            .deposit_salt
            .connect(builder, deposit_salt);
        Self {
            prev_block,
            block,
            prev_deposit_merkle_proof,
            deposit_merkle_proof,
            deposit,
            deposit_index,
            deposit_salt,
            block_hash,
            pubkey,
            nullifier,
            determine_lock_time_target,
        }
    }

    pub fn set_witness<W: WitnessWrite<F>, F: Field>(
        &self,
        witness: &mut W,
        value: &StartTimeValue,
    ) {
        self.prev_block.set_witness(witness, &value.prev_block);
        self.block.set_witness(witness, &value.block);
        self.prev_deposit_merkle_proof
            .set_witness(witness, &value.prev_deposit_merkle_proof);
        self.deposit_merkle_proof
            .set_witness(witness, &value.deposit_merkle_proof);
        self.deposit.set_witness(witness, &value.deposit);
        witness.set_target(
            self.deposit_index,
            F::from_canonical_u32(value.deposit_index),
        );
        self.deposit_salt.set_witness(witness, value.deposit_salt);
        self.block_hash.set_witness(witness, value.block_hash);
        self.pubkey.set_witness(witness, value.pubkey);
        self.nullifier.set_witness(witness, value.nullifier);
        self.determine_lock_time_target
            .set_witness(witness, &value.determine_lock_time_value);
    }
}

#[derive(Debug)]
pub struct StartTimeCircuit<F, C, const D: usize>
where
    F: RichField + Extendable<D>,
    C: GenericConfig<D, F = F>,
{
    pub data: CircuitData<F, C, D>,
    pub target: StartTimeTarget,
}

impl<F, C, const D: usize> StartTimeCircuit<F, C, D>
where
    F: RichField + Extendable<D>,
    C: GenericConfig<D, F = F> + 'static,
    C::Hasher: AlgebraicHasher<F>,
{
    pub fn new() -> Self {
        let config = CircuitConfig::default();
        let mut builder = CircuitBuilder::<F, D>::new(config.clone());
        let target = StartTimeTarget::new::<F, C, D>(&mut builder, true);
        let pis = StartTimePublicInputsTarget {
            pubkey: target.pubkey,
            nullifier: target.nullifier,
            lock_time: target.determine_lock_time_target.lock_time,
            block_timestamp: target.block.timestamp,
            block_hash: target.block_hash,
            block_number: target.block.block_number,
        };
        builder.register_public_inputs(&pis.to_vec());
        let data = builder.build();
        Self { data, target }
    }

    pub fn prove(&self, value: &StartTimeValue) -> anyhow::Result<ProofWithPublicInputs<F, C, D>> {
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
    use rand::Rng as _;

    use crate::{
        common::{
            block::Block,
            deposit::{get_pubkey_salt_hash, Deposit},
            salt::Salt,
            trees::deposit_tree::DepositTree,
        },
        constants::DEPOSIT_TREE_HEIGHT,
        ethereum_types::{
            address::Address, bytes32::Bytes32, u256::U256, u32limb_trait::U32LimbTrait,
        },
    };

    type F = GoldilocksField;
    type C = PoseidonGoldilocksConfig;
    const D: usize = 2;

    #[test]
    fn test_start_time_circuit() {
        let mut rng = rand::thread_rng();

        let pubkey = U256::rand(&mut rng);
        let deposit_salt = Salt::rand(&mut rng);
        let pubkey_salt_hash = get_pubkey_salt_hash(pubkey, deposit_salt);
        let deposit_index = 100;

        let mut deposit_tree = DepositTree::new(DEPOSIT_TREE_HEIGHT);
        let deposit = Deposit {
            depositor: Address::rand(&mut rng),
            pubkey_salt_hash,
            amount: U256::rand(&mut rng),
            token_index: rng.gen(),
            is_eligible: true,
        };

        let prev_block = Block {
            prev_block_hash: Bytes32::rand(&mut rng),
            deposit_tree_root: deposit_tree.get_root(),
            signature_hash: Bytes32::rand(&mut rng),
            timestamp: 0.into(),
            block_number: 1,
        };
        let prev_deposit_merkle_proof = deposit_tree.prove(deposit_index as u64);
        // add random deposits to the tree
        for _ in 0..deposit_index {
            deposit_tree.push(Deposit::rand(&mut rng));
        }
        deposit_tree.push(deposit.clone());
        for _ in 0..deposit_index {
            deposit_tree.push(Deposit::rand(&mut rng));
        }
        let block = Block {
            prev_block_hash: prev_block.hash(),
            deposit_tree_root: deposit_tree.get_root(),
            signature_hash: Bytes32::rand(&mut rng),
            timestamp: 111.into(),
            block_number: 2,
        };
        let deposit_merkle_proof = deposit_tree.prove(deposit_index as u64);

        let value = super::StartTimeValue::new(
            prev_block,
            block,
            prev_deposit_merkle_proof,
            deposit_merkle_proof,
            deposit,
            deposit_index,
            deposit_salt,
            pubkey,
        )
        .unwrap();

        let circuit = super::StartTimeCircuit::<F, C, D>::new();
        let _proof = circuit.prove(&value).unwrap();
    }
}
