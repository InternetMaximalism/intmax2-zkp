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
        proof::{ProofWithPublicInputs, ProofWithPublicInputsTarget},
    },
};
use plonky2_keccak::{builder::BuilderKeccak256, utils::solidity_keccak256};

use crate::{
    common::{
        salt::{Salt, SaltTarget},
        trees::deposit_tree::{
            DepositLeaf, DepositLeafTarget, DepositMerkleProof, DepositMerkleProofTarget,
        },
    },
    constants::DEPOSIT_TREE_HEIGHT,
    ethereum_types::{
        bytes32::Bytes32,
        u256::U256,
        u32limb_trait::{U32LimbTargetTrait as _, U32LimbTrait as _},
    },
    utils::poseidon_hash_out::{PoseidonHashOut, PoseidonHashOutTarget},
};

pub struct SimpleWithdrawPublicInputs {
    pub deposit_root: Bytes32<u32>,
    pub nullifier: Bytes32<u32>, // nullifier = hash(pubkey, zero_salt)
    pub token_index: u32,
    pub amount: U256<u32>,
}

pub struct SimpleWithdrawPublicInputsTarget {
    pub deposit_root: Bytes32<Target>,
    pub nullifier: Bytes32<Target>,
    pub token_index: Target,
    pub amount: U256<Target>,
}

impl SimpleWithdrawPublicInputs {
    pub fn to_u32_vec(&self) -> Vec<u32> {
        let vec = vec![
            self.deposit_root.limbs(),
            self.nullifier.limbs(),
            vec![self.token_index],
            self.amount.limbs(),
        ]
        .concat();
        vec
    }

    pub fn hash(&self) -> Bytes32<u32> {
        let vec = self.to_u32_vec();
        Bytes32::<u32>::from_limbs(&solidity_keccak256(&vec))
    }
}

impl SimpleWithdrawPublicInputsTarget {
    pub fn to_vec(&self) -> Vec<Target> {
        let vec = vec![
            self.deposit_root.limbs(),
            self.nullifier.limbs(),
            vec![self.token_index],
            self.amount.limbs(),
        ]
        .concat();
        vec
    }

    pub fn hash<
        F: RichField + Extendable<D>,
        C: GenericConfig<D, F = F> + 'static,
        const D: usize,
    >(
        &self,
        builder: &mut CircuitBuilder<F, D>,
    ) -> Bytes32<Target>
    where
        <C as GenericConfig<D>>::Hasher: AlgebraicHasher<F>,
    {
        let inputs = self.to_vec();
        Bytes32::<Target>::from_limbs(&builder.keccak256::<C>(&inputs))
    }
}

pub struct SimpleWithdrawValue {
    pub deposit_root: Bytes32<u32>,
    pub deposit_index: u32,
    pub deposit_leaf: DepositLeaf,
    pub deposit_merkle_proof: DepositMerkleProof,
    pub nullifier: Bytes32<u32>,
    pub pubkey: U256<u32>,
    pub salt: Salt,
}

pub struct SimpleWithdrawTarget {
    pub deposit_root: Bytes32<Target>,
    pub deposit_index: Target,
    pub deposit_leaf: DepositLeafTarget,
    pub deposit_merkle_proof: DepositMerkleProofTarget,
    pub nullifier: Bytes32<Target>,
    pub pubkey: U256<Target>,
    pub salt: SaltTarget,
}

impl SimpleWithdrawValue {
    pub fn new(
        deposit_root: Bytes32<u32>,
        deposit_index: u32,
        deposit_leaf: DepositLeaf,
        deposit_merkle_proof: DepositMerkleProof,
        pubkey: U256<u32>,
        salt: Salt,
    ) -> Self {
        let pubkey_salt_hash = get_pubkey_salt_hash(pubkey, salt);
        assert_eq!(
            pubkey_salt_hash, deposit_leaf.pubkey_salt_hash,
            "pubkey_salt_hash mismatch"
        );
        deposit_merkle_proof
            .verify(&deposit_leaf, deposit_index as usize, deposit_root)
            .expect("deposit_merkle_proof verify failed");
        let nullifier = get_pubkey_salt_hash(pubkey, Salt::default());
        Self {
            deposit_root,
            deposit_index,
            deposit_leaf,
            deposit_merkle_proof,
            nullifier,
            pubkey,
            salt,
        }
    }
}

impl SimpleWithdrawTarget {
    pub fn new<F: RichField + Extendable<D>, C: GenericConfig<D, F = F> + 'static, const D: usize>(
        builder: &mut CircuitBuilder<F, D>,
    ) -> Self
    where
        <C as GenericConfig<D>>::Hasher: AlgebraicHasher<F>,
    {
        let pubkey = U256::new(builder, true);
        let salt = SaltTarget::new(builder);
        let deposit_index = builder.add_virtual_target();
        // range check is done on the contract
        let deposit_leaf = DepositLeafTarget::new(builder, false);
        let deposit_merkle_proof = DepositMerkleProofTarget::new(builder, DEPOSIT_TREE_HEIGHT);
        // range check is done on the contracts
        let deposit_root = Bytes32::<Target>::new(builder, false);
        deposit_merkle_proof.verify::<F, C, D>(builder, &deposit_leaf, deposit_index, deposit_root);
        let pubkey_salt_hash = get_pubkey_salt_hash_circuit(builder, pubkey, salt);
        deposit_leaf
            .pubkey_salt_hash
            .connect(builder, pubkey_salt_hash);
        let default_salt = SaltTarget::constant(builder, Salt::default());
        let nullifier = get_pubkey_salt_hash_circuit(builder, pubkey, default_salt);
        Self {
            deposit_root,
            deposit_index,
            deposit_leaf,
            deposit_merkle_proof,
            nullifier,
            pubkey,
            salt,
        }
    }

    pub fn set_witness<F: Field, W: WitnessWrite<F>>(
        &self,
        witness: &mut W,
        value: &SimpleWithdrawValue,
    ) {
        self.deposit_root.set_witness(witness, value.deposit_root);
        witness.set_target(
            self.deposit_index,
            F::from_canonical_u32(value.deposit_index),
        );
        self.deposit_leaf.set_witness(witness, &value.deposit_leaf);
        self.deposit_merkle_proof
            .set_witness(witness, &value.deposit_merkle_proof);
        self.nullifier.set_witness(witness, value.nullifier);
        self.pubkey.set_witness(witness, value.pubkey);
        self.salt.set_witness(witness, value.salt);
    }
}

pub fn get_pubkey_salt_hash(pubkey: U256<u32>, salt: Salt) -> Bytes32<u32> {
    let input = vec![pubkey.to_u64_vec(), salt.to_u64_vec()].concat();
    let hash = PoseidonHashOut::hash_inputs_u64(&input);
    hash.into()
}

pub fn get_pubkey_salt_hash_circuit<F: RichField + Extendable<D>, const D: usize>(
    builder: &mut CircuitBuilder<F, D>,
    pubkey: U256<Target>,
    salt: SaltTarget,
) -> Bytes32<Target> {
    let inputs = vec![pubkey.to_vec(), salt.to_vec()].concat();
    let hash = PoseidonHashOutTarget::hash_inputs(builder, &inputs);
    Bytes32::<Target>::from_hash_out(builder, hash)
}

pub struct SimpleWithdrawCircuit<
    F: RichField + Extendable<D>,
    C: GenericConfig<D, F = F>,
    const D: usize,
> {
    pub target: SimpleWithdrawTarget,
    pub data: CircuitData<F, C, D>,
}

impl<F: RichField + Extendable<D>, C: GenericConfig<D, F = F> + 'static, const D: usize>
    SimpleWithdrawCircuit<F, C, D>
where
    <C as GenericConfig<D>>::Hasher: AlgebraicHasher<F>,
{
    pub fn new() -> Self {
        let mut builder = CircuitBuilder::<F, D>::new(CircuitConfig::default());
        let target = SimpleWithdrawTarget::new::<F, C, D>(&mut builder);
        let pis = SimpleWithdrawPublicInputsTarget {
            deposit_root: target.deposit_root,
            nullifier: target.nullifier,
            token_index: target.deposit_leaf.token_index,
            amount: target.deposit_leaf.amount,
        };
        let pis_hash = pis.hash::<F, C, D>(&mut builder);
        builder.register_public_inputs(&pis_hash.to_vec());
        let data = builder.build();
        Self { data, target }
    }

    pub fn prove(
        &self,
        value: &SimpleWithdrawValue,
    ) -> anyhow::Result<ProofWithPublicInputs<F, C, D>> {
        let mut pw = PartialWitness::<F>::new();
        self.target.set_witness(&mut pw, value);
        self.data.prove(pw)
    }

    pub fn add_proof_target_and_verify(
        &self,
        builder: &mut CircuitBuilder<F, D>,
    ) -> ProofWithPublicInputsTarget<D> {
        let proof = builder.add_virtual_proof_with_pis(&self.data.common);
        let vd_target = builder.constant_verifier_data(&self.data.verifier_only);
        builder.verify_proof::<C>(&proof, &vd_target, &self.data.common);
        proof
    }
}

#[cfg(test)]
mod tests {
    use plonky2::{
        field::goldilocks_field::GoldilocksField, plonk::config::PoseidonGoldilocksConfig,
    };
    use rand::Rng;

    use crate::common::trees::deposit_tree::DepositTree;

    use super::*;
    type F = GoldilocksField;
    const D: usize = 2;
    type C = PoseidonGoldilocksConfig;

    #[test]
    fn simple_withdraw() {
        let mut rng = rand::thread_rng();
        let mut deposit_tree = DepositTree::new(DEPOSIT_TREE_HEIGHT);

        // add dummy deposits
        for _ in 0..100 {
            let deposit_leaf = DepositLeaf::rand(&mut rng);
            deposit_tree.push(deposit_leaf);
        }

        let salt = Salt::rand(&mut rng);
        let pubkey = U256::rand(&mut rng);
        let pubkey_salt_hash = get_pubkey_salt_hash(pubkey, salt);
        let deposit = DepositLeaf {
            pubkey_salt_hash,
            token_index: rng.gen(),
            amount: U256::rand(&mut rng),
        };
        let deposit_index = deposit_tree.len();
        deposit_tree.push(deposit.clone());

        // add dummy deposits
        for _ in 0..100 {
            let deposit_leaf = DepositLeaf::rand(&mut rng);
            deposit_tree.push(deposit_leaf);
        }

        let deposit_merkle_proof = deposit_tree.prove(deposit_index);

        let value = SimpleWithdrawValue::new(
            deposit_tree.get_root(),
            deposit_index as u32,
            deposit,
            deposit_merkle_proof,
            pubkey,
            salt,
        );

        let circuit = SimpleWithdrawCircuit::<F, C, D>::new();
        let instant = std::time::Instant::now();
        let _proof = circuit.prove(&value).expect("prove failed");
        println!("prove time: {:?}", instant.elapsed());
        dbg!(circuit.data.common.degree_bits());
    }
}
