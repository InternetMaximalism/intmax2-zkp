use std::marker::PhantomData;

use plonky2::{
    field::extension::Extendable,
    hash::hash_types::RichField,
    iop::witness::{PartialWitness, WitnessWrite as _},
    plonk::{
        circuit_builder::CircuitBuilder,
        circuit_data::{CircuitConfig, CircuitData},
        config::{AlgebraicHasher, GenericConfig},
        proof::{ProofWithPublicInputs, ProofWithPublicInputsTarget},
    },
};

use super::simple_withraw_circuit::SimpleWithdrawCircuit;

pub struct WrapperCircuit<F, C, OuterC, const D: usize>
where
    F: RichField + Extendable<D>,
    C: GenericConfig<D, F = F>,
    OuterC: GenericConfig<D, F = F>,
{
    pub data: CircuitData<F, OuterC, D>,
    pub wrap_proof: ProofWithPublicInputsTarget<D>,
    _maker: PhantomData<C>,
}

impl<F, C, OuterC, const D: usize> WrapperCircuit<F, C, OuterC, D>
where
    F: RichField + Extendable<D>,
    OuterC: GenericConfig<D, F = F>,
    C: GenericConfig<D, F = F> + 'static,
    C::Hasher: AlgebraicHasher<F>,
{
    pub fn new(config: CircuitConfig, inner_circuit: &SimpleWithdrawCircuit<F, C, D>) -> Self {
        let mut builder = CircuitBuilder::new(config);
        let wrap_proof = inner_circuit.add_proof_target_and_verify(&mut builder);
        builder.register_public_inputs(&wrap_proof.public_inputs);
        let data = builder.build();
        Self {
            data,
            wrap_proof,
            _maker: PhantomData,
        }
    }

    pub fn prove(
        &self,
        inner_proof: &ProofWithPublicInputs<F, C, D>,
    ) -> anyhow::Result<ProofWithPublicInputs<F, OuterC, D>> {
        let mut pw = PartialWitness::new();
        pw.set_proof_with_pis_target(&self.wrap_proof, inner_proof);
        self.data.prove(pw)
    }
}

#[cfg(test)]
mod tests {
    use plonky2::{
        field::goldilocks_field::GoldilocksField,
        plonk::{circuit_data::CircuitConfig, config::PoseidonGoldilocksConfig},
    };
    use rand::Rng;

    use crate::{
        circuits::mining::{
            simple_withraw_circuit::{
                get_pubkey_salt_hash, SimpleWithdrawCircuit, SimpleWithdrawValue,
            },
            wrapper::WrapperCircuit,
        },
        common::{
            salt::Salt,
            trees::deposit_tree::{DepositLeaf, DepositTree},
        },
        constants::DEPOSIT_TREE_HEIGHT,
        ethereum_types::u256::U256,
        utils::save::{save_circuit_data, save_proof},
        wrapper_config::plonky2_config::PoseidonBN128GoldilocksConfig,
    };

    type F = GoldilocksField;
    const D: usize = 2;
    type C = PoseidonGoldilocksConfig;

    #[test]
    fn wrap_withdraw() {
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
        let inner_proof = circuit.prove(&value).expect("prove failed");

        let config = CircuitConfig::standard_recursion_config();
        type OuterC = PoseidonBN128GoldilocksConfig;

        let wrapper_circuit = WrapperCircuit::<F, C, OuterC, D>::new(config, &circuit);
        let proof = wrapper_circuit.prove(&inner_proof).expect("prove failed");
        println!("prove time: {:?}", instant.elapsed());
        dbg!(wrapper_circuit.data.common.degree_bits());

        save_circuit_data("./withdraw_circuit_data/", &wrapper_circuit.data).expect("save failed");
        save_proof("./withdraw_circuit_data/", &proof).expect("save failed");
    }
}
