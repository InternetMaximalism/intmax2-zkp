use std::panic::{self, AssertUnwindSafe};

use crate::{
    circuits::{
        balance::balance_processor::BalanceProcessor,
        claim::{
            determine_lock_time::LockTimeConfig, single_claim_processor::SingleClaimProcessor,
        },
        validity::validity_processor::ValidityProcessor,
        withdrawal::single_withdrawal_circuit::SingleWithdrawalCircuit,
    },
    utils::serializer::U32GateSerializer,
};
use plonky2::{
    field::goldilocks_field::GoldilocksField,
    plonk::{
        circuit_data::VerifierCircuitData, config::PoseidonGoldilocksConfig,
        proof::ProofWithPublicInputs,
    },
};

const VALIDITY_VD_PATH: &str = "bin/validity_verifier_circuit_data.bin";
const VALIDITY_VD_BYTES: &[u8] = include_bytes!("../../bin/validity_verifier_circuit_data.bin");

const BALANCE_VD_PATH: &str = "bin/balance_verifier_circuit_data.bin";
const BALANCE_VD_BYTES: &[u8] = include_bytes!("../../bin/balance_verifier_circuit_data.bin");

const TRANSITION_VD_PATH: &str = "bin/transition_verifier_circuit_data.bin";
const TRANSITION_VD_BYTES: &[u8] = include_bytes!("../../bin/transition_verifier_circuit_data.bin");

const SINGLE_WITHDRAWAL_VD_PATH: &str = "bin/single_withdrawal_verifier_circuit_data.bin";
const SINGLE_WITHDRAWAL_VD_BYTES: &[u8] =
    include_bytes!("../../bin/single_withdrawal_verifier_circuit_data.bin");

const FASTER_SINGLE_CLAIM_VD_PATH: &str = "bin/faster_single_claim_verifier_circuit_data.bin";
const FASTER_SINGLE_CLAIM_VD_BYTES: &[u8] =
    include_bytes!("../../bin/faster_single_claim_verifier_circuit_data.bin");

const SINGLE_CLAIM_VD_PATH: &str = "bin/single_claim_verifier_circuit_data.bin";
const SINGLE_CLAIM_VD_BYTES: &[u8] =
    include_bytes!("../../bin/single_claim_verifier_circuit_data.bin");

const SPENT_VD_PATH: &str = "bin/spent_verifier_circuit_data.bin";
const SPENT_VD_BYTES: &[u8] = include_bytes!("../../bin/spent_verifier_circuit_data.bin");

type F = GoldilocksField;
type C = PoseidonGoldilocksConfig;
const D: usize = 2;

pub struct CircuitVerifiers {
    balance_vd: VerifierCircuitData<F, C, D>,
    validity_vd: VerifierCircuitData<F, C, D>,
    transition_vd: VerifierCircuitData<F, C, D>,
    single_withdrawal_vd: VerifierCircuitData<F, C, D>,
    single_claim_vd: VerifierCircuitData<F, C, D>,
    faster_single_claim_vd: VerifierCircuitData<F, C, D>,
    spent_vd: VerifierCircuitData<F, C, D>,
}

impl CircuitVerifiers {
    // Construct the circuit verifiers from the processors.
    pub fn construct() -> Self {
        let validity_processor = ValidityProcessor::new();
        let validity_vd = validity_processor.get_verifier_data();
        let balance_processor = BalanceProcessor::new(&validity_vd);
        let transition_vd = validity_processor
            .transition_processor
            .transition_wrapper_circuit
            .data
            .verifier_data();
        let balance_vd = balance_processor.get_verifier_data();
        let single_withdrawal_circuit = SingleWithdrawalCircuit::new(&balance_vd);
        let spent_vd = balance_processor
            .balance_transition_processor
            .sender_processor
            .spent_circuit
            .data
            .verifier_data();
        let single_claim_processor =
            SingleClaimProcessor::new(&validity_vd, &LockTimeConfig::normal());
        let faster_single_claim_processor =
            SingleClaimProcessor::new(&validity_vd, &LockTimeConfig::faster());
        Self {
            balance_vd,
            validity_vd,
            transition_vd,
            single_withdrawal_vd: single_withdrawal_circuit.data.verifier_data(),
            single_claim_vd: single_claim_processor.get_verifier_data(),
            faster_single_claim_vd: faster_single_claim_processor.get_verifier_data(),
            spent_vd,
        }
    }

    pub fn save(&self) -> anyhow::Result<()> {
        save_verifier_circuit_data(BALANCE_VD_PATH, &self.balance_vd)?;
        save_verifier_circuit_data(VALIDITY_VD_PATH, &self.validity_vd)?;
        save_verifier_circuit_data(TRANSITION_VD_PATH, &self.transition_vd)?;
        save_verifier_circuit_data(SINGLE_WITHDRAWAL_VD_PATH, &self.single_withdrawal_vd)?;
        save_verifier_circuit_data(SINGLE_CLAIM_VD_PATH, &self.single_claim_vd)?;
        save_verifier_circuit_data(FASTER_SINGLE_CLAIM_VD_PATH, &self.faster_single_claim_vd)?;
        save_verifier_circuit_data(SPENT_VD_PATH, &self.spent_vd)?;
        Ok(())
    }

    pub fn load() -> Self {
        let balance_vd = deserialize_verifier_circuit_data(BALANCE_VD_BYTES.to_vec()).unwrap();
        let validity_vd = deserialize_verifier_circuit_data(VALIDITY_VD_BYTES.to_vec()).unwrap();
        let single_withdrawal_vd =
            deserialize_verifier_circuit_data(SINGLE_WITHDRAWAL_VD_BYTES.to_vec()).unwrap();
        let single_claim_vd =
            deserialize_verifier_circuit_data(SINGLE_CLAIM_VD_BYTES.to_vec()).unwrap();
        let faster_single_claim_vd =
            deserialize_verifier_circuit_data(FASTER_SINGLE_CLAIM_VD_BYTES.to_vec()).unwrap();
        let transition_vd =
            deserialize_verifier_circuit_data(TRANSITION_VD_BYTES.to_vec()).unwrap();
        let spent_vd = deserialize_verifier_circuit_data(SPENT_VD_BYTES.to_vec()).unwrap();
        Self {
            balance_vd,
            validity_vd,
            transition_vd,
            single_withdrawal_vd,
            single_claim_vd,
            faster_single_claim_vd,
            spent_vd,
        }
    }

    pub fn get_balance_vd(&self) -> VerifierCircuitData<F, C, D> {
        self.balance_vd.clone()
    }

    pub fn get_validity_vd(&self) -> VerifierCircuitData<F, C, D> {
        self.validity_vd.clone()
    }

    pub fn get_transition_vd(&self) -> VerifierCircuitData<F, C, D> {
        self.transition_vd.clone()
    }

    pub fn get_single_withdrawal_vd(&self) -> VerifierCircuitData<F, C, D> {
        self.single_withdrawal_vd.clone()
    }

    pub fn get_claim_vd(&self, is_faster_mining: bool) -> VerifierCircuitData<F, C, D> {
        if is_faster_mining {
            self.faster_single_claim_vd.clone()
        } else {
            self.single_claim_vd.clone()
        }
    }
    pub fn get_spent_vd(&self) -> VerifierCircuitData<F, C, D> {
        self.spent_vd.clone()
    }
}

fn save_verifier_circuit_data(path: &str, vd: &VerifierCircuitData<F, C, D>) -> anyhow::Result<()> {
    let gate_serializer = U32GateSerializer;
    let circuit_bytes = vd
        .to_bytes(&gate_serializer)
        .map_err(|e| anyhow::anyhow!(e))?;
    let mut circuit_file = std::fs::File::create(path)?;
    std::io::Write::write_all(&mut circuit_file, &circuit_bytes)?;
    Ok(())
}

fn deserialize_verifier_circuit_data(
    data: Vec<u8>,
) -> anyhow::Result<VerifierCircuitData<F, C, D>> {
    let gate_serializer = U32GateSerializer;
    let vd =
        VerifierCircuitData::from_bytes(data, &gate_serializer).map_err(|e| anyhow::anyhow!(e))?;
    Ok(vd)
}

pub fn safe_proof_verify(
    vd: &VerifierCircuitData<F, C, D>,
    proof: &ProofWithPublicInputs<F, C, D>,
) -> anyhow::Result<()> {
    let result = panic::catch_unwind(AssertUnwindSafe(|| vd.verify(proof.clone())));
    match result {
        Ok(verify_result) => {
            verify_result.map_err(|e| anyhow::anyhow!("Proof verification failed: {}", e))
        }
        Err(panic_payload) => {
            let panic_message = if let Some(s) = panic_payload.downcast_ref::<&str>() {
                s.to_string()
            } else if let Some(s) = panic_payload.downcast_ref::<String>() {
                s.clone()
            } else {
                "Unknown panic occurred".to_string()
            };
            Err(anyhow::anyhow!(
                "Proof verification panicked: {}",
                panic_message
            ))
        }
    }
}

#[cfg(test)]
mod tests {
    #[test]
    #[ignore]
    fn test_save_circuit_verifiers() {
        let circuit_verifiers = super::CircuitVerifiers::construct();
        circuit_verifiers.save().unwrap();
    }

    #[test]
    fn test_load_circuit_verifiers() {
        let time = std::time::Instant::now();
        let _circuit_verifiers = super::CircuitVerifiers::load();
        println!("Time taken: {:?}", time.elapsed());
    }
}
