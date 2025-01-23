pub mod determine_lock_time;
pub mod single_claim_processor;
pub mod single_claim_proof;
pub mod deposit_time;
pub mod utils;

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use crate::{
        circuits::{
            balance::balance_processor::BalanceProcessor,
            test_utils::state_manager::ValidityStateManager,
            validity::validity_processor::ValidityProcessor,
        },
        utils::hash_chain::hash_chain_processor::HashChainProcessor,
        wrapper_config::plonky2_config::PoseidonBN128GoldilocksConfig,
    };
    use plonky2::{
        field::goldilocks_field::GoldilocksField, plonk::config::PoseidonGoldilocksConfig,
    };

    use super::single_claim_proof::SingleClaimCircuit;

    type F = GoldilocksField;
    type C = PoseidonGoldilocksConfig;
    type OuterC = PoseidonBN128GoldilocksConfig;
    const D: usize = 2;

    #[test]
    fn test_claim() {
        let mut rng = rand::thread_rng();
        let validity_processor = Arc::new(ValidityProcessor::<F, C, D>::new());
        let balance_processor = BalanceProcessor::new(&validity_processor.get_verifier_data());
        let mut validity_state_manager = ValidityStateManager::new(validity_processor.clone());
        // let single_claim_circuit =
        // SingleClaimCircuit::new(validity_processor.get_verifier_data());
        // let withdrawal_processor =
        //     HashChainProcessor::new(&single_withdrawal_circuit.data.verifier_data());
    }
}
