pub mod determine_lock_time;
pub mod single_claim_proof;
pub mod start_time;
pub mod utils;

#[cfg(test)]
mod tests {
    use crate::wrapper_config::plonky2_config::PoseidonBN128GoldilocksConfig;
    use plonky2::{
        field::goldilocks_field::GoldilocksField, plonk::config::PoseidonGoldilocksConfig,
    };

    type F = GoldilocksField;
    type C = PoseidonGoldilocksConfig;
    type OuterC = PoseidonBN128GoldilocksConfig;
    const D: usize = 2;

    #[test]
    fn test_claim() {
        
    }
}
