use plonky2::{
    field::extension::Extendable, hash::hash_types::RichField, iop::target::BoolTarget,
    plonk::circuit_builder::CircuitBuilder,
};

pub trait BuilderLogic<F: RichField + Extendable<D>, const D: usize> {
    fn conditional_assert_true(&mut self, condition: BoolTarget, target: BoolTarget);

    /// returns x && y if condition is true
    /// returns x if condition is false
    fn conditional_and(
        &mut self,
        condition: BoolTarget,
        x: BoolTarget,
        y: BoolTarget,
    ) -> BoolTarget;
}

impl<F: RichField + Extendable<D>, const D: usize> BuilderLogic<F, D> for CircuitBuilder<F, D> {
    fn conditional_assert_true(&mut self, condition: BoolTarget, target: BoolTarget) {
        // condition * (1 - target) = - target*condition + enabled
        let tmp = self.arithmetic(
            F::NEG_ONE,
            F::ONE,
            target.target,
            condition.target,
            condition.target,
        );
        self.assert_zero(tmp);
    }

    fn conditional_and(
        &mut self,
        condition: BoolTarget,
        x: BoolTarget,
        y: BoolTarget,
    ) -> BoolTarget {
        let x_and_y = self.and(x, y);
        let selected = self.select(condition, x_and_y.target, x.target);
        BoolTarget::new_unsafe(selected)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use plonky2::{
        iop::witness::PartialWitness,
        plonk::{circuit_data::CircuitConfig, config::PoseidonGoldilocksConfig},
    };

    type F = <PoseidonGoldilocksConfig as plonky2::plonk::config::GenericConfig<D>>::F;
    const D: usize = 2;

    /// Test for conditional_assert_true
    /// 
    /// The method implements the constraint: condition * (1 - target) = 0
    /// This means:
    /// - If condition is true (1), then target must be true (1) for the constraint to be satisfied
    /// - If condition is false (0), then the constraint is always satisfied regardless of target
    #[test]
    fn test_logic_conditional_assert_true() {
        // Case 1: condition = true, target = true (should pass)
        // When condition is true and target is true, the constraint is satisfied: 1 * (1 - 1) = 0
        let config = CircuitConfig::standard_recursion_config();
        let mut builder = CircuitBuilder::<F, D>::new(config);
        
        let condition = builder.constant_bool(true);
        let target = builder.constant_bool(true);
        
        builder.conditional_assert_true(condition, target);
        
        let circuit = builder.build::<PoseidonGoldilocksConfig>();
        let pw = PartialWitness::new();
        let proof = circuit.prove(pw).unwrap();
        circuit.verify(proof).unwrap();
        
        // Case 2: condition = false, target = false (should pass)
        // When condition is false, the constraint is always satisfied: 0 * (1 - 0) = 0
        let config = CircuitConfig::standard_recursion_config();
        let mut builder = CircuitBuilder::<F, D>::new(config);
        
        let condition = builder.constant_bool(false);
        let target = builder.constant_bool(false);
        
        builder.conditional_assert_true(condition, target);
        
        let circuit = builder.build::<PoseidonGoldilocksConfig>();
        let pw = PartialWitness::new();
        let proof = circuit.prove(pw).unwrap();
        circuit.verify(proof).unwrap();
        
        // Case 3: condition = false, target = true (should pass)
        // When condition is false, the constraint is always satisfied: 0 * (1 - 1) = 0
        let config = CircuitConfig::standard_recursion_config();
        let mut builder = CircuitBuilder::<F, D>::new(config);
        
        let condition = builder.constant_bool(false);
        let target = builder.constant_bool(true);
        
        builder.conditional_assert_true(condition, target);
        
        let circuit = builder.build::<PoseidonGoldilocksConfig>();
        let pw = PartialWitness::new();
        let proof = circuit.prove(pw).unwrap();
        circuit.verify(proof).unwrap();
    }
    
    /// Test for the case where conditional_assert_true should fail
    /// This is separated into its own test because we expect it to panic
    #[test]
    #[should_panic(expected = "Partition containing Wire")]
    fn test_logic_conditional_assert_true_failure() {
        // Case: condition = true, target = false (should fail)
        // When condition is true and target is false, the constraint is not satisfied: 1 * (1 - 0) = 1 ≠ 0
        let config = CircuitConfig::standard_recursion_config();
        let mut builder = CircuitBuilder::<F, D>::new(config);
        
        let condition = builder.constant_bool(true);
        let target = builder.constant_bool(false);
        
        builder.conditional_assert_true(condition, target);
        
        let circuit = builder.build::<PoseidonGoldilocksConfig>();
        let pw = PartialWitness::new();
        // This should panic during circuit building because the constraint is unsatisfiable
        circuit.prove(pw).unwrap();
    }

    #[test]
    fn test_logic_conditional_and() {
        // Case 1: condition = true, x = true, y = true
        {
            let config = CircuitConfig::standard_recursion_config();
            let mut builder = CircuitBuilder::<F, D>::new(config);
            
            let condition = builder.constant_bool(true);
            let x = builder.constant_bool(true);
            let y = builder.constant_bool(true);
            
            let result = builder.conditional_and(condition, x, y);
            let expected = builder.constant_bool(true);
            builder.connect(result.target, expected.target);
            
            let circuit = builder.build::<PoseidonGoldilocksConfig>();
            let pw = PartialWitness::new();
            let proof = circuit.prove(pw).unwrap();
            circuit.verify(proof).unwrap();
        }
        
        // Case 2: condition = true, x = true, y = false
        {
            let config = CircuitConfig::standard_recursion_config();
            let mut builder = CircuitBuilder::<F, D>::new(config);
            
            let condition = builder.constant_bool(true);
            let x = builder.constant_bool(true);
            let y = builder.constant_bool(false);
            
            let result = builder.conditional_and(condition, x, y);
            let expected = builder.constant_bool(false);
            builder.connect(result.target, expected.target);
            
            let circuit = builder.build::<PoseidonGoldilocksConfig>();
            let pw = PartialWitness::new();
            let proof = circuit.prove(pw).unwrap();
            circuit.verify(proof).unwrap();
        }
        
        // Case 3: condition = true, x = false, y = true
        {
            let config = CircuitConfig::standard_recursion_config();
            let mut builder = CircuitBuilder::<F, D>::new(config);
            
            let condition = builder.constant_bool(true);
            let x = builder.constant_bool(false);
            let y = builder.constant_bool(true);
            
            let result = builder.conditional_and(condition, x, y);
            let expected = builder.constant_bool(false);
            builder.connect(result.target, expected.target);
            
            let circuit = builder.build::<PoseidonGoldilocksConfig>();
            let pw = PartialWitness::new();
            let proof = circuit.prove(pw).unwrap();
            circuit.verify(proof).unwrap();
        }
        
        // Case 4: condition = false, x = true, y = true
        {
            let config = CircuitConfig::standard_recursion_config();
            let mut builder = CircuitBuilder::<F, D>::new(config);
            
            let condition = builder.constant_bool(false);
            let x = builder.constant_bool(true);
            let y = builder.constant_bool(true);
            
            let result = builder.conditional_and(condition, x, y);
            let expected = builder.constant_bool(true); // Should return x when condition is false
            builder.connect(result.target, expected.target);
            
            let circuit = builder.build::<PoseidonGoldilocksConfig>();
            let pw = PartialWitness::new();
            let proof = circuit.prove(pw).unwrap();
            circuit.verify(proof).unwrap();
        }
        
        // Case 5: condition = false, x = false, y = true
        {
            let config = CircuitConfig::standard_recursion_config();
            let mut builder = CircuitBuilder::<F, D>::new(config);
            
            let condition = builder.constant_bool(false);
            let x = builder.constant_bool(false);
            let y = builder.constant_bool(true);
            
            let result = builder.conditional_and(condition, x, y);
            let expected = builder.constant_bool(false); // Should return x when condition is false
            builder.connect(result.target, expected.target);
            
            let circuit = builder.build::<PoseidonGoldilocksConfig>();
            let pw = PartialWitness::new();
            let proof = circuit.prove(pw).unwrap();
            circuit.verify(proof).unwrap();
        }
    }
}
