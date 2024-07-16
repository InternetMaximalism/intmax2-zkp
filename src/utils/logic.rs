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
