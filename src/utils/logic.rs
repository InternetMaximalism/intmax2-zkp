use plonky2::{
    field::extension::Extendable,
    hash::hash_types::RichField,
    iop::target::{BoolTarget, Target},
    plonk::circuit_builder::CircuitBuilder,
};

pub trait BuilderLogic<F: RichField + Extendable<D>, const D: usize> {
    fn conditional_assert_true(&mut self, condition: BoolTarget, target: BoolTarget);

    fn connect_targets(&mut self, left: &[Target], right: &[Target]);

    fn is_equal_targets(&mut self, left: &[Target], right: &[Target]) -> BoolTarget;

    fn conditional_assert_eq_targets(
        &mut self,
        condition: BoolTarget,
        left: &[Target],
        right: &[Target],
    );

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

    fn connect_targets(&mut self, left: &[Target], right: &[Target]) {
        assert_eq!(left.len(), right.len());
        for (l, r) in left.iter().zip(right.iter()) {
            self.connect(*l, *r);
        }
    }

    fn is_equal_targets(&mut self, left: &[Target], right: &[Target]) -> BoolTarget {
        assert_eq!(left.len(), right.len());
        let mut output = self.constant_bool(true);
        for (l, r) in left.iter().zip(right.iter()) {
            let l_is_equal_to_r = self.is_equal(*l, *r);
            output = self.and(output, l_is_equal_to_r);
        }
        output
    }

    fn conditional_assert_eq_targets(&mut self, condition: BoolTarget, x: &[Target], y: &[Target]) {
        for (x, y) in x.iter().zip(y.iter()) {
            self.conditional_assert_eq(condition.target, *x, *y);
        }
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
