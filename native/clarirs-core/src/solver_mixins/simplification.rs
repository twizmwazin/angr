use crate::prelude::*;

/// A mixin that simplifies expressions before passing them to the underlying solver.
#[derive(Clone, Debug)]
pub struct SimplificationMixin<'c, S: Solver<'c>> {
    inner: S,
    _marker: std::marker::PhantomData<&'c ()>,
}

impl<'c, S: Solver<'c>> SimplificationMixin<'c, S> {
    pub fn new(inner: S) -> Self {
        Self {
            inner,
            _marker: std::marker::PhantomData,
        }
    }
}

impl<'c, S: Solver<'c>> SolverMixin<'c> for SimplificationMixin<'c, S> {
    type Inner = S;

    fn inner(&self) -> &S {
        &self.inner
    }

    fn inner_mut(&mut self) -> &mut S {
        &mut self.inner
    }

    fn add(this: &mut Self, constraint: &AstRef<'c>) -> Result<(), ClarirsError> {
        let simplified = constraint.simplify()?;
        if simplified.is_true() {
            return Ok(());
        }
        this.inner.add(&simplified)
    }

    fn satisfiable_with_extra(this: &mut Self, extra: &[AstRef<'c>]) -> Result<bool, ClarirsError> {
        let simplified = extra
            .iter()
            .map(|c| c.simplify())
            .collect::<Result<Vec<_>, _>>()?;
        this.inner.satisfiable_with_extra(&simplified)
    }

    fn is_true(this: &mut Self, expr: &AstRef<'c>) -> Result<bool, ClarirsError> {
        this.inner.is_true(&expr.simplify()?)
    }

    fn is_false(this: &mut Self, expr: &AstRef<'c>) -> Result<bool, ClarirsError> {
        this.inner.is_false(&expr.simplify()?)
    }

    fn has_true(this: &mut Self, expr: &AstRef<'c>) -> Result<bool, ClarirsError> {
        this.inner.has_true(&expr.simplify()?)
    }

    fn has_false(this: &mut Self, expr: &AstRef<'c>) -> Result<bool, ClarirsError> {
        this.inner.has_false(&expr.simplify()?)
    }

    fn min_unsigned(this: &mut Self, expr: &AstRef<'c>) -> Result<AstRef<'c>, ClarirsError> {
        this.inner.min_unsigned(&expr.simplify()?)
    }

    fn max_unsigned(this: &mut Self, expr: &AstRef<'c>) -> Result<AstRef<'c>, ClarirsError> {
        this.inner.max_unsigned(&expr.simplify()?)
    }

    fn min_signed(this: &mut Self, expr: &AstRef<'c>) -> Result<AstRef<'c>, ClarirsError> {
        this.inner.min_signed(&expr.simplify()?)
    }

    fn max_signed(this: &mut Self, expr: &AstRef<'c>) -> Result<AstRef<'c>, ClarirsError> {
        this.inner.max_signed(&expr.simplify()?)
    }

    fn eval_n(this: &mut Self, expr: &AstRef<'c>, n: u32) -> Result<Vec<AstRef<'c>>, ClarirsError> {
        this.inner.eval_n(&expr.simplify()?, n)
    }

    fn batch_eval(this: &mut Self, exprs: &[AstRef<'c>]) -> Result<Vec<AstRef<'c>>, ClarirsError> {
        let simplified = exprs
            .iter()
            .map(|expr| expr.simplify())
            .collect::<Result<Vec<_>, _>>()?;
        this.inner.batch_eval(&simplified)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_simplification_mixin_simplifies_before_passing() {
        let ctx = Context::new();
        let base_solver = ConcreteSolver::new(&ctx);
        let mut solver = SimplificationMixin::new(base_solver);

        // Create an expression that needs simplification: 5 & 5 (should simplify to 5)
        let five = ctx.bvv(BitVec::from((5, 64))).unwrap();
        let and_expr = ctx.and2(&five, &five).unwrap();

        // The mixin should simplify this to just 5 before evaluation
        let results = solver.eval_n(&and_expr, 1).unwrap();
        assert_eq!(results.len(), 1);

        // Verify it was simplified to a concrete BVV
        assert!(matches!(results[0].op(), AstOp::BVV(_)));
    }

    #[test]
    fn test_simplification_mixin_is_true_with_tautology() {
        let ctx = Context::new();
        let base_solver = ConcreteSolver::new(&ctx);
        let mut solver = SimplificationMixin::new(base_solver);

        // Create a tautology: true OR false (should simplify to true)
        let true_val = ctx.true_().unwrap();
        let false_val = ctx.false_().unwrap();
        let tautology = ctx.or2(&true_val, &false_val).unwrap();

        // Should simplify to true before checking
        assert!(solver.is_true(&tautology).unwrap());
    }

    #[test]
    fn test_simplification_mixin_add_simplifies_constraint() {
        let ctx = Context::new();
        let base_solver = ConcreteSolver::new(&ctx);
        let mut solver = SimplificationMixin::new(base_solver);

        // Create a constraint that needs simplification: NOT(false) (should simplify to true)
        let false_val = ctx.false_().unwrap();
        let constraint = ctx.not(&false_val).unwrap();

        // Should simplify before adding
        assert!(solver.add(&constraint).is_ok());
    }
}
