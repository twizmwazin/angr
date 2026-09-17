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

    pub fn inner(&self) -> &S {
        &self.inner
    }

    pub fn inner_mut(&mut self) -> &mut S {
        &mut self.inner
    }
}

impl<'c, S: Solver<'c>> HasContext<'c> for SimplificationMixin<'c, S> {
    fn context(&self) -> &'c Context<'c> {
        self.inner.context()
    }
}

impl<'c, S: Solver<'c>> crate::solver::SolverMixin<'c> for SimplificationMixin<'c, S> {
    type Inner = S;

    fn wrapped(&self) -> &S {
        &self.inner
    }

    fn wrapped_mut(&mut self) -> &mut S {
        &mut self.inner
    }

    fn rewrite(&mut self, expr: &AstRef<'c>) -> Result<AstRef<'c>, ClarirsError> {
        expr.simplify()
    }

    fn add(&mut self, constraint: &AstRef<'c>) -> Result<(), ClarirsError> {
        let simplified = constraint.simplify()?;
        if simplified.is_true() {
            return Ok(());
        }
        self.inner.add(&simplified)
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
