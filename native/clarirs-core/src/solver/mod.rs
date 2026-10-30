mod composite;
mod concrete;
mod hybrid;

pub use composite::CompositeSolver;
pub use concrete::ConcreteSolver;
pub use hybrid::HybridSolver;

use std::collections::BTreeSet;

use crate::prelude::*;

pub trait Solver<'c>: Clone + HasContext<'c> {
    // Constraint management
    fn add(&mut self, constraint: &AstRef<'c>) -> Result<(), ClarirsError>;

    fn clear(&mut self) -> Result<(), ClarirsError>;

    fn constraints(&self) -> Result<Vec<AstRef<'c>>, ClarirsError>;

    /// Simplify the constraints held internally by the solver
    fn simplify(&mut self) -> Result<(), ClarirsError>;

    /// Get all variables involved in the current set of constraints
    fn variables(&self) -> Result<BTreeSet<InternedString>, ClarirsError> {
        Ok(self
            .constraints()?
            .iter()
            .flat_map(|c| c.variables())
            .cloned()
            .collect())
    }

    /// Check if the current set of constraints is satisfiable
    fn satisfiable(&mut self) -> Result<bool, ClarirsError>;

    /// Check satisfiability with `extra` constraints temporarily added.
    /// The default clones the solver and adds the constraints; backends
    /// override this with cheaper scoped checks (e.g. Z3 assumptions on the
    /// persistent incremental solver). This is the hot path of symbolic
    /// execution: every branch feasibility check goes through it.
    fn satisfiable_with_extra(&mut self, extra: &[AstRef<'c>]) -> Result<bool, ClarirsError> {
        if extra.is_empty() {
            return self.satisfiable();
        }
        let mut solver = self.clone();
        for constraint in extra {
            solver.add(constraint)?;
        }
        solver.satisfiable()
    }

    /// Evaluate an expression in the current model. The result has the same
    /// sort as the input expression.
    ///
    /// If the constraints are unsatisfiable, [`ClarirsError::Unsat`] is
    /// returned. The default draws a single solution from [`Solver::eval_n`].
    fn eval(&mut self, expr: &AstRef<'c>) -> Result<AstRef<'c>, ClarirsError> {
        let mut results = self.eval_n(expr, 1)?;
        results.pop().ok_or(ClarirsError::Unsat)
    }

    /// Find up to `n` distinct solutions for an expression. The results have
    /// the same sort as the input expression.
    ///
    /// Returns no solutions if the constraints are unsatisfiable. The default
    /// asks [`Solver::batch_eval_n`] for `n` rows over the single expression
    /// and unwraps each row.
    fn eval_n(&mut self, expr: &AstRef<'c>, n: u32) -> Result<Vec<AstRef<'c>>, ClarirsError> {
        self.batch_eval_n(std::slice::from_ref(expr), n)?
            .into_iter()
            .map(|mut row| {
                row.pop().ok_or_else(|| {
                    ClarirsError::InvalidArguments(
                        "batch_eval_n returned a row with no value".to_string(),
                    )
                })
            })
            .collect()
    }

    /// Evaluate several expressions against a single, shared model, returning
    /// one value per input expression in order.
    ///
    /// Unlike calling [`Solver::eval`] in a loop, every value is drawn from the
    /// same satisfying assignment, so the results are mutually consistent. This
    /// is what makes the values usable as a *model*. Returns
    /// [`ClarirsError::Unsat`] if the constraints are unsatisfiable. The
    /// default takes the first row of [`Solver::batch_eval_n`].
    fn batch_eval(&mut self, exprs: &[AstRef<'c>]) -> Result<Vec<AstRef<'c>>, ClarirsError> {
        let mut rows = self.batch_eval_n(exprs, 1)?;
        rows.pop().ok_or(ClarirsError::Unsat)
    }

    /// Find up to `n` distinct rows of solutions for several expressions. Each
    /// row holds one value per input expression, in order, and every value in a
    /// row is drawn from a single satisfying assignment, so a row is a usable
    /// *model* of the expressions. Rows are pairwise distinct as tuples; two
    /// rows may agree on some expressions as long as they differ on another.
    ///
    /// Returns no rows if the constraints are unsatisfiable. For an empty
    /// `exprs` there is exactly one possible row, the empty one, which is
    /// returned when the constraints are satisfiable. A batch of concrete
    /// expressions has exactly one row, and implementations may produce it
    /// without consulting the constraints, so such a query is not a
    /// satisfiability check.
    ///
    /// This is the single primitive of the evaluation interface: [`Solver::eval`],
    /// [`Solver::eval_n`] and [`Solver::batch_eval`] all default to it, so a
    /// backend only has to implement this method. Backends may still override
    /// the others when a cheaper path exists (e.g. a one-model query that can
    /// skip the exclusion constraints needed to enumerate several rows).
    fn batch_eval_n(
        &mut self,
        exprs: &[AstRef<'c>],
        n: u32,
    ) -> Result<Vec<Vec<AstRef<'c>>>, ClarirsError>;

    /// Check if an expression is true in the current model. If the constraints are unsatisfiable, an
    /// error is returned. Equivalent to `eval(expr) == ctx.true_()`
    fn is_true(&mut self, expr: &AstRef<'c>) -> Result<bool, ClarirsError>;

    /// Check if an expression is false in the current model. If the constraints are unsatisfiable, an
    /// error is returned. Equivalent to `eval(expr) == ctx.false_()`
    fn is_false(&mut self, expr: &AstRef<'c>) -> Result<bool, ClarirsError>;

    /// Check if an expression could be true in the current model. If the constraints are unsatisfiable, an
    /// error is returned. Equivalent to `eval(expr) == ctx.true_()`
    fn has_true(&mut self, expr: &AstRef<'c>) -> Result<bool, ClarirsError>;

    /// Check if an expression could be false in the current model. If the constraints are unsatisfiable, an
    /// error is returned. Equivalent to `eval(expr) == ctx.false_()`
    fn has_false(&mut self, expr: &AstRef<'c>) -> Result<bool, ClarirsError>;

    /// Get the minimum value of an expression in the current model, interpreting the bitvector as unsigned.
    /// If the constraints are unsatisfiable, an error is returned.
    fn min_unsigned(&mut self, expr: &AstRef<'c>) -> Result<AstRef<'c>, ClarirsError>;

    /// Get the maximum value of an expression in the current model, interpreting the bitvector as unsigned.
    /// If the constraints are unsatisfiable, an error is returned.
    fn max_unsigned(&mut self, expr: &AstRef<'c>) -> Result<AstRef<'c>, ClarirsError>;

    /// Get the minimum value of an expression in the current model, interpreting the bitvector as signed.
    /// If the constraints are unsatisfiable, an error is returned.
    fn min_signed(&mut self, expr: &AstRef<'c>) -> Result<AstRef<'c>, ClarirsError>;

    /// Get the maximum value of an expression in the current model, interpreting the bitvector as signed.
    /// If the constraints are unsatisfiable, an error is returned.
    fn max_signed(&mut self, expr: &AstRef<'c>) -> Result<AstRef<'c>, ClarirsError>;
}
