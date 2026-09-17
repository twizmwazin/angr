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
    /// If the constraints are unsatisfiable, an error is returned.
    fn eval(&mut self, expr: &AstRef<'c>) -> Result<AstRef<'c>, ClarirsError> {
        let mut results = self.eval_n(expr, 1)?;
        results.pop().ok_or(ClarirsError::Unsat)
    }

    /// Evaluate several expressions against a single, shared model, returning
    /// one value per input expression in order.
    ///
    /// Unlike calling [`Solver::eval`] in a loop, every value is drawn from the
    /// same satisfying assignment, so the results are mutually consistent. This
    /// is what makes the values usable as a *model*. Returns
    /// [`ClarirsError::Unsat`] if the constraints are unsatisfiable.
    ///
    /// The default implementation evaluates each expression independently,
    /// which is only consistent for solvers that admit a single model (e.g.
    /// [`ConcreteSolver`]). Only a backend that admits multiple models and can
    /// produce one (e.g. Z3) needs to override this; mixins inherit the default
    /// and need not forward it, since model extraction asks the backend
    /// directly. Callers that rely on consistency (e.g. the model cache)
    /// nonetheless verify a returned assignment before trusting it.
    fn batch_eval(&mut self, exprs: &[AstRef<'c>]) -> Result<Vec<AstRef<'c>>, ClarirsError> {
        exprs.iter().map(|expr| self.eval(expr)).collect()
    }

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

    /// Find up to `n` solutions for an expression. The results have the same
    /// sort as the input expression.
    fn eval_n(&mut self, expr: &AstRef<'c>, n: u32) -> Result<Vec<AstRef<'c>>, ClarirsError>;
}

/// A solver that wraps another one. Every [`Solver`] method defaults to
/// forwarding to the wrapped solver, so a mixin implements only what it
/// changes; expressions and constraints pass through [`SolverMixin::rewrite`]
/// on the way in. Implement it by path rather than importing it: with both
/// traits in scope, method calls on a mixin are ambiguous.
pub trait SolverMixin<'c>: Clone + HasContext<'c> {
    type Inner: Solver<'c>;

    fn wrapped(&self) -> &Self::Inner;

    fn wrapped_mut(&mut self) -> &mut Self::Inner;

    /// Rewrite an expression or constraint before it reaches the wrapped solver.
    fn rewrite(&mut self, expr: &AstRef<'c>) -> Result<AstRef<'c>, ClarirsError> {
        Ok(expr.clone())
    }

    fn add(&mut self, constraint: &AstRef<'c>) -> Result<(), ClarirsError> {
        let constraint = self.rewrite(constraint)?;
        self.wrapped_mut().add(&constraint)
    }

    fn clear(&mut self) -> Result<(), ClarirsError> {
        self.wrapped_mut().clear()
    }

    fn constraints(&self) -> Result<Vec<AstRef<'c>>, ClarirsError> {
        self.wrapped().constraints()
    }

    fn simplify(&mut self) -> Result<(), ClarirsError> {
        self.wrapped_mut().simplify()
    }

    fn satisfiable(&mut self) -> Result<bool, ClarirsError> {
        self.wrapped_mut().satisfiable()
    }

    fn satisfiable_with_extra(&mut self, extra: &[AstRef<'c>]) -> Result<bool, ClarirsError> {
        let extra = extra
            .iter()
            .map(|c| self.rewrite(c))
            .collect::<Result<Vec<_>, _>>()?;
        self.wrapped_mut().satisfiable_with_extra(&extra)
    }

    fn batch_eval(&mut self, exprs: &[AstRef<'c>]) -> Result<Vec<AstRef<'c>>, ClarirsError> {
        let exprs = exprs
            .iter()
            .map(|e| self.rewrite(e))
            .collect::<Result<Vec<_>, _>>()?;
        self.wrapped_mut().batch_eval(&exprs)
    }

    fn is_true(&mut self, expr: &AstRef<'c>) -> Result<bool, ClarirsError> {
        let expr = self.rewrite(expr)?;
        self.wrapped_mut().is_true(&expr)
    }

    fn is_false(&mut self, expr: &AstRef<'c>) -> Result<bool, ClarirsError> {
        let expr = self.rewrite(expr)?;
        self.wrapped_mut().is_false(&expr)
    }

    fn has_true(&mut self, expr: &AstRef<'c>) -> Result<bool, ClarirsError> {
        let expr = self.rewrite(expr)?;
        self.wrapped_mut().has_true(&expr)
    }

    fn has_false(&mut self, expr: &AstRef<'c>) -> Result<bool, ClarirsError> {
        let expr = self.rewrite(expr)?;
        self.wrapped_mut().has_false(&expr)
    }

    fn min_unsigned(&mut self, expr: &AstRef<'c>) -> Result<AstRef<'c>, ClarirsError> {
        let expr = self.rewrite(expr)?;
        self.wrapped_mut().min_unsigned(&expr)
    }

    fn max_unsigned(&mut self, expr: &AstRef<'c>) -> Result<AstRef<'c>, ClarirsError> {
        let expr = self.rewrite(expr)?;
        self.wrapped_mut().max_unsigned(&expr)
    }

    fn min_signed(&mut self, expr: &AstRef<'c>) -> Result<AstRef<'c>, ClarirsError> {
        let expr = self.rewrite(expr)?;
        self.wrapped_mut().min_signed(&expr)
    }

    fn max_signed(&mut self, expr: &AstRef<'c>) -> Result<AstRef<'c>, ClarirsError> {
        let expr = self.rewrite(expr)?;
        self.wrapped_mut().max_signed(&expr)
    }

    fn eval_n(&mut self, expr: &AstRef<'c>, n: u32) -> Result<Vec<AstRef<'c>>, ClarirsError> {
        let expr = self.rewrite(expr)?;
        self.wrapped_mut().eval_n(&expr, n)
    }
}

impl<'c, M: SolverMixin<'c>> Solver<'c> for M {
    fn add(&mut self, constraint: &AstRef<'c>) -> Result<(), ClarirsError> {
        SolverMixin::add(self, constraint)
    }

    fn clear(&mut self) -> Result<(), ClarirsError> {
        SolverMixin::clear(self)
    }

    fn constraints(&self) -> Result<Vec<AstRef<'c>>, ClarirsError> {
        SolverMixin::constraints(self)
    }

    fn simplify(&mut self) -> Result<(), ClarirsError> {
        SolverMixin::simplify(self)
    }

    fn satisfiable(&mut self) -> Result<bool, ClarirsError> {
        SolverMixin::satisfiable(self)
    }

    fn satisfiable_with_extra(&mut self, extra: &[AstRef<'c>]) -> Result<bool, ClarirsError> {
        SolverMixin::satisfiable_with_extra(self, extra)
    }

    fn batch_eval(&mut self, exprs: &[AstRef<'c>]) -> Result<Vec<AstRef<'c>>, ClarirsError> {
        SolverMixin::batch_eval(self, exprs)
    }

    fn is_true(&mut self, expr: &AstRef<'c>) -> Result<bool, ClarirsError> {
        SolverMixin::is_true(self, expr)
    }

    fn is_false(&mut self, expr: &AstRef<'c>) -> Result<bool, ClarirsError> {
        SolverMixin::is_false(self, expr)
    }

    fn has_true(&mut self, expr: &AstRef<'c>) -> Result<bool, ClarirsError> {
        SolverMixin::has_true(self, expr)
    }

    fn has_false(&mut self, expr: &AstRef<'c>) -> Result<bool, ClarirsError> {
        SolverMixin::has_false(self, expr)
    }

    fn min_unsigned(&mut self, expr: &AstRef<'c>) -> Result<AstRef<'c>, ClarirsError> {
        SolverMixin::min_unsigned(self, expr)
    }

    fn max_unsigned(&mut self, expr: &AstRef<'c>) -> Result<AstRef<'c>, ClarirsError> {
        SolverMixin::max_unsigned(self, expr)
    }

    fn min_signed(&mut self, expr: &AstRef<'c>) -> Result<AstRef<'c>, ClarirsError> {
        SolverMixin::min_signed(self, expr)
    }

    fn max_signed(&mut self, expr: &AstRef<'c>) -> Result<AstRef<'c>, ClarirsError> {
        SolverMixin::max_signed(self, expr)
    }

    fn eval_n(&mut self, expr: &AstRef<'c>, n: u32) -> Result<Vec<AstRef<'c>>, ClarirsError> {
        SolverMixin::eval_n(self, expr, n)
    }
}
