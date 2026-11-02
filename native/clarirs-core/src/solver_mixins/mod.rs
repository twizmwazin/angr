mod concrete_early_resolution;
mod model_cache;
mod replacement;
mod simplification;

pub use concrete_early_resolution::ConcreteEarlyResolutionMixin;
pub use model_cache::ModelCacheMixin;
pub use replacement::ReplacementSolver;
pub use simplification::SimplificationMixin;

use crate::prelude::*;

/// A solver layered over an inner solver. Implementors provide access to the
/// inner solver and override only the hooks they change; every other
/// operation forwards to the inner solver. A blanket impl makes every
/// `SolverMixin` a [`Solver`] and [`HasContext`].
///
/// The hooks mirror [`Solver`]'s methods but take `this` instead of `self`
/// (like `Arc::get_mut`), so they are not method-call candidates and never
/// make `solver.add(..)` ambiguous. Inside a hook, `this.add(..)` invokes the
/// full [`Solver`] method on the mixin itself.
pub trait SolverMixin<'c>: Clone {
    type Inner: Solver<'c>;

    fn inner(&self) -> &Self::Inner;
    fn inner_mut(&mut self) -> &mut Self::Inner;

    fn add(this: &mut Self, constraint: &AstRef<'c>) -> Result<(), ClarirsError> {
        this.inner_mut().add(constraint)
    }
    fn clear(this: &mut Self) -> Result<(), ClarirsError> {
        this.inner_mut().clear()
    }
    fn constraints(this: &Self) -> Result<Vec<AstRef<'c>>, ClarirsError> {
        this.inner().constraints()
    }
    fn simplify(this: &mut Self) -> Result<(), ClarirsError> {
        this.inner_mut().simplify()
    }
    fn satisfiable(this: &mut Self) -> Result<bool, ClarirsError> {
        this.inner_mut().satisfiable()
    }
    fn satisfiable_with_extra(this: &mut Self, extra: &[AstRef<'c>]) -> Result<bool, ClarirsError> {
        this.inner_mut().satisfiable_with_extra(extra)
    }
    fn is_true(this: &mut Self, expr: &AstRef<'c>) -> Result<bool, ClarirsError> {
        this.inner_mut().is_true(expr)
    }
    fn is_false(this: &mut Self, expr: &AstRef<'c>) -> Result<bool, ClarirsError> {
        this.inner_mut().is_false(expr)
    }
    fn has_true(this: &mut Self, expr: &AstRef<'c>) -> Result<bool, ClarirsError> {
        this.inner_mut().has_true(expr)
    }
    fn has_false(this: &mut Self, expr: &AstRef<'c>) -> Result<bool, ClarirsError> {
        this.inner_mut().has_false(expr)
    }
    fn min_unsigned(this: &mut Self, expr: &AstRef<'c>) -> Result<AstRef<'c>, ClarirsError> {
        this.inner_mut().min_unsigned(expr)
    }
    fn max_unsigned(this: &mut Self, expr: &AstRef<'c>) -> Result<AstRef<'c>, ClarirsError> {
        this.inner_mut().max_unsigned(expr)
    }
    fn min_signed(this: &mut Self, expr: &AstRef<'c>) -> Result<AstRef<'c>, ClarirsError> {
        this.inner_mut().min_signed(expr)
    }
    fn max_signed(this: &mut Self, expr: &AstRef<'c>) -> Result<AstRef<'c>, ClarirsError> {
        this.inner_mut().max_signed(expr)
    }
    fn eval_n(this: &mut Self, expr: &AstRef<'c>, n: u32) -> Result<Vec<AstRef<'c>>, ClarirsError> {
        this.inner_mut().eval_n(expr, n)
    }
    fn batch_eval(this: &mut Self, exprs: &[AstRef<'c>]) -> Result<Vec<AstRef<'c>>, ClarirsError> {
        this.inner_mut().batch_eval(exprs)
    }
}

impl<'c, M: SolverMixin<'c>> Solver<'c> for M {
    fn add(&mut self, constraint: &AstRef<'c>) -> Result<(), ClarirsError> {
        M::add(self, constraint)
    }
    fn clear(&mut self) -> Result<(), ClarirsError> {
        M::clear(self)
    }
    fn constraints(&self) -> Result<Vec<AstRef<'c>>, ClarirsError> {
        M::constraints(self)
    }
    fn simplify(&mut self) -> Result<(), ClarirsError> {
        M::simplify(self)
    }
    fn satisfiable(&mut self) -> Result<bool, ClarirsError> {
        M::satisfiable(self)
    }
    fn satisfiable_with_extra(&mut self, extra: &[AstRef<'c>]) -> Result<bool, ClarirsError> {
        M::satisfiable_with_extra(self, extra)
    }
    fn is_true(&mut self, expr: &AstRef<'c>) -> Result<bool, ClarirsError> {
        M::is_true(self, expr)
    }
    fn is_false(&mut self, expr: &AstRef<'c>) -> Result<bool, ClarirsError> {
        M::is_false(self, expr)
    }
    fn has_true(&mut self, expr: &AstRef<'c>) -> Result<bool, ClarirsError> {
        M::has_true(self, expr)
    }
    fn has_false(&mut self, expr: &AstRef<'c>) -> Result<bool, ClarirsError> {
        M::has_false(self, expr)
    }
    fn min_unsigned(&mut self, expr: &AstRef<'c>) -> Result<AstRef<'c>, ClarirsError> {
        M::min_unsigned(self, expr)
    }
    fn max_unsigned(&mut self, expr: &AstRef<'c>) -> Result<AstRef<'c>, ClarirsError> {
        M::max_unsigned(self, expr)
    }
    fn min_signed(&mut self, expr: &AstRef<'c>) -> Result<AstRef<'c>, ClarirsError> {
        M::min_signed(self, expr)
    }
    fn max_signed(&mut self, expr: &AstRef<'c>) -> Result<AstRef<'c>, ClarirsError> {
        M::max_signed(self, expr)
    }
    fn eval_n(&mut self, expr: &AstRef<'c>, n: u32) -> Result<Vec<AstRef<'c>>, ClarirsError> {
        M::eval_n(self, expr, n)
    }
    fn batch_eval(&mut self, exprs: &[AstRef<'c>]) -> Result<Vec<AstRef<'c>>, ClarirsError> {
        M::batch_eval(self, exprs)
    }
}

impl<'c, M: SolverMixin<'c>> HasContext<'c> for M {
    fn context(&self) -> &'c Context<'c> {
        self.inner().context()
    }
}
