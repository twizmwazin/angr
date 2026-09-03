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

/// Implement the named `Solver` methods by forwarding them unchanged to the solver in `$target`.
macro_rules! forward_solver_methods {
    ($target:ident; $($method:ident),+ $(,)?) => {
        $($crate::solver::forward_solver_methods!(@ $target; $method);)+
    };
    (@ $target:ident; add) => {
        fn add(&mut self, constraint: &AstRef<'c>) -> Result<(), ClarirsError> {
            self.$target.add(constraint)
        }
    };
    (@ $target:ident; clear) => {
        fn clear(&mut self) -> Result<(), ClarirsError> {
            self.$target.clear()
        }
    };
    (@ $target:ident; constraints) => {
        fn constraints(&self) -> Result<Vec<AstRef<'c>>, ClarirsError> {
            self.$target.constraints()
        }
    };
    (@ $target:ident; simplify) => {
        fn simplify(&mut self) -> Result<(), ClarirsError> {
            self.$target.simplify()
        }
    };
    (@ $target:ident; variables) => {
        fn variables(&self) -> Result<::std::collections::BTreeSet<InternedString>, ClarirsError> {
            self.$target.variables()
        }
    };
    (@ $target:ident; satisfiable) => {
        fn satisfiable(&mut self) -> Result<bool, ClarirsError> {
            self.$target.satisfiable()
        }
    };
    (@ $target:ident; batch_eval) => {
        fn batch_eval(&mut self, exprs: &[AstRef<'c>]) -> Result<Vec<AstRef<'c>>, ClarirsError> {
            self.$target.batch_eval(exprs)
        }
    };
    (@ $target:ident; $query:ident) => {
        $crate::solver::forward_query!(self.$target; |expr| expr; $query);
    };
}
pub(crate) use forward_solver_methods;

/// Implement `Solver` query methods (`is_true`..`max_signed`, `eval_n`) by forwarding them: to a
/// field with the given argument, to one of two fields chosen by a condition, or through a helper
/// taking `(vars, |solver| ..)`. The given expressions run in the method body and may `?`/`return`.
macro_rules! forward_query {
    ($self:ident.$target:ident; |$expr:ident| $arg:expr; $($method:ident),+ $(,)?) => {
        $($crate::solver::forward_query!(@ret $method; @to $self.$target; |$expr| $arg);)+
    };
    (|$expr:ident| if ($cond:expr) { $self:ident.$a:ident } else { $this:ident.$b:ident };
     $($method:ident),+ $(,)?) => {
        $($crate::solver::forward_query!(
            @ret $method; @split $self.$a / $self.$b; |$expr| $cond
        );)+
    };
    (|$expr:ident| $self:ident.$via:ident($vars:expr); $($method:ident),+ $(,)?) => {
        $($crate::solver::forward_query!(@ret $method; @via $self.$via($vars); |$expr|);)+
    };
    (@ret is_true; $($rest:tt)*) => {
        $crate::solver::forward_query!(@gen is_true -> bool; $($rest)*);
    };
    (@ret is_false; $($rest:tt)*) => {
        $crate::solver::forward_query!(@gen is_false -> bool; $($rest)*);
    };
    (@ret has_true; $($rest:tt)*) => {
        $crate::solver::forward_query!(@gen has_true -> bool; $($rest)*);
    };
    (@ret has_false; $($rest:tt)*) => {
        $crate::solver::forward_query!(@gen has_false -> bool; $($rest)*);
    };
    (@ret min_unsigned; $($rest:tt)*) => {
        $crate::solver::forward_query!(@gen min_unsigned -> AstRef<'c>; $($rest)*);
    };
    (@ret max_unsigned; $($rest:tt)*) => {
        $crate::solver::forward_query!(@gen max_unsigned -> AstRef<'c>; $($rest)*);
    };
    (@ret min_signed; $($rest:tt)*) => {
        $crate::solver::forward_query!(@gen min_signed -> AstRef<'c>; $($rest)*);
    };
    (@ret max_signed; $($rest:tt)*) => {
        $crate::solver::forward_query!(@gen max_signed -> AstRef<'c>; $($rest)*);
    };
    (@ret eval_n; $($rest:tt)*) => {
        $crate::solver::forward_query!(@gen eval_n -> Vec<AstRef<'c>>, n; $($rest)*);
    };
    (@gen $method:ident -> $ret:ty $(, $n:ident)?;
     @to $self:ident.$target:ident; |$expr:ident| $arg:expr) => {
        fn $method(&mut $self, $expr: &AstRef<'c> $(, $n: u32)?) -> Result<$ret, ClarirsError> {
            $self.$target.$method($arg $(, $n)?)
        }
    };
    (@gen $method:ident -> $ret:ty $(, $n:ident)?;
     @split $self:ident.$a:ident / $this:ident.$b:ident; |$expr:ident| $cond:expr) => {
        fn $method(&mut $self, $expr: &AstRef<'c> $(, $n: u32)?) -> Result<$ret, ClarirsError> {
            if $cond {
                $self.$a.$method($expr $(, $n)?)
            } else {
                $self.$b.$method($expr $(, $n)?)
            }
        }
    };
    (@gen $method:ident -> $ret:ty $(, $n:ident)?;
     @via $self:ident.$via:ident($vars:expr); |$expr:ident|) => {
        fn $method(&mut $self, $expr: &AstRef<'c> $(, $n: u32)?) -> Result<$ret, ClarirsError> {
            $self.$via($vars, |s| s.$method($expr $(, $n)?))
        }
    };
}
pub(crate) use forward_query;
