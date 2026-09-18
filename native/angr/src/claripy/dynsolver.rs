use clarirs_core::prelude::*;
use clarirs_core::solver_mixins::{
    ConcreteEarlyResolutionMixin, ModelCacheMixin, SimplificationMixin,
};
use clarirs_smtrs::SmtrsSolver;
use clarirs_vsa::VSASolver;

// Type aliases for the wrapped solvers with mixins.
//
// `WrappedSmtrsSolver` is the caching smtrs stack used by the default `Solver` (and,
// like claripy, by the composite/replacement/hybrid frontends): the
// `ModelCacheMixin` sits just above the smtrs backend and caches satisfiability
// and models. `WrappedSmtrsCachelessSolver` omits that mixin, mirroring claripy's
// `SolverCacheless`.
type WrappedConcreteSolver<'c> = ConcreteSolver<'c>;
type WrappedSmtrsSolver<'c> =
    SimplificationMixin<'c, ConcreteEarlyResolutionMixin<'c, ModelCacheMixin<'c, SmtrsSolver<'c>>>>;
type WrappedSmtrsCachelessSolver<'c> =
    SimplificationMixin<'c, ConcreteEarlyResolutionMixin<'c, SmtrsSolver<'c>>>;
type WrappedVSASolver<'c> =
    SimplificationMixin<'c, ConcreteEarlyResolutionMixin<'c, VSASolver<'c>>>;
type WrappedHybridSolver<'c> = SimplificationMixin<
    'c,
    ConcreteEarlyResolutionMixin<
        'c,
        HybridSolver<'c, WrappedVSASolver<'c>, WrappedSmtrsSolver<'c>>,
    >,
>;
type WrappedReplacementSolver<'c> = ReplacementSolver<'c, WrappedSmtrsSolver<'c>>;
type WrappedCompositeSolver<'c> = CompositeSolver<'c, WrappedSmtrsSolver<'c>>;

#[derive(Clone, Debug)]
pub(crate) enum DynSolver {
    Concrete(WrappedConcreteSolver<'static>),
    Smtrs(WrappedSmtrsSolver<'static>),
    SmtrsCacheless(WrappedSmtrsCachelessSolver<'static>),
    Vsa(WrappedVSASolver<'static>),
    Hybrid(WrappedHybridSolver<'static>),
    Replacement(WrappedReplacementSolver<'static>),
    Composite(WrappedCompositeSolver<'static>),
}

impl HasContext<'static> for DynSolver {
    fn context(&self) -> &'static Context<'static> {
        match self {
            DynSolver::Concrete(solver) => solver.context(),
            DynSolver::Smtrs(solver) => solver.context(),
            DynSolver::SmtrsCacheless(solver) => solver.context(),
            DynSolver::Vsa(solver) => solver.context(),
            DynSolver::Hybrid(solver) => solver.context(),
            DynSolver::Replacement(solver) => solver.context(),
            DynSolver::Composite(solver) => solver.context(),
        }
    }
}

impl DynSolver {
    /// Get unsat core (only supported for the smtrs-backed solvers)
    pub(crate) fn unsat_core(&mut self) -> Result<Vec<usize>, ClarirsError> {
        match self {
            DynSolver::Smtrs(wrapped_solver) => {
                // Access through the mixin layers
                // SimplificationMixin -> ConcreteEarlyResolutionMixin -> ModelCacheMixin -> SmtrsSolver
                let smtrs_solver = wrapped_solver.inner_mut().inner_mut().inner_mut();
                smtrs_solver.unsat_core()
            }
            DynSolver::SmtrsCacheless(wrapped_solver) => {
                // SimplificationMixin -> ConcreteEarlyResolutionMixin -> SmtrsSolver
                let smtrs_solver = wrapped_solver.inner_mut().inner_mut();
                smtrs_solver.unsat_core()
            }
            DynSolver::Hybrid(wrapped_solver) => {
                // Access through mixin layers to the HybridSolver, then to its exact (smtrs) solver
                let hybrid = wrapped_solver.inner_mut().inner_mut();
                let smtrs_solver = hybrid.exact_mut().inner_mut().inner_mut().inner_mut();
                smtrs_solver.unsat_core()
            }
            DynSolver::Composite(composite) => {
                // The composite's core is the core of whichever independent
                // child is unsat (claripy's CompositeFrontend does the same).
                for child in composite.children_mut() {
                    if !child.satisfiable()? {
                        // SimplificationMixin -> ConcreteEarlyResolutionMixin -> ModelCacheMixin -> SmtrsSolver
                        let smtrs_solver = child.inner_mut().inner_mut().inner_mut();
                        return smtrs_solver.unsat_core();
                    }
                }
                Ok(vec![])
            }
            _ => Err(ClarirsError::UnsupportedOperation(
                "unsat_core is only supported for the smtrs-backed and Hybrid solvers".to_string(),
            )),
        }
    }

    /// Add a replacement (only supported for Replacement solver)
    pub(crate) fn add_replacement(
        &mut self,
        old: AstRef<'static>,
        new: AstRef<'static>,
    ) -> Result<(), ClarirsError> {
        match self {
            DynSolver::Replacement(solver) => {
                solver.add_replacement(old, new);
                Ok(())
            }
            _ => Err(ClarirsError::UnsupportedOperation(
                "add_replacement is only supported for Replacement solver".to_string(),
            )),
        }
    }

    /// Whether automatic replacement extraction is enabled. Only meaningful for
    /// the Replacement solver; other solvers report `false`.
    pub(crate) fn auto_replace(&self) -> bool {
        match self {
            DynSolver::Replacement(solver) => solver.auto_replace(),
            _ => false,
        }
    }

    /// Whether approximate-first evaluation is enabled (only meaningful for
    /// the Hybrid solver).
    pub(crate) fn approximate_first(&self) -> bool {
        match self {
            // SimplificationMixin -> ConcreteEarlyResolutionMixin -> HybridSolver
            DynSolver::Hybrid(solver) => solver.inner().inner().approximate_first(),
            _ => false,
        }
    }

    /// Clear all replacements (only supported for Replacement solver)
    pub(crate) fn clear_replacements(&mut self) -> Result<(), ClarirsError> {
        match self {
            DynSolver::Replacement(solver) => {
                solver.clear_replacements();
                Ok(())
            }
            _ => Err(ClarirsError::UnsupportedOperation(
                "clear_replacements is only supported for Replacement solver".to_string(),
            )),
        }
    }
}

macro_rules! dispatch {
    ($self:expr, $method:ident $(, $arg:expr)*) => {
        match $self {
            DynSolver::Concrete(solver) => solver.$method($($arg),*),
            DynSolver::Smtrs(solver) => solver.$method($($arg),*),
            DynSolver::SmtrsCacheless(solver) => solver.$method($($arg),*),
            DynSolver::Vsa(solver) => solver.$method($($arg),*),
            DynSolver::Hybrid(solver) => solver.$method($($arg),*),
            DynSolver::Replacement(solver) => solver.$method($($arg),*),
            DynSolver::Composite(solver) => solver.$method($($arg),*),
        }
    };
}

impl Solver<'static> for DynSolver {
    fn add(&mut self, constraint: &AstRef<'static>) -> Result<(), ClarirsError> {
        dispatch!(self, add, constraint)
    }

    fn clear(&mut self) -> Result<(), ClarirsError> {
        dispatch!(self, clear)
    }

    fn constraints(&self) -> Result<Vec<AstRef<'static>>, ClarirsError> {
        dispatch!(self, constraints)
    }

    fn simplify(&mut self) -> Result<(), ClarirsError> {
        dispatch!(self, simplify)
    }

    fn satisfiable(&mut self) -> Result<bool, ClarirsError> {
        dispatch!(self, satisfiable)
    }

    fn satisfiable_with_extra(&mut self, extra: &[AstRef<'static>]) -> Result<bool, ClarirsError> {
        dispatch!(self, satisfiable_with_extra, extra)
    }

    fn is_true(&mut self, expr: &AstRef<'static>) -> Result<bool, ClarirsError> {
        dispatch!(self, is_true, expr)
    }

    fn is_false(&mut self, expr: &AstRef<'static>) -> Result<bool, ClarirsError> {
        dispatch!(self, is_false, expr)
    }

    fn has_true(&mut self, expr: &AstRef<'static>) -> Result<bool, ClarirsError> {
        dispatch!(self, has_true, expr)
    }

    fn has_false(&mut self, expr: &AstRef<'static>) -> Result<bool, ClarirsError> {
        dispatch!(self, has_false, expr)
    }

    fn min_unsigned(&mut self, expr: &AstRef<'static>) -> Result<AstRef<'static>, ClarirsError> {
        dispatch!(self, min_unsigned, expr)
    }

    fn max_unsigned(&mut self, expr: &AstRef<'static>) -> Result<AstRef<'static>, ClarirsError> {
        dispatch!(self, max_unsigned, expr)
    }

    fn min_signed(&mut self, expr: &AstRef<'static>) -> Result<AstRef<'static>, ClarirsError> {
        dispatch!(self, min_signed, expr)
    }

    fn max_signed(&mut self, expr: &AstRef<'static>) -> Result<AstRef<'static>, ClarirsError> {
        dispatch!(self, max_signed, expr)
    }

    fn eval_n(
        &mut self,
        expr: &AstRef<'static>,
        n: u32,
    ) -> Result<Vec<AstRef<'static>>, ClarirsError> {
        dispatch!(self, eval_n, expr, n)
    }

    fn batch_eval(
        &mut self,
        exprs: &[AstRef<'static>],
    ) -> Result<Vec<AstRef<'static>>, ClarirsError> {
        dispatch!(self, batch_eval, exprs)
    }
}
