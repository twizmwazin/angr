use clarirs_core::prelude::*;
use clarirs_core::solver_mixins::{
    ConcreteEarlyResolutionMixin, ModelCacheMixin, SimplificationMixin,
};
use clarirs_vsa::VSASolver;
use clarirs_z3::Z3Solver;

// Type aliases for the wrapped solvers with mixins.
//
// `WrappedZ3Solver` is the caching Z3 stack used by the default `Solver` (and,
// like claripy, by the composite/replacement/hybrid frontends): the
// `ModelCacheMixin` sits just above the Z3 backend and caches satisfiability
// and models. `WrappedZ3CachelessSolver` omits that mixin, mirroring claripy's
// `SolverCacheless`.
type WrappedConcreteSolver = ConcreteSolver;
type WrappedZ3Solver = SimplificationMixin<ConcreteEarlyResolutionMixin<ModelCacheMixin<Z3Solver>>>;
type WrappedZ3CachelessSolver = SimplificationMixin<ConcreteEarlyResolutionMixin<Z3Solver>>;
type WrappedVSASolver = SimplificationMixin<ConcreteEarlyResolutionMixin<VSASolver>>;
type WrappedHybridSolver = SimplificationMixin<
    ConcreteEarlyResolutionMixin<HybridSolver<WrappedVSASolver, WrappedZ3Solver>>,
>;
type WrappedReplacementSolver = ReplacementSolver<WrappedZ3Solver>;
type WrappedCompositeSolver = CompositeSolver<WrappedZ3Solver>;

#[derive(Clone, Debug)]
pub(crate) enum DynSolver {
    Concrete(WrappedConcreteSolver),
    Z3(WrappedZ3Solver),
    Z3Cacheless(WrappedZ3CachelessSolver),
    Vsa(WrappedVSASolver),
    Hybrid(WrappedHybridSolver),
    Replacement(WrappedReplacementSolver),
    Composite(WrappedCompositeSolver),
}

impl HasContext for DynSolver {
    fn context(&self) -> Arc<Context> {
        match self {
            DynSolver::Concrete(solver) => solver.context(),
            DynSolver::Z3(solver) => solver.context(),
            DynSolver::Z3Cacheless(solver) => solver.context(),
            DynSolver::Vsa(solver) => solver.context(),
            DynSolver::Hybrid(solver) => solver.context(),
            DynSolver::Replacement(solver) => solver.context(),
            DynSolver::Composite(solver) => solver.context(),
        }
    }
}

impl DynSolver {
    /// Get unsat core (only supported for Z3 solver)
    pub(crate) fn unsat_core(&mut self) -> Result<Vec<usize>, ClarirsError> {
        match self {
            DynSolver::Z3(wrapped_solver) => {
                // Access through the mixin layers
                // SimplificationMixin -> ConcreteEarlyResolutionMixin -> ModelCacheMixin -> Z3Solver
                let z3_solver = wrapped_solver.inner_mut().inner_mut().inner_mut();
                z3_solver.unsat_core()
            }
            DynSolver::Z3Cacheless(wrapped_solver) => {
                // SimplificationMixin -> ConcreteEarlyResolutionMixin -> Z3Solver
                let z3_solver = wrapped_solver.inner_mut().inner_mut();
                z3_solver.unsat_core()
            }
            DynSolver::Hybrid(wrapped_solver) => {
                // Access through mixin layers to the HybridSolver, then to its exact (Z3) solver
                let hybrid = wrapped_solver.inner_mut().inner_mut();
                let z3_solver = hybrid.exact_mut().inner_mut().inner_mut().inner_mut();
                z3_solver.unsat_core()
            }
            DynSolver::Composite(composite) => {
                // The composite's core is the core of whichever independent
                // child is unsat (claripy's CompositeFrontend does the same).
                for child in composite.children_mut() {
                    if !child.satisfiable()? {
                        // SimplificationMixin -> ConcreteEarlyResolutionMixin -> ModelCacheMixin -> Z3Solver
                        let z3_solver = child.inner_mut().inner_mut().inner_mut();
                        return z3_solver.unsat_core();
                    }
                }
                Ok(vec![])
            }
            _ => Err(ClarirsError::UnsupportedOperation(
                "unsat_core is only supported for Z3 and Hybrid solvers".to_string(),
            )),
        }
    }

    /// Add a replacement (only supported for Replacement solver)
    pub(crate) fn add_replacement(&mut self, old: AstRef, new: AstRef) -> Result<(), ClarirsError> {
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
            DynSolver::Z3(solver) => solver.$method($($arg),*),
            DynSolver::Z3Cacheless(solver) => solver.$method($($arg),*),
            DynSolver::Vsa(solver) => solver.$method($($arg),*),
            DynSolver::Hybrid(solver) => solver.$method($($arg),*),
            DynSolver::Replacement(solver) => solver.$method($($arg),*),
            DynSolver::Composite(solver) => solver.$method($($arg),*),
        }
    };
}

impl Solver for DynSolver {
    fn add(&mut self, constraint: &AstRef) -> Result<(), ClarirsError> {
        dispatch!(self, add, constraint)
    }

    fn clear(&mut self) -> Result<(), ClarirsError> {
        dispatch!(self, clear)
    }

    fn constraints(&self) -> Result<Vec<AstRef>, ClarirsError> {
        dispatch!(self, constraints)
    }

    fn simplify(&mut self) -> Result<(), ClarirsError> {
        dispatch!(self, simplify)
    }

    fn satisfiable(&mut self) -> Result<bool, ClarirsError> {
        dispatch!(self, satisfiable)
    }

    fn satisfiable_with_extra(&mut self, extra: &[AstRef]) -> Result<bool, ClarirsError> {
        dispatch!(self, satisfiable_with_extra, extra)
    }

    fn is_true(&mut self, expr: &AstRef) -> Result<bool, ClarirsError> {
        dispatch!(self, is_true, expr)
    }

    fn is_false(&mut self, expr: &AstRef) -> Result<bool, ClarirsError> {
        dispatch!(self, is_false, expr)
    }

    fn has_true(&mut self, expr: &AstRef) -> Result<bool, ClarirsError> {
        dispatch!(self, has_true, expr)
    }

    fn has_false(&mut self, expr: &AstRef) -> Result<bool, ClarirsError> {
        dispatch!(self, has_false, expr)
    }

    fn min_unsigned(&mut self, expr: &AstRef) -> Result<AstRef, ClarirsError> {
        dispatch!(self, min_unsigned, expr)
    }

    fn max_unsigned(&mut self, expr: &AstRef) -> Result<AstRef, ClarirsError> {
        dispatch!(self, max_unsigned, expr)
    }

    fn min_signed(&mut self, expr: &AstRef) -> Result<AstRef, ClarirsError> {
        dispatch!(self, min_signed, expr)
    }

    fn max_signed(&mut self, expr: &AstRef) -> Result<AstRef, ClarirsError> {
        dispatch!(self, max_signed, expr)
    }

    fn eval_n(&mut self, expr: &AstRef, n: u32) -> Result<Vec<AstRef>, ClarirsError> {
        dispatch!(self, eval_n, expr, n)
    }

    fn batch_eval(&mut self, exprs: &[AstRef]) -> Result<Vec<AstRef>, ClarirsError> {
        dispatch!(self, batch_eval, exprs)
    }
}
