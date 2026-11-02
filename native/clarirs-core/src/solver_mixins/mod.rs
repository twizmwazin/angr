mod concrete_early_resolution;
mod model_cache;
mod replacement;
mod simplification;

pub use concrete_early_resolution::ConcreteEarlyResolutionMixin;
pub use model_cache::ModelCacheMixin;
pub use replacement::ReplacementSolver;
pub use simplification::SimplificationMixin;

use crate::prelude::*;

/// Defines [`SolverMixin`] and its blanket [`Solver`] impl from one list of
/// signatures, so the overridable hooks and the forwarding stay in sync. Each
/// entry names the receiver type and the accessor used to reach the inner
/// solver.
macro_rules! solver_mixin {
    ($($name:ident($recv:ty, $get:ident $(, $arg:ident: $ty:ty)*) -> $ret:ty;)*) => {
        /// A solver layered over an inner solver. Implementors provide access
        /// to the inner solver and override only the hooks they change; every
        /// other operation forwards to the inner solver. A blanket impl makes
        /// every `SolverMixin` a [`Solver`] and [`HasContext`].
        ///
        /// The hooks mirror [`Solver`]'s methods but take `this` instead of
        /// `self` (like `Arc::get_mut`), so they are not method-call
        /// candidates and never make `solver.add(..)` ambiguous. Inside a
        /// hook, `this.add(..)` invokes the full [`Solver`] method on the
        /// mixin itself.
        pub trait SolverMixin<'c>: Clone {
            type Inner: Solver<'c>;

            fn inner(&self) -> &Self::Inner;
            fn inner_mut(&mut self) -> &mut Self::Inner;

            $(fn $name(this: $recv $(, $arg: $ty)*) -> Result<$ret, ClarirsError> {
                this.$get().$name($($arg),*)
            })*
        }

        impl<'c, M: SolverMixin<'c>> Solver<'c> for M {
            $(fn $name(self: $recv $(, $arg: $ty)*) -> Result<$ret, ClarirsError> {
                <M as SolverMixin<'c>>::$name(self $(, $arg)*)
            })*
        }
    };
}

solver_mixin! {
    add(&mut Self, inner_mut, constraint: &AstRef<'c>) -> ();
    clear(&mut Self, inner_mut) -> ();
    constraints(&Self, inner) -> Vec<AstRef<'c>>;
    simplify(&mut Self, inner_mut) -> ();
    satisfiable(&mut Self, inner_mut) -> bool;
    satisfiable_with_extra(&mut Self, inner_mut, extra: &[AstRef<'c>]) -> bool;
    is_true(&mut Self, inner_mut, expr: &AstRef<'c>) -> bool;
    is_false(&mut Self, inner_mut, expr: &AstRef<'c>) -> bool;
    has_true(&mut Self, inner_mut, expr: &AstRef<'c>) -> bool;
    has_false(&mut Self, inner_mut, expr: &AstRef<'c>) -> bool;
    min_unsigned(&mut Self, inner_mut, expr: &AstRef<'c>) -> AstRef<'c>;
    max_unsigned(&mut Self, inner_mut, expr: &AstRef<'c>) -> AstRef<'c>;
    min_signed(&mut Self, inner_mut, expr: &AstRef<'c>) -> AstRef<'c>;
    max_signed(&mut Self, inner_mut, expr: &AstRef<'c>) -> AstRef<'c>;
    eval_n(&mut Self, inner_mut, expr: &AstRef<'c>, n: u32) -> Vec<AstRef<'c>>;
    batch_eval(&mut Self, inner_mut, exprs: &[AstRef<'c>]) -> Vec<AstRef<'c>>;
}

impl<'c, M: SolverMixin<'c>> HasContext<'c> for M {
    fn context(&self) -> &'c Context<'c> {
        self.inner().context()
    }
}
