use std::collections::HashSet;

use crate::algorithms::replace::Replacements;
use crate::prelude::*;

/// A solver mixin that applies expression replacements before delegating to
/// the inner solver. This mirrors claripy's `ReplacementFrontend`.
///
/// When constraints of the form `x == <concrete>` are added, the replacement
/// solver automatically extracts the mapping and uses it to simplify future
/// queries. Explicit replacements can also be added via
/// [`add_replacement`](Self::add_replacement).
///
/// The replacement dictionary maps ASTs to their replacement `AstRef`
/// values. When a query is made, all known replacements are applied to the
/// expression in a single pass before forwarding to the inner solver.
///
/// A constraint is added in three steps, in this order:
///
/// 1. The replacements known so far are applied to it.
/// 2. The result goes to the inner solver. The constraint that defines a
///    replacement (`x == 5`) therefore reaches the inner solver with `x`
///    still in it, so the inner solver pins `x` as well. That keeps it sound
///    against constraints on `x` that it was given before the replacement
///    existed, and when the replacements are later removed.
/// 3. A replacement is extracted from the *replaced* constraint, and never
///    over an existing entry. A later `x == 6` has become `5 == 6` by then:
///    it makes the inner solver unsatisfiable and leaves `x -> 5` alone.
#[derive(Clone, Debug)]
pub struct ReplacementSolver<'c, S: Solver<'c>> {
    inner: S,
    /// The constraints as added, before replacement. claripy's
    /// ReplacementFrontend reports the original constraints; only the inner
    /// solver sees the replaced forms. Callers rely on this: e.g. rebuilding a
    /// solver from `constraints()` must not pick up values substituted by the
    /// replacements.
    original_constraints: Vec<AstRef<'c>>,
    /// The replacements.
    replacements: Replacements<'c>,
    /// Hashes of the `replacements` keys that were extracted from constraints
    /// rather than given to [`add_replacement`](Self::add_replacement). They
    /// are consequences of the constraints, so `clear` drops them with the
    /// constraints.
    auto_extracted: HashSet<u64>,
    /// Whether to automatically extract replacements from `x == <concrete>` constraints.
    auto_replace: bool,
}

impl<'c, S: Solver<'c>> ReplacementSolver<'c, S> {
    pub fn new(inner: S) -> Self {
        Self::new_with_options(inner, true)
    }

    pub fn new_with_options(inner: S, auto_replace: bool) -> Self {
        Self {
            inner,
            original_constraints: Vec::new(),
            replacements: Replacements::new(),
            auto_extracted: HashSet::new(),
            auto_replace,
        }
    }

    pub fn inner(&self) -> &S {
        &self.inner
    }

    /// Whether replacements are automatically extracted from `x == <concrete>`
    /// style constraints as they are added.
    pub fn auto_replace(&self) -> bool {
        self.auto_replace
    }

    pub fn inner_mut(&mut self) -> &mut S {
        &mut self.inner
    }

    /// Add an explicit replacement mapping: occurrences of `old` will be
    /// replaced with `new` in all future queries. This overwrites any
    /// replacement already known for `old`.
    ///
    /// Explicit replacements are not tied to the constraints: they survive
    /// [`clear`](Solver::clear) and go away only through
    /// [`remove_replacements`](Self::remove_replacements) or
    /// [`clear_replacements`](Self::clear_replacements).
    pub fn add_replacement(&mut self, old: AstRef<'c>, new: AstRef<'c>) {
        self.auto_extracted.remove(&old.hash());
        self.replacements.insert(old, new);
    }

    /// Remove specific replacements by their hashes.
    pub fn remove_replacements(&mut self, hashes: &[u64]) {
        self.replacements
            .retain(|old, _| !hashes.contains(&old.hash()));
        for hash in hashes {
            self.auto_extracted.remove(hash);
        }
    }

    /// Clear all replacements.
    pub fn clear_replacements(&mut self) {
        self.replacements.clear();
        self.auto_extracted.clear();
    }

    /// Get the current replacements.
    pub fn replacements(&self) -> &Replacements<'c> {
        &self.replacements
    }

    /// Apply known replacements to an AstRef.
    fn apply_replacements(&self, ast: &AstRef<'c>) -> Result<AstRef<'c>, ClarirsError> {
        ast.replace_many(&self.replacements)
    }

    /// Record `old -> new` as extracted from a constraint, unless `old`
    /// already has a replacement: the first value stays, and the constraint
    /// that disagrees with it is left for the inner solver to refute.
    fn add_extracted_replacement(&mut self, old: AstRef<'c>, new: AstRef<'c>) {
        if self.replacements.get(&old).is_none() {
            self.auto_extracted.insert(old.hash());
            self.replacements.insert(old, new);
        }
    }

    /// Try to extract a replacement from an equality constraint like
    /// `sym == concrete`, or from `Not(sym)`. `constraint` must already have
    /// had the known replacements applied.
    fn try_extract_replacement(&mut self, constraint: &AstRef<'c>) {
        match constraint.op() {
            AstOp::Eq(lhs, rhs) => {
                if lhs.symbolic() && !rhs.symbolic() {
                    self.add_extracted_replacement(lhs.clone(), rhs.clone());
                } else if !lhs.symbolic() && rhs.symbolic() {
                    self.add_extracted_replacement(rhs.clone(), lhs.clone());
                }
            }
            AstOp::Not(inner) => {
                // Not(x) means x is false
                if inner.symbolic()
                    && let Ok(false_val) = constraint.context().false_()
                {
                    self.add_extracted_replacement(inner.clone(), false_val);
                }
            }
            _ => {}
        }
    }
}

impl<'c, S: Solver<'c>> HasContext<'c> for ReplacementSolver<'c, S> {
    fn context(&self) -> &'c Context<'c> {
        self.inner.context()
    }
}

impl<'c, S: Solver<'c>> Solver<'c> for ReplacementSolver<'c, S> {
    fn add(&mut self, constraint: &AstRef<'c>) -> Result<(), ClarirsError> {
        // Apply the replacements known so far before looking for a new one.
        // Extracting from the raw constraint would let `x == 6` overwrite an
        // earlier `x -> 5` and then rewrite itself into `6 == 6`.
        let replaced = self.apply_replacements(constraint)?;
        self.inner.add(&replaced)?;
        self.original_constraints.push(constraint.clone());

        if self.auto_replace {
            self.try_extract_replacement(&replaced);
        }
        Ok(())
    }

    fn clear(&mut self) -> Result<(), ClarirsError> {
        self.original_constraints.clear();
        // Replacements extracted from the constraints go with them; explicit
        // ones stay (see `add_replacement`).
        let auto_extracted = std::mem::take(&mut self.auto_extracted);
        self.replacements
            .retain(|old, _| !auto_extracted.contains(&old.hash()));
        self.inner.clear()
    }

    fn constraints(&self) -> Result<Vec<AstRef<'c>>, ClarirsError> {
        Ok(self.original_constraints.clone())
    }

    fn simplify(&mut self) -> Result<(), ClarirsError> {
        self.inner.simplify()
    }

    fn satisfiable(&mut self) -> Result<bool, ClarirsError> {
        self.inner.satisfiable()
    }

    fn satisfiable_with_extra(&mut self, extra: &[AstRef<'c>]) -> Result<bool, ClarirsError> {
        let replaced = extra
            .iter()
            .map(|c| self.apply_replacements(c))
            .collect::<Result<Vec<_>, _>>()?;
        self.inner.satisfiable_with_extra(&replaced)
    }

    fn batch_eval_n(
        &mut self,
        exprs: &[AstRef<'c>],
        n: u32,
    ) -> Result<Vec<Vec<AstRef<'c>>>, ClarirsError> {
        let replaced = exprs
            .iter()
            .map(|expr| self.apply_replacements(expr))
            .collect::<Result<Vec<_>, _>>()?;
        self.inner.batch_eval_n(&replaced, n)
    }

    fn is_true(&mut self, expr: &AstRef<'c>) -> Result<bool, ClarirsError> {
        let replaced = self.apply_replacements(expr)?;
        self.inner.is_true(&replaced)
    }

    fn is_false(&mut self, expr: &AstRef<'c>) -> Result<bool, ClarirsError> {
        let replaced = self.apply_replacements(expr)?;
        self.inner.is_false(&replaced)
    }

    fn has_true(&mut self, expr: &AstRef<'c>) -> Result<bool, ClarirsError> {
        let replaced = self.apply_replacements(expr)?;
        self.inner.has_true(&replaced)
    }

    fn has_false(&mut self, expr: &AstRef<'c>) -> Result<bool, ClarirsError> {
        let replaced = self.apply_replacements(expr)?;
        self.inner.has_false(&replaced)
    }

    fn min_unsigned(&mut self, expr: &AstRef<'c>) -> Result<AstRef<'c>, ClarirsError> {
        let replaced = self.apply_replacements(expr)?;
        self.inner.min_unsigned(&replaced)
    }

    fn max_unsigned(&mut self, expr: &AstRef<'c>) -> Result<AstRef<'c>, ClarirsError> {
        let replaced = self.apply_replacements(expr)?;
        self.inner.max_unsigned(&replaced)
    }

    fn min_signed(&mut self, expr: &AstRef<'c>) -> Result<AstRef<'c>, ClarirsError> {
        let replaced = self.apply_replacements(expr)?;
        self.inner.min_signed(&replaced)
    }

    fn max_signed(&mut self, expr: &AstRef<'c>) -> Result<AstRef<'c>, ClarirsError> {
        let replaced = self.apply_replacements(expr)?;
        self.inner.max_signed(&replaced)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ast::AstFactory;

    #[test]
    fn test_replacement_solver_basic() -> Result<(), ClarirsError> {
        let ctx = Context::new();
        let inner = ConcreteSolver::new(&ctx);
        let mut solver = ReplacementSolver::new(inner);

        let x = ctx.bvs("x", 8)?;
        let five = ctx.bvv(BitVec::from((5, 8)))?;

        // Add explicit replacement: x -> 5
        solver.add_replacement(x.clone(), five.clone());

        // Evaluating x should now return 5
        let result = solver.eval(&x)?;
        assert_eq!(result, five);

        Ok(())
    }

    #[test]
    fn test_replacement_solver_auto_extract() -> Result<(), ClarirsError> {
        let ctx = Context::new();
        let inner = ConcreteSolver::new(&ctx);
        let mut solver = ReplacementSolver::new(inner);

        let x = ctx.bvs("x", 8)?;
        let five = ctx.bvv(BitVec::from((5, 8)))?;

        // Add constraint: x == 5 (should auto-extract replacement)
        let eq_constraint = ctx.eq_(&x, &five)?;
        solver.add(&eq_constraint)?;

        // Evaluating x should now return 5
        let result = solver.eval(&x)?;
        assert_eq!(result, five);

        Ok(())
    }

    #[test]
    fn test_replacement_solver_expression() -> Result<(), ClarirsError> {
        let ctx = Context::new();
        let inner = ConcreteSolver::new(&ctx);
        let mut solver = ReplacementSolver::new(inner);

        let x = ctx.bvs("x", 8)?;
        let five = ctx.bvv(BitVec::from((5, 8)))?;
        let three = ctx.bvv(BitVec::from((3, 8)))?;

        // Replace x with 5
        solver.add_replacement(x.clone(), five.clone());

        // Evaluating x + 3 should return 8
        let expr = ctx.add(&x, &three)?;
        let result = solver.eval(&expr)?;
        let expected = ctx.bvv(BitVec::from((8, 8)))?;
        assert_eq!(result, expected);

        Ok(())
    }

    #[test]
    fn test_replacement_solver_clear() -> Result<(), ClarirsError> {
        let ctx = Context::new();
        let inner = ConcreteSolver::new(&ctx);
        let mut solver = ReplacementSolver::new(inner);

        let x = ctx.bvs("x", 8)?;
        let five = ctx.bvv(BitVec::from((5, 8)))?;

        solver.add_replacement(x.clone(), five.clone());
        assert!(!solver.replacements().is_empty());

        solver.clear_replacements();
        assert!(solver.replacements().is_empty());

        Ok(())
    }

    #[test]
    fn test_replacement_solver_bool() -> Result<(), ClarirsError> {
        let ctx = Context::new();
        let inner = ConcreteSolver::new(&ctx);
        let mut solver = ReplacementSolver::new(inner);

        let x = ctx.bools("x")?;

        // Replace x with true
        solver.add_replacement(x.clone(), ctx.true_()?);

        assert!(solver.is_true(&x)?);
        assert!(!solver.is_false(&x)?);

        Ok(())
    }

    #[test]
    fn test_replacement_solver_auto_replace_disabled() -> Result<(), ClarirsError> {
        let ctx = Context::new();
        let inner = ConcreteSolver::new(&ctx);
        // auto_replace = false: `x == 5` should NOT register a replacement.
        let mut solver = ReplacementSolver::new_with_options(inner, false);
        assert!(!solver.auto_replace());

        let x = ctx.bvs("x", 8)?;
        let five = ctx.bvv(BitVec::from((5, 8)))?;

        let eq_constraint = ctx.eq_(&x, &five)?;
        solver.add(&eq_constraint)?;

        // No replacement was extracted, so the map stays empty.
        assert!(solver.replacements().is_empty());

        // Explicit replacements still work regardless of auto_replace.
        solver.add_replacement(x.clone(), five.clone());
        assert_eq!(solver.eval(&x)?, five);

        Ok(())
    }

    #[test]
    fn test_replacement_solver_reports_original_constraints() -> Result<(), ClarirsError> {
        let ctx = Context::new();
        let inner = ConcreteSolver::new(&ctx);
        let mut solver = ReplacementSolver::new(inner);

        let x = ctx.bvs("x", 8)?;
        let one = ctx.bvv(BitVec::from((1, 8)))?;
        let five = ctx.bvv(BitVec::from((5, 8)))?;
        let six = ctx.bvv(BitVec::from((6, 8)))?;

        // x == 5 auto-extracts the replacement x -> 5.
        let eq = ctx.eq_(&x, &five)?;
        solver.add(&eq)?;
        // x + 1 == 6 folds to `true` once x is replaced by 5, but constraints()
        // must report the original form, not the replaced one.
        let derived = ctx.eq_(&ctx.add(&x, &one)?, &six)?;
        solver.add(&derived)?;

        let constraints = solver.constraints()?;
        assert!(constraints.contains(&eq));
        assert!(constraints.contains(&derived));

        solver.clear()?;
        assert!(solver.constraints()?.is_empty());

        Ok(())
    }

    #[test]
    fn test_replacement_solver_keeps_first_extracted_value() -> Result<(), ClarirsError> {
        let ctx = Context::new();
        let inner = ConcreteSolver::new(&ctx);
        let mut solver = ReplacementSolver::new(inner);

        let x = ctx.bvs("x", 8)?;
        let five = ctx.bvv(BitVec::from((5, 8)))?;
        let six = ctx.bvv(BitVec::from((6, 8)))?;

        solver.add(&ctx.eq_(&x, &five)?)?;
        // A contradicting equality must not overwrite x -> 5 (it reaches the
        // inner solver as `5 == 6` instead).
        solver.add(&ctx.eq_(&x, &six)?)?;
        solver.add(&ctx.eq_(&six, &x)?)?;

        assert_eq!(solver.replacements().len(), 1);
        assert_eq!(solver.replacements().get(&x), Some(&five));
        assert_eq!(solver.eval(&x)?, five);

        Ok(())
    }

    #[test]
    fn test_replacement_solver_not_keeps_existing_replacement() -> Result<(), ClarirsError> {
        let ctx = Context::new();
        let inner = ConcreteSolver::new(&ctx);
        let mut solver = ReplacementSolver::new(inner);

        let b = ctx.bools("b")?;

        // b == true extracts b -> true; a later Not(b) must not flip it.
        solver.add(&ctx.eq_(&b, &ctx.true_()?)?)?;
        solver.add(&ctx.not(&b)?)?;
        assert_eq!(solver.replacements().get(&b), Some(&ctx.true_()?));

        // An explicit replacement is not overwritten by extraction either,
        // but add_replacement itself still overwrites.
        let c = ctx.bools("c")?;
        solver.add_replacement(c.clone(), ctx.true_()?);
        solver.add(&ctx.not(&c)?)?;
        assert_eq!(solver.replacements().get(&c), Some(&ctx.true_()?));
        solver.add_replacement(c.clone(), ctx.false_()?);
        assert_eq!(solver.replacements().get(&c), Some(&ctx.false_()?));

        Ok(())
    }

    #[test]
    fn test_replacement_solver_clear_drops_extracted_replacements() -> Result<(), ClarirsError> {
        let ctx = Context::new();
        let inner = ConcreteSolver::new(&ctx);
        let mut solver = ReplacementSolver::new(inner);

        let x = ctx.bvs("x", 8)?;
        let y = ctx.bvs("y", 8)?;
        let z = ctx.bvs("z", 8)?;
        let five = ctx.bvv(BitVec::from((5, 8)))?;
        let six = ctx.bvv(BitVec::from((6, 8)))?;

        // x -> 5 is extracted, y -> 6 is explicit, and z -> 5 is extracted
        // and then explicitly overwritten, which makes it explicit.
        solver.add(&ctx.eq_(&x, &five)?)?;
        solver.add_replacement(y.clone(), six.clone());
        solver.add(&ctx.eq_(&z, &five)?)?;
        solver.add_replacement(z.clone(), six.clone());
        assert_eq!(solver.replacements().len(), 3);

        // clear() removes the constraints and what was derived from them.
        solver.clear()?;
        assert_eq!(solver.replacements().len(), 2);
        assert_eq!(solver.replacements().get(&x), None);
        assert_eq!(solver.replacements().get(&y), Some(&six));
        assert_eq!(solver.replacements().get(&z), Some(&six));
        assert!(solver.eval(&x).is_err());

        // The cleared solver extracts afresh.
        solver.add(&ctx.eq_(&x, &six)?)?;
        assert_eq!(solver.eval(&x)?, six);

        solver.clear_replacements();
        assert!(solver.replacements().is_empty());

        Ok(())
    }
}
