use std::sync::atomic::{AtomicU64, Ordering};

use clarirs_core::prelude::*;
use smtrs_core::{BvConst, Op};

use crate::backend::{Config, Request, release, with_backend};
use crate::convert::{bitvec_of, is_literal, value_to_ast};

static NEXT_SOLVER_ID: AtomicU64 = AtomicU64::new(1);

fn next_solver_id() -> u64 {
    NEXT_SOLVER_ID.fetch_add(1, Ordering::Relaxed)
}

/// A [`Solver`] backed by a persistent smtrs engine.
///
/// The value holds the constraints as ASTs and an id; the engine lives in
/// thread-local storage (see [`crate::backend`]). Cloning is cheap and the
/// clone's first query reuses the original's engine under a push level, so
/// clone-add-query-drop — how angr asks scoped questions — costs no solver
/// build.
#[derive(Debug)]
pub struct SmtrsSolver<'c> {
    ctx: &'c Context<'c>,
    assertions: Vec<AstRef<'c>>,
    timeout: Option<u32>,
    unsat_core: bool,
    id: u64,
    /// Nearest ancestor that had a live engine when this solver was cloned.
    parent: Option<u64>,
    /// Queries answered so far; the first may borrow the ancestor's engine.
    queries: u64,
}

impl<'c> Clone for SmtrsSolver<'c> {
    fn clone(&self) -> Self {
        crate::stats::CLONES.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        let parent = with_backend(|b| {
            let parent = if b.has_engine(self.id) {
                Some(self.id)
            } else {
                self.parent
            };
            if let Some(pid) = parent {
                b.attach(pid);
            }
            parent
        });
        SmtrsSolver {
            ctx: self.ctx,
            assertions: self.assertions.clone(),
            timeout: self.timeout,
            unsat_core: self.unsat_core,
            id: next_solver_id(),
            parent,
            queries: 0,
        }
    }
}

impl Drop for SmtrsSolver<'_> {
    fn drop(&mut self) {
        release(self.id, self.parent);
    }
}

impl<'c> SmtrsSolver<'c> {
    pub fn new(ctx: &'c Context<'c>) -> Self {
        Self::new_with_options(ctx, None, false)
    }

    /// `timeout` is per query, in milliseconds, like z3's parameter; a query
    /// that runs past it fails with [`ClarirsError::SolverUnknown`].
    pub fn new_with_timeout(ctx: &'c Context<'c>, timeout: Option<u32>) -> Self {
        Self::new_with_options(ctx, timeout, false)
    }

    pub fn new_with_options(ctx: &'c Context<'c>, timeout: Option<u32>, unsat_core: bool) -> Self {
        Self {
            ctx,
            assertions: Vec::new(),
            timeout,
            unsat_core,
            id: next_solver_id(),
            parent: None,
            queries: 0,
        }
    }

    fn config(&self) -> Config {
        Config {
            timeout: self.timeout,
            unsat_core: self.unsat_core,
        }
    }

    /// Run a query against this solver's engine.
    fn query<R>(
        &mut self,
        f: impl FnOnce(
            &mut crate::convert::Converter<'_>,
            &mut crate::backend::Engine,
        ) -> Result<R, ClarirsError>,
    ) -> Result<R, ClarirsError> {
        self.queries += 1;
        let req = Request {
            id: self.id,
            parent: self.parent,
            constraints: &self.assertions,
            config: self.config(),
            first: self.queries == 1,
        };
        let _t = crate::stats::RUN.enter();
        let (result, own_engine) = with_backend(|b| {
            let result = b.run(&req, f);
            (result, b.has_engine(req.id))
        });
        // With an engine of its own, this solver is done with its ancestor's.
        if own_engine && let Some(parent) = self.parent.take() {
            with_backend(|b| b.detach(Some(parent)));
        }
        result
    }

    fn invalidate(&self) {
        with_backend(|b| b.drop_engine(self.id));
    }

    /// Indices into [`Solver::constraints`] of a subset that is
    /// unsatisfiable on its own. The subset is sound, not minimal.
    ///
    /// Only available on a solver created with `unsat_core = true`, and only
    /// while the constraints are unsatisfiable.
    pub fn unsat_core(&mut self) -> Result<Vec<usize>, ClarirsError> {
        if !self.unsat_core {
            return Err(ClarirsError::UnsupportedOperation(
                "Unsat core tracking is not enabled. Use new_with_options with unsat_core=true"
                    .to_string(),
            ));
        }
        self.query(|conv, engine| {
            if engine.check(conv.pool, &[])? {
                return Err(ClarirsError::UnsupportedOperation(
                    "Can only get unsat core after an UNSAT result".to_string(),
                ));
            }
            let core = engine.solver.unsat_core().map_err(|why| {
                ClarirsError::UnsupportedOperation(format!("no unsat core: {why}"))
            })?;
            let mut indices: Vec<usize> = core
                .iter()
                .filter_map(|sym| engine.tracked.iter().position(|t| t == sym))
                .collect();
            indices.sort_unstable();
            Ok(indices)
        })
    }

    /// `expr` simplified, or its literal value when it has one — the cases
    /// no solver is needed for.
    fn resolve(expr: &AstRef<'c>) -> Result<Result<AstRef<'c>, AstRef<'c>>, ClarirsError> {
        let expr = expr.simplify()?;
        if expr.concrete() && is_literal(&expr) {
            Ok(Ok(expr))
        } else {
            Ok(Err(expr))
        }
    }

    fn extremum(
        &mut self,
        expr: &AstRef<'c>,
        maximize: bool,
        signed: bool,
    ) -> Result<AstRef<'c>, ClarirsError> {
        let expr = match Self::resolve(expr)? {
            Ok(literal) => return Ok(literal),
            Err(expr) => expr,
        };
        if !expr.ast_type().is_bitvec() {
            return Err(ClarirsError::TypeError(
                "min/max require a bit-vector expression".to_string(),
            ));
        }
        let ctx = self.ctx;
        self.query(|conv, engine| {
            let (term, _) = conv.query_term(&expr, true)?;
            // Flipping the sign bit maps signed order onto unsigned order, so
            // one native extremum answers both.
            let width = conv.pool.width(term);
            let sign = BvConst::from_bits(width, |i| i == width - 1);
            let target = if signed {
                let sign_term = conv.pool.bv(sign.clone());
                conv.pool
                    .mk(Op::BvXor, &[term, sign_term])
                    .map_err(|e| ClarirsError::TypeError(e.to_string()))?
            } else {
                term
            };
            if !engine.check(conv.pool, &[])? {
                return Err(ClarirsError::Unsat);
            }
            let found = engine.extremum(conv.pool, target, maximize);
            let value = found.ok_or_else(|| {
                ClarirsError::SolverUnknown("smtrs could not optimize this expression".to_string())
            })?;
            let value = if signed { value.xor(&sign) } else { value };
            ctx.bvv(bitvec_of(&value))
        })
    }
}

impl<'c> HasContext<'c> for SmtrsSolver<'c> {
    fn context(&self) -> &'c Context<'c> {
        self.ctx
    }
}

impl<'c> Solver<'c> for SmtrsSolver<'c> {
    fn add(&mut self, constraint: &AstRef<'c>) -> Result<(), ClarirsError> {
        self.assertions.push(constraint.clone());
        Ok(())
    }

    fn clear(&mut self) -> Result<(), ClarirsError> {
        self.assertions.clear();
        self.invalidate();
        Ok(())
    }

    fn constraints(&self) -> Result<Vec<AstRef<'c>>, ClarirsError> {
        Ok(self.assertions.clone())
    }

    fn simplify(&mut self) -> Result<(), ClarirsError> {
        let simplified = self
            .assertions
            .iter()
            .map(|c| c.simplify())
            .filter(|c| !matches!(c, Ok(c) if c.is_true()))
            .collect::<Result<Vec<_>, ClarirsError>>()?;
        if simplified.len() != self.assertions.len()
            || simplified
                .iter()
                .zip(&self.assertions)
                .any(|(a, b)| a.hash() != b.hash())
        {
            self.assertions = simplified;
            // The engine's asserted prefix no longer matches; `run` will
            // notice, but drop it now rather than keep it warm for nothing.
            crate::stats::INVALIDATED_BY_SIMPLIFY
                .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            self.invalidate();
        } else {
            crate::stats::SIMPLIFY_NOOP.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        }
        Ok(())
    }

    fn satisfiable(&mut self) -> Result<bool, ClarirsError> {
        self.query(|conv, engine| engine.check(conv.pool, &[]))
    }

    fn satisfiable_with_extra(&mut self, extra: &[AstRef<'c>]) -> Result<bool, ClarirsError> {
        if extra.is_empty() {
            return self.satisfiable();
        }
        // The extras become assumptions on the persistent engine: one
        // incremental SAT call, no clone and no re-encoding. This is angr's
        // hottest solver call (every branch feasibility check).
        self.query(|conv, engine| {
            let mut assumptions = Vec::with_capacity(extra.len());
            for c in extra {
                assumptions.push(conv.term(c)?);
            }
            engine.check(conv.pool, &assumptions)
        })
    }

    fn eval(&mut self, expr: &AstRef<'c>) -> Result<AstRef<'c>, ClarirsError> {
        let mut values = self.batch_eval(std::slice::from_ref(expr))?;
        values.pop().ok_or(ClarirsError::Unsat)
    }

    fn batch_eval(&mut self, exprs: &[AstRef<'c>]) -> Result<Vec<AstRef<'c>>, ClarirsError> {
        // Every value is read from one model, so the results are consistent.
        let mut resolved = Vec::with_capacity(exprs.len());
        let mut pending = Vec::new();
        for (i, expr) in exprs.iter().enumerate() {
            match Self::resolve(expr)? {
                Ok(literal) => resolved.push(Some(literal)),
                Err(expr) => {
                    resolved.push(None);
                    pending.push((i, expr));
                }
            }
        }
        if pending.is_empty() {
            return Ok(resolved
                .into_iter()
                .map(|v| v.expect("all literal"))
                .collect());
        }
        let values = self.query(|conv, engine| {
            let exprs: Vec<AstRef<'c>> = pending.iter().map(|(_, e)| e.clone()).collect();
            let mut terms = Vec::with_capacity(pending.len());
            let mut kinds = Vec::with_capacity(pending.len());
            for expr in &exprs {
                let (t, k) = conv.query_term(expr, false)?;
                terms.push(t);
                kinds.push(k);
            }
            engine.ensure_model(conv.pool)?;
            engine.eval_kinds(conv, &exprs, &terms, &kinds)
        })?;
        for ((i, _), value) in pending.into_iter().zip(values) {
            resolved[i] = Some(value);
        }
        Ok(resolved.into_iter().map(|v| v.expect("filled")).collect())
    }

    fn is_true(&mut self, expr: &AstRef<'c>) -> Result<bool, ClarirsError> {
        let expr = expr.simplify()?;
        Ok(expr.concrete() && expr.is_true())
    }

    fn is_false(&mut self, expr: &AstRef<'c>) -> Result<bool, ClarirsError> {
        let expr = expr.simplify()?;
        Ok(expr.concrete() && expr.is_false())
    }

    fn has_true(&mut self, expr: &AstRef<'c>) -> Result<bool, ClarirsError> {
        self.satisfiable_with_extra(std::slice::from_ref(expr))
    }

    fn has_false(&mut self, expr: &AstRef<'c>) -> Result<bool, ClarirsError> {
        let negated = self.ctx.not(expr)?;
        self.satisfiable_with_extra(&[negated])
    }

    fn min_unsigned(&mut self, expr: &AstRef<'c>) -> Result<AstRef<'c>, ClarirsError> {
        self.extremum(expr, false, false)
    }

    fn max_unsigned(&mut self, expr: &AstRef<'c>) -> Result<AstRef<'c>, ClarirsError> {
        self.extremum(expr, true, false)
    }

    fn min_signed(&mut self, expr: &AstRef<'c>) -> Result<AstRef<'c>, ClarirsError> {
        self.extremum(expr, false, true)
    }

    fn max_signed(&mut self, expr: &AstRef<'c>) -> Result<AstRef<'c>, ClarirsError> {
        self.extremum(expr, true, true)
    }

    fn eval_n(&mut self, expr: &AstRef<'c>, n: u32) -> Result<Vec<AstRef<'c>>, ClarirsError> {
        if n == 0 {
            return Ok(Vec::new());
        }
        let expr = match Self::resolve(expr)? {
            Ok(literal) => return Ok(vec![literal]),
            Err(expr) => expr,
        };
        if n == 1 {
            // One value needs no enumeration: read it off the model.
            return Ok(vec![self.eval(&expr)?]);
        }
        let ctx = self.ctx;
        self.query(|conv, engine| {
            let (term, kind) = conv.query_term(&expr, true)?;
            if crate::backend::Engine::needs_substitution(conv.pool, term, kind) {
                // No bit-level enumeration through the string lowering:
                // exclude each value found with an assumption and ask again.
                let plain = conv.term(&expr)?;
                let mut assumptions = Vec::new();
                let mut values = Vec::new();
                while values.len() < n as usize {
                    if !engine.check(conv.pool, &assumptions)? {
                        break;
                    }
                    let value = engine.eval_by_substitution(conv, &expr)?;
                    let literal = conv.term(&value)?;
                    assumptions.push(
                        conv.pool
                            .mk(Op::Distinct, &[plain, literal])
                            .map_err(|e| ClarirsError::TypeError(e.to_string()))?,
                    );
                    values.push(value);
                }
                if values.is_empty() {
                    return Err(ClarirsError::Unsat);
                }
                return Ok(values);
            }
            if !engine.check(conv.pool, &[])? {
                return Err(ClarirsError::Unsat);
            }
            let values = engine.enumerate(conv.pool, term, n as usize);
            if values.is_empty() {
                return Err(ClarirsError::SolverUnknown(
                    "smtrs could not enumerate values for this expression".to_string(),
                ));
            }
            values
                .iter()
                .map(|v| value_to_ast(ctx, &smtrs_core::Value::Bv(v.clone()), kind))
                .collect()
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use clarirs_core::solver_mixins::ModelCacheMixin;

    fn bv<'c>(ctx: &'c Context<'c>, v: u64, w: u32) -> AstRef<'c> {
        ctx.bvv(BitVec::from((v, w))).unwrap()
    }

    #[test]
    fn test_solver_simple() -> Result<(), ClarirsError> {
        let ctx = Context::new();
        let mut solver = SmtrsSolver::new(&ctx);
        let x = ctx.bools("x")?;
        let y = ctx.bools("y")?;
        solver.add(&ctx.neq(&x, &y)?)?;
        let x_val = solver.eval(&x)?;
        let y_val = solver.eval(&y)?;
        assert_ne!(x_val, y_val);
        Ok(())
    }

    #[test]
    fn test_batch_eval_consistent_model() -> Result<(), ClarirsError> {
        let ctx = Context::new();
        let mut solver = SmtrsSolver::new(&ctx);
        let x = ctx.bvs("x", 8)?;
        let y = ctx.bvs("y", 8)?;
        solver.add(&ctx.eq_(&y, &ctx.add(&x, bv(&ctx, 1, 8))?)?)?;
        let values = solver.batch_eval(&[x.clone(), y.clone()])?;
        assert_eq!(values.len(), 2);
        let expected_y = ctx.add(&values[0], bv(&ctx, 1, 8))?.simplify()?;
        assert_eq!(values[1], expected_y);
        Ok(())
    }

    #[test]
    fn test_model_cache_matches_cacheless() -> Result<(), ClarirsError> {
        let ctx = Context::new();
        let mut cached = ModelCacheMixin::new(SmtrsSolver::new(&ctx));
        let mut cacheless = SmtrsSolver::new(&ctx);
        let x = ctx.bvs("x", 32)?;
        let c1 = ctx.uge(&x, bv(&ctx, 10, 32))?;
        let c2 = ctx.ule(&x, bv(&ctx, 20, 32))?;
        cached.add(&c1)?;
        cached.add(&c2)?;
        cacheless.add(&c1)?;
        cacheless.add(&c2)?;
        assert_eq!(cached.satisfiable()?, cacheless.satisfiable()?);
        assert!(cached.satisfiable()?);
        let v = cached.eval(&x)?;
        let in_range = cached.is_true(&ctx.and2(
            &ctx.uge(&v, bv(&ctx, 10, 32))?,
            &ctx.ule(&v, bv(&ctx, 20, 32))?,
        )?)?;
        assert!(
            in_range,
            "cached eval produced an out-of-range value: {v:?}"
        );
        let extra_sat = ctx.eq_(&x, v.clone().into_bitvec().unwrap())?;
        assert!(cached.satisfiable_with_extra(&[extra_sat])?);
        let extra_unsat = ctx.eq_(&x, bv(&ctx, 100, 32))?;
        assert_eq!(
            cached.satisfiable_with_extra(std::slice::from_ref(&extra_unsat))?,
            cacheless.satisfiable_with_extra(&[extra_unsat])?,
        );
        assert!(!cached.satisfiable_with_extra(&[ctx.eq_(&x, bv(&ctx, 100, 32))?])?);
        Ok(())
    }

    #[test]
    fn test_model_cache_unsat() -> Result<(), ClarirsError> {
        let ctx = Context::new();
        let mut cached = ModelCacheMixin::new(SmtrsSolver::new(&ctx));
        let x = ctx.bvs("x", 8)?;
        cached.add(&ctx.eq_(&x, bv(&ctx, 1, 8))?)?;
        cached.add(&ctx.eq_(&x, bv(&ctx, 2, 8))?)?;
        assert!(!cached.satisfiable()?);
        assert!(!cached.satisfiable()?);
        Ok(())
    }

    #[test]
    fn test_fp_neq_is_ieee() -> Result<(), ClarirsError> {
        let ctx = Context::new();
        let mut solver = SmtrsSolver::new(&ctx);
        let x = ctx.fps("x", FSort::f64())?;
        // x != x is satisfiable for floats: NaN is IEEE-unequal to itself.
        solver.add(&ctx.neq(&x, &x)?)?;
        assert!(solver.satisfiable()?);
        // ...and NaN is the only witness.
        solver.add(&ctx.not(&ctx.fp_is_nan(&x)?)?)?;
        assert!(!solver.satisfiable()?);
        Ok(())
    }

    #[test]
    fn test_fp_eval_reads_back_a_float() -> Result<(), ClarirsError> {
        let ctx = Context::new();
        let mut solver = SmtrsSolver::new(&ctx);
        let x = ctx.fps("x", FSort::f32())?;
        let two = ctx.fpv(Float::from_f64_with_rounding(
            2.5,
            FPRM::NearestTiesToEven,
            FSort::f32(),
        )?)?;
        solver.add(&ctx.fp_eq(&x, &two)?)?;
        let v = solver.eval(&x)?;
        let AstOp::FPV(f) = v.op() else {
            panic!("expected a float literal, got {v:?}");
        };
        assert_eq!(f.to_f64(), Some(2.5));
        // An expression over x, and enumeration, both go through the same
        // lowering.
        let sum = ctx.fp_add(&x, &x, FPRM::NearestTiesToEven)?;
        let AstOp::FPV(f) = solver.eval(&sum)?.op().clone() else {
            panic!("expected a float literal");
        };
        assert_eq!(f.to_f64(), Some(5.0));
        let many = solver.eval_n(&x, 3)?;
        assert_eq!(many.len(), 1);
        Ok(())
    }

    #[test]
    fn test_solver_unsat() -> Result<(), ClarirsError> {
        let ctx = Context::new();
        let mut solver = SmtrsSolver::new(&ctx);
        let x = ctx.bools("x")?;
        let y = ctx.bools("y")?;
        solver.add(&ctx.eq_(&x, &y)?)?;
        solver.add(&ctx.neq(&x, &y)?)?;
        assert!(!solver.satisfiable()?);
        assert!(matches!(solver.eval(&x), Err(ClarirsError::Unsat)));
        Ok(())
    }

    #[test]
    fn test_solver_bool() -> Result<(), ClarirsError> {
        let ctx = Context::new();
        let mut solver = SmtrsSolver::new(&ctx);
        let x = ctx.bools("x")?;
        let y = ctx.bools("y")?;
        solver.add(&ctx.not(&ctx.eq_(&x, &y)?)?)?;
        solver.add(&ctx.eq_(&x, &ctx.true_()?)?)?;
        let x_val = solver.eval(&x)?;
        let y_val = solver.eval(&y)?;
        assert!(x_val.is_true());
        assert!(y_val.is_false());
        Ok(())
    }

    #[test]
    fn test_eval_bool_ops() -> Result<(), ClarirsError> {
        let ctx = Context::new();
        let mut solver = SmtrsSolver::new(&ctx);
        let t = ctx.true_()?;
        let f = ctx.false_()?;
        assert!(solver.eval(&ctx.and2(&t, &f)?)?.is_false());
        assert!(solver.eval(&ctx.or2(&t, &f)?)?.is_true());
        assert!(solver.eval(&ctx.xor2(&t, &t)?)?.is_false());
        assert!(solver.eval(&ctx.ite(&f, &t, &f)?)?.is_false());

        let c = ctx.bools("c")?;
        let x = ctx.bools("x")?;
        let y = ctx.bools("y")?;
        solver.add(&ctx.eq_(&c, &ctx.true_()?)?)?;
        solver.add(&ctx.eq_(&x, &ctx.true_()?)?)?;
        solver.add(&ctx.eq_(&y, &ctx.false_()?)?)?;
        assert!(solver.eval(&ctx.ite(c, x.clone(), y.clone())?)?.is_true());
        assert!(solver.eval(&ctx.and2(&x, &y)?)?.is_false());
        assert!(solver.eval(&ctx.or2(&x, &y)?)?.is_true());
        assert!(solver.eval(&ctx.xor2(&x, &y)?)?.is_true());
        assert!(solver.eval(&ctx.neq(&x, &y)?)?.is_true());
        assert!(solver.eval(&ctx.not(&x)?)?.is_false());
        Ok(())
    }

    #[test]
    fn test_unconstrained_variables_read_as_zero() -> Result<(), ClarirsError> {
        let ctx = Context::new();
        let mut solver = SmtrsSolver::new(&ctx);
        let x = ctx.bvs("x", 16)?;
        let free = ctx.bvs("free", 16)?;
        solver.add(&ctx.eq_(&x, bv(&ctx, 7, 16))?)?;
        let v = solver.eval(&ctx.add(&x, &free)?)?;
        assert_eq!(v, bv(&ctx, 7, 16));
        assert!(solver.eval(&ctx.bools("b")?)?.is_false());
        Ok(())
    }

    #[test]
    fn test_eval_n_enumerates_distinct_values() -> Result<(), ClarirsError> {
        let ctx = Context::new();
        let mut solver = SmtrsSolver::new(&ctx);
        let x = ctx.bvs("x", 8)?;
        solver.add(&ctx.ult(&x, bv(&ctx, 3, 8))?)?;
        let mut values: Vec<u64> = solver
            .eval_n(&x, 10)?
            .iter()
            .map(|v| match v.op() {
                AstOp::BVV(b) => b.to_u64().unwrap(),
                _ => panic!("not a literal"),
            })
            .collect();
        values.sort_unstable();
        assert_eq!(values, vec![0, 1, 2]);
        // The blocking clauses were retired: the solver is unchanged.
        assert_eq!(solver.eval_n(&x, 10)?.len(), 3);
        assert!(solver.satisfiable_with_extra(&[ctx.eq_(&x, bv(&ctx, 2, 8))?])?);

        // Booleans enumerate too.
        let b = ctx.bools("b")?;
        let mut bools = solver.eval_n(&b, 5)?;
        bools.sort_by_key(|v| v.is_true());
        assert_eq!(bools.len(), 2);
        assert!(bools[0].is_false() && bools[1].is_true());
        Ok(())
    }

    mod test_bitvec_optimize {
        use super::*;

        #[test]
        fn concrete_is_returned_as_is() -> Result<(), ClarirsError> {
            let ctx = Context::new();
            let mut solver = SmtrsSolver::new(&ctx);
            let v = bv(&ctx, 42, 64);
            assert_eq!(solver.min_unsigned(&v)?, v);
            assert_eq!(solver.max_unsigned(&v)?, v);
            assert_eq!(solver.min_signed(&v)?, v);
            assert_eq!(solver.max_signed(&v)?, v);
            Ok(())
        }

        #[test]
        fn unsigned_constrained() -> Result<(), ClarirsError> {
            let ctx = Context::new();
            let mut solver = SmtrsSolver::new(&ctx);
            let x = ctx.bvs("x", 64)?;
            let lo = bv(&ctx, 10, 64);
            let hi = bv(&ctx, 20, 64);
            solver.add(&ctx.uge(&x, &lo)?)?;
            solver.add(&ctx.ule(&x, &hi)?)?;
            assert_eq!(solver.min_unsigned(&x)?, lo);
            assert_eq!(solver.max_unsigned(&x)?, hi);
            Ok(())
        }

        #[test]
        fn unsigned_complex() -> Result<(), ClarirsError> {
            let ctx = Context::new();
            let mut solver = SmtrsSolver::new(&ctx);
            let x = ctx.bvs("x", 8)?;
            let y = ctx.bvs("y", 8)?;
            solver.add(&ctx.ugt(&x, bv(&ctx, 5, 8))?)?;
            solver.add(&ctx.ult(&y, bv(&ctx, 10, 8))?)?;
            let sum = ctx.add(&x, &y)?;
            solver.add(&ctx.eq_(&ctx.extract(&sum, 0, 0)?, bv(&ctx, 0, 1))?)?;
            assert_eq!(solver.min_unsigned(&x)?, bv(&ctx, 6, 8));

            let mut solver = SmtrsSolver::new(&ctx);
            solver.add(&ctx.ult(&x, bv(&ctx, 100, 8))?)?;
            solver.add(&ctx.ugt(&y, bv(&ctx, 20, 8))?)?;
            solver.add(&ctx.ugt(&x, &y)?)?;
            assert_eq!(solver.max_unsigned(&x)?, bv(&ctx, 99, 8));
            Ok(())
        }

        #[test]
        fn signed_constrained() -> Result<(), ClarirsError> {
            let ctx = Context::new();
            let mut solver = SmtrsSolver::new(&ctx);
            let x = ctx.bvs("x", 64)?;
            let lo = bv(&ctx, 0xfffffffffffffff6, 64); // -10
            let hi = bv(&ctx, 20, 64);
            solver.add(&ctx.sge(&x, &lo)?)?;
            solver.add(&ctx.sle(&x, &hi)?)?;
            assert_eq!(solver.min_signed(&x)?, lo);
            assert_eq!(solver.max_signed(&x)?, hi);
            // Unsigned extrema of the same set: 0 and -1.
            assert_eq!(solver.min_unsigned(&x)?, bv(&ctx, 0, 64));
            assert_eq!(solver.max_unsigned(&x)?, bv(&ctx, u64::MAX, 64));
            Ok(())
        }

        #[test]
        fn signed_complex() -> Result<(), ClarirsError> {
            let ctx = Context::new();
            let mut solver = SmtrsSolver::new(&ctx);
            let x = ctx.bvs("x", 8)?;
            let y = ctx.bvs("y", 8)?;
            solver.add(&ctx.sgt(&x, bv(&ctx, 0xfb, 8))?)?; // x > -5
            solver.add(&ctx.slt(&y, bv(&ctx, 10, 8))?)?;
            let sum = ctx.add(&x, &y)?;
            solver.add(&ctx.eq_(&ctx.extract(&sum, 0, 0)?, bv(&ctx, 0, 1))?)?;
            assert_eq!(solver.min_signed(&x)?, bv(&ctx, 0xfc, 8)); // -4

            let mut solver = SmtrsSolver::new(&ctx);
            solver.add(&ctx.slt(&x, bv(&ctx, 100, 8))?)?;
            solver.add(&ctx.sgt(&y, bv(&ctx, 0xec, 8))?)?; // y > -20
            solver.add(&ctx.sgt(&x, &y)?)?;
            assert_eq!(solver.max_signed(&x)?, bv(&ctx, 99, 8));
            Ok(())
        }

        #[test]
        fn signed_negative_range() -> Result<(), ClarirsError> {
            let ctx = Context::new();
            let mut solver = SmtrsSolver::new(&ctx);
            let x = ctx.bvs("x", 8)?;
            let lo = bv(&ctx, 0x9c, 8); // -100
            let hi = bv(&ctx, 0xf6, 8); // -10
            solver.add(&ctx.sge(&x, &lo)?)?;
            solver.add(&ctx.sle(&x, &hi)?)?;
            assert_eq!(solver.min_signed(&x)?, lo);
            assert_eq!(solver.max_signed(&x)?, hi);
            Ok(())
        }

        #[test]
        fn unsat_is_reported() -> Result<(), ClarirsError> {
            let ctx = Context::new();
            let mut solver = SmtrsSolver::new(&ctx);
            let x = ctx.bvs("x", 8)?;
            solver.add(&ctx.eq_(&x, bv(&ctx, 1, 8))?)?;
            solver.add(&ctx.eq_(&x, bv(&ctx, 2, 8))?)?;
            assert!(matches!(solver.min_unsigned(&x), Err(ClarirsError::Unsat)));
            Ok(())
        }
    }

    #[test]
    fn test_unsat_core() -> Result<(), ClarirsError> {
        let ctx = Context::new();
        let mut solver = SmtrsSolver::new_with_options(&ctx, None, true);
        let x = ctx.bvs("x", 8)?;
        solver.add(&ctx.ugt(&x, bv(&ctx, 10, 8))?)?; // 0
        solver.add(&ctx.ult(&x, bv(&ctx, 5, 8))?)?; // 1
        solver.add(&ctx.ugt(&x, bv(&ctx, 0, 8))?)?; // 2, not needed
        assert!(!solver.satisfiable()?);
        let core = solver.unsat_core()?;
        assert!(core.contains(&0));
        assert!(core.contains(&1));
        assert!(core.len() <= 3);
        Ok(())
    }

    #[test]
    fn test_unsat_core_bool() -> Result<(), ClarirsError> {
        let ctx = Context::new();
        let mut solver = SmtrsSolver::new_with_options(&ctx, None, true);
        let x = ctx.bools("x")?;
        let y = ctx.bools("y")?;
        solver.add(&ctx.eq_(&x, &ctx.true_()?)?)?;
        solver.add(&ctx.eq_(&y, &ctx.true_()?)?)?;
        solver.add(&ctx.eq_(&x, &y)?)?;
        solver.add(&ctx.neq(&x, &y)?)?;
        assert!(!solver.satisfiable()?);
        let core = solver.unsat_core()?;
        assert!(!core.is_empty());
        assert!(core.len() <= 4);
        Ok(())
    }

    #[test]
    fn test_unsat_core_errors() -> Result<(), ClarirsError> {
        let ctx = Context::new();
        let x = ctx.bools("x")?;

        let mut solver = SmtrsSolver::new(&ctx);
        solver.add(&x)?;
        solver.add(&ctx.not(&x)?)?;
        assert!(!solver.satisfiable()?);
        assert!(solver.unsat_core().is_err());

        let mut solver = SmtrsSolver::new_with_options(&ctx, None, true);
        solver.add(&x)?;
        assert!(solver.satisfiable()?);
        assert!(solver.unsat_core().is_err());
        Ok(())
    }

    #[test]
    fn test_clone_is_independent_and_borrows_then_forks() -> Result<(), ClarirsError> {
        let ctx = Context::new();
        let mut parent = SmtrsSolver::new(&ctx);
        let x = ctx.bvs("x", 8)?;
        parent.add(&ctx.ult(&x, bv(&ctx, 10, 8))?)?;
        assert!(parent.satisfiable()?);

        // A scoped query on a clone: borrowed from the parent's engine.
        let mut child = parent.clone();
        child.add(&ctx.eq_(&x, bv(&ctx, 3, 8))?)?;
        assert_eq!(child.eval(&x)?, bv(&ctx, 3, 8));
        // The parent is unaffected by the pushed level.
        assert!(parent.satisfiable_with_extra(&[ctx.eq_(&x, bv(&ctx, 4, 8))?])?);
        assert_eq!(parent.min_unsigned(&x)?, bv(&ctx, 0, 8));

        // The child keeps being used: it gets its own engine (a fork).
        assert_eq!(child.max_unsigned(&x)?, bv(&ctx, 3, 8));
        child.add(&ctx.eq_(&x, bv(&ctx, 4, 8))?)?;
        assert!(!child.satisfiable()?);
        assert!(parent.satisfiable()?);

        // Both sides diverge after the fork.
        parent.add(&ctx.ugt(&x, bv(&ctx, 7, 8))?)?;
        assert_eq!(parent.min_unsigned(&x)?, bv(&ctx, 8, 8));
        drop(parent);
        assert!(!child.satisfiable()?);
        Ok(())
    }

    /// angr drops a state once it has stepped it. The engine of a dropped
    /// solver stays for the clones made from it: their first query borrows
    /// it, a second forks it, and it goes once no clone depends on it.
    #[test]
    fn test_a_dropped_solver_leaves_its_engine_to_its_clones() -> Result<(), ClarirsError> {
        let ctx = Context::new();
        let x = ctx.bvs("x", 8)?;
        let mut parent = SmtrsSolver::new(&ctx);
        parent.add(&ctx.ugt(&x, bv(&ctx, 5, 8))?)?;
        assert!(parent.satisfiable()?);
        let pid = parent.id;
        let mut child = parent.clone();
        let cid = child.id;
        child.add(&ctx.ult(&x, bv(&ctx, 7, 8))?)?;
        let orphan = parent.clone();
        drop(parent);
        assert!(with_backend(
            |b| !b.has_engine(pid) && b.has_retired_engine(pid)
        ));

        // Borrowed under a push level, then forked into an engine of its own.
        assert_eq!(child.eval(&x)?, bv(&ctx, 6, 8));
        assert!(with_backend(
            |b| !b.has_engine(cid) && b.has_retired_engine(pid)
        ));
        assert_eq!(child.max_unsigned(&x)?, bv(&ctx, 6, 8));
        assert!(with_backend(
            |b| b.has_engine(cid) && b.has_retired_engine(pid)
        ));

        // The last dependant gone, the retired engine goes too.
        drop(orphan);
        assert!(with_backend(|b| !b.has_retired_engine(pid)));
        child.add(&ctx.eq_(&x, bv(&ctx, 6, 8))?)?;
        assert!(child.satisfiable()?);
        drop(child);
        assert!(with_backend(|b| !b.has_engine(cid)));
        Ok(())
    }

    #[test]
    fn test_clear_and_simplify() -> Result<(), ClarirsError> {
        let ctx = Context::new();
        let mut solver = SmtrsSolver::new(&ctx);
        let x = ctx.bvs("x", 8)?;
        solver.add(&ctx.eq_(&x, bv(&ctx, 1, 8))?)?;
        solver.add(&ctx.eq_(&x, bv(&ctx, 2, 8))?)?;
        assert!(!solver.satisfiable()?);
        solver.clear()?;
        assert!(solver.satisfiable()?);
        assert!(solver.constraints()?.is_empty());

        solver.add(&ctx.true_()?)?;
        solver.add(&ctx.eq_(&ctx.add(&x, bv(&ctx, 0, 8))?, bv(&ctx, 5, 8))?)?;
        solver.simplify()?;
        assert_eq!(solver.constraints()?.len(), 1);
        assert_eq!(solver.eval(&x)?, bv(&ctx, 5, 8));
        Ok(())
    }

    #[test]
    fn test_bv_operators_agree_with_the_simplifier() -> Result<(), ClarirsError> {
        // Each symbolic operator is pinned by the solver and compared with
        // clarirs's own constant folding of the same expression.
        let ctx = Context::new();
        let x = ctx.bvs("x", 32)?;
        let y = ctx.bvs("y", 32)?;
        let (xv, yv) = (bv(&ctx, 0xdead_beef, 32), bv(&ctx, 0x0000_0013, 32));
        let exprs = [
            ctx.add(&x, &y)?,
            ctx.sub(&x, &y)?,
            ctx.mul(&x, &y)?,
            ctx.udiv(&x, &y)?,
            ctx.sdiv(&x, &y)?,
            ctx.urem(&x, &y)?,
            ctx.srem(&x, &y)?,
            ctx.shl(&x, &y)?,
            ctx.lshr(&x, &y)?,
            ctx.ashr(&x, &y)?,
            ctx.rotate_left(&x, &y)?,
            ctx.rotate_right(&x, &y)?,
            ctx.and2(&x, &y)?,
            ctx.or2(&x, &y)?,
            ctx.xor2(&x, &y)?,
            ctx.not(&x)?,
            ctx.neg(&x)?,
            ctx.byte_reverse(&x)?,
            ctx.zero_ext(&x, 8)?,
            ctx.sign_ext(&x, 8)?,
            ctx.extract(&x, 23, 8)?,
            ctx.concat2(&x, &y)?,
            ctx.ite(&ctx.ult(&x, &y)?, &x, &y)?,
        ];
        for expr in exprs {
            let mut solver = SmtrsSolver::new(&ctx);
            solver.add(&ctx.eq_(&x, &xv)?)?;
            solver.add(&ctx.eq_(&y, &yv)?)?;
            let expected = expr.replace(&x, &xv)?.replace(&y, &yv)?.simplify()?;
            assert!(expected.concrete(), "reference did not fold: {expected:?}");
            assert_eq!(solver.eval(&expr)?, expected, "mismatch on {expr:?}");
            // And via enumeration, which takes the bit-blasting path.
            assert_eq!(
                solver.eval_n(&expr, 2)?,
                vec![expected.clone()],
                "eval_n mismatch on {expr:?}"
            );
        }
        Ok(())
    }

    #[test]
    fn test_comparisons() -> Result<(), ClarirsError> {
        let ctx = Context::new();
        let mut solver = SmtrsSolver::new(&ctx);
        let x = ctx.bvs("x", 8)?;
        solver.add(&ctx.eq_(&x, bv(&ctx, 0xf0, 8))?)?; // -16 signed, 240 unsigned
        let seven = bv(&ctx, 7, 8);
        assert!(solver.eval(&ctx.ugt(&x, &seven)?)?.is_true());
        assert!(solver.eval(&ctx.uge(&x, &seven)?)?.is_true());
        assert!(solver.eval(&ctx.ult(&x, &seven)?)?.is_false());
        assert!(solver.eval(&ctx.ule(&x, &seven)?)?.is_false());
        assert!(solver.eval(&ctx.sgt(&x, &seven)?)?.is_false());
        assert!(solver.eval(&ctx.sge(&x, &seven)?)?.is_false());
        assert!(solver.eval(&ctx.slt(&x, &seven)?)?.is_true());
        assert!(solver.eval(&ctx.sle(&x, &seven)?)?.is_true());
        Ok(())
    }

    #[test]
    fn test_timeout_reports_unknown() -> Result<(), ClarirsError> {
        let ctx = Context::new();
        // A 1 ms budget on a factoring problem: the answer is `unknown`, not a
        // hang and not a wrong answer.
        let mut solver = SmtrsSolver::new_with_timeout(&ctx, Some(1));
        let x = ctx.bvs("x", 64)?;
        let y = ctx.bvs("y", 64)?;
        let product = ctx.mul(&x, &y)?;
        solver.add(&ctx.eq_(&product, bv(&ctx, 0xc4d4_a7e3_1f2b_6d61, 64))?)?;
        solver.add(&ctx.ugt(&x, bv(&ctx, 1, 64))?)?;
        solver.add(&ctx.ugt(&y, bv(&ctx, 1, 64))?)?;
        solver.add(&ctx.ult(&x, &y)?)?;
        match solver.satisfiable() {
            Err(ClarirsError::SolverUnknown(_)) => {}
            Ok(true) => {
                // Fast machine: the answer arrived in time, so it must be right.
                let (xv, yv) = (solver.eval(&x)?, solver.eval(&y)?);
                let check = ctx.mul(&xv, &yv)?.simplify()?;
                assert_eq!(check, bv(&ctx, 0xc4d4_a7e3_1f2b_6d61, 64));
            }
            other => panic!("unexpected: {other:?}"),
        }
        // The solver is usable afterwards.
        let mut easy = SmtrsSolver::new_with_timeout(&ctx, Some(10_000));
        easy.add(&ctx.eq_(&x, bv(&ctx, 3, 64))?)?;
        assert!(easy.satisfiable()?);
        Ok(())
    }

    #[test]
    fn test_strings_solve_and_read_back() -> Result<(), ClarirsError> {
        let ctx = Context::new();
        let mut solver = SmtrsSolver::new(&ctx);
        let s = ctx.strings("s")?;
        solver.add(&ctx.eq_(&s, &ctx.stringv("hi")?)?)?;
        assert!(solver.satisfiable()?);
        assert_eq!(solver.eval(&s)?, ctx.stringv("hi")?);
        assert_eq!(
            solver.batch_eval(std::slice::from_ref(&s))?,
            vec![ctx.stringv("hi")?]
        );
        // An expression over the variable folds after substitution.
        let hello = ctx.str_concat(&s, &ctx.stringv(" there")?)?;
        assert_eq!(solver.eval(&hello)?, ctx.stringv("hi there")?);
        let len = ctx.str_len(&s)?;
        assert_eq!(solver.eval(&len)?, bv(&ctx, 2, 64));
        // Lengths cross the bit-vector/Int bridge in constraints too.
        assert!(solver.satisfiable_with_extra(&[ctx.eq_(&len, bv(&ctx, 2, 64))?])?);
        assert!(!solver.satisfiable_with_extra(&[ctx.eq_(&len, bv(&ctx, 3, 64))?])?);
        assert!(solver.satisfiable_with_extra(&[ctx.str_prefix_of(&ctx.stringv("h")?, &s)?])?);
        assert!(!solver.satisfiable_with_extra(&[ctx.str_contains(&s, &ctx.stringv("x")?)?])?);
        Ok(())
    }

    #[test]
    fn test_string_enumeration_and_latin1() -> Result<(), ClarirsError> {
        let ctx = Context::new();
        let mut solver = SmtrsSolver::new(&ctx);
        let s = ctx.strings("s")?;
        let len = ctx.str_len(&s)?;
        solver.add(&ctx.eq_(&len, bv(&ctx, 1, 64))?)?;
        solver.add(&ctx.str_prefix_of(&ctx.stringv("a")?, &s)?)?;
        // Exactly one string of length 1 starts with "a".
        let values = solver.eval_n(&s, 5)?;
        assert_eq!(values, vec![ctx.stringv("a")?]);

        let mut solver = SmtrsSolver::new(&ctx);
        solver.add(&ctx.eq_(&len, bv(&ctx, 1, 64))?)?;
        solver.add(&ctx.str_is_digit(&s)?)?;
        let mut digits: Vec<String> = solver
            .eval_n(&s, 20)?
            .iter()
            .map(|v| match v.op() {
                AstOp::StringV(t) => t.clone(),
                _ => panic!("not a string literal"),
            })
            .collect();
        digits.sort();
        assert_eq!(digits.len(), 10);
        assert_eq!(digits[0], "0");
        assert_eq!(digits[9], "9");

        // Code points up to U+00FF are representable; beyond is refused.
        let mut solver = SmtrsSolver::new(&ctx);
        solver.add(&ctx.eq_(&s, &ctx.stringv("h\u{e9}llo \"q\" \\")?)?)?;
        assert_eq!(solver.eval(&s)?, ctx.stringv("h\u{e9}llo \"q\" \\")?);
        let mut solver = SmtrsSolver::new(&ctx);
        solver.add(&ctx.eq_(&s, &ctx.stringv("\u{4e2d}")?)?)?;
        assert!(matches!(
            solver.satisfiable(),
            Err(ClarirsError::UnsupportedOperation(_))
        ));
        Ok(())
    }

    #[test]
    fn test_vsa_operations_are_rejected() -> Result<(), ClarirsError> {
        let ctx = Context::new();
        let mut solver = SmtrsSolver::new(&ctx);
        let x = ctx.bvs("x", 8)?;
        solver.add(&ctx.eq_(&ctx.union(&x, bv(&ctx, 1, 8))?, bv(&ctx, 1, 8))?)?;
        assert!(matches!(
            solver.satisfiable(),
            Err(ClarirsError::UnsupportedOperation(_))
        ));
        Ok(())
    }
}
