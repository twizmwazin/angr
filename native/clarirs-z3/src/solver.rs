use crate::astext::AstExtZ3;
use crate::rc::{RcAst, RcModel, RcOptimize, RcParamSet, RcSolver};
use clarirs_core::prelude::*;
use std::cell::RefCell;
use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use z3_sys::{Z3_L_FALSE, Z3_L_TRUE};

/// A persistent z3 solver, incrementally extended as constraints are added.
///
/// Kept in thread-local storage keyed by [`Z3Solver::cache_id`], since z3 objects
/// are bound to the thread-local `Z3_CONTEXT`. `Z3Solver` stores only the id, so
/// it stays `Send`; first use on a new thread rebuilds there.
struct CachedSolver {
    solver: RcSolver,
    /// Converted roots of the asserted constraints. The z3 solver holds these
    /// terms internally anyway; keeping the `RcAst` roots too pins their
    /// conversion-cache entries for the solver's lifetime, so shared subterms
    /// of later conversions hit the cache instead of being rebuilt.
    roots: Vec<RcAst>,
    /// Number of `Z3Solver::assertions` already pushed into `solver`.
    asserted: usize,
    /// Hashes of the asserted constraints, in assertion order. Lets a cloned
    /// solver verify that this entry's assertions are a prefix of its own
    /// before borrowing the solver for a scoped check.
    hashes: Vec<u64>,
    /// Model from the most recent successful check, valid for exactly the
    /// `asserted` constraints (cleared whenever more are pushed). Kept so
    /// model queries after a satisfiability check don't re-run the solver.
    model: Option<RcModel>,
    timeout: Option<u32>,
    unsat_core: bool,
}

thread_local! {
    static SOLVER_CACHE: RefCell<HashMap<u64, CachedSolver>> = RefCell::new(HashMap::new());
    /// Witness models for solvers that have no [`SOLVER_CACHE`] entry of their
    /// own: a check answered by borrowing an ancestor's solver stores its model
    /// here, keyed by the borrowing solver's `cache_id`. The `usize` is the
    /// number of assertions the model covers; it is only trusted when it still
    /// equals the solver's current assertion count.
    static MODEL_STASH: RefCell<HashMap<u64, (usize, RcModel)>> = RefCell::new(HashMap::new());
}

static NEXT_SOLVER_ID: AtomicU64 = AtomicU64::new(1);

fn next_solver_id() -> u64 {
    NEXT_SOLVER_ID.fetch_add(1, Ordering::Relaxed)
}

/// Maximum number of un-asserted trailing constraints a clone may pass as
/// per-check assumptions when borrowing an ancestor's live z3 solver. Past
/// this, building an own solver amortizes better than re-sending a long
/// assumption list on every check.
const MAX_BORROW_SUFFIX: usize = 32;

#[derive(Debug)]
pub struct Z3Solver<'c> {
    ctx: &'c Context<'c>,
    assertions: Vec<AstRef<'c>>,
    timeout: Option<u32>,
    unsat_core: bool,
    // Maps constraint index to tracking variable
    tracking_vars: HashMap<usize, AstRef<'c>>,
    /// Identifies this solver's incremental z3 solver in [`SOLVER_CACHE`].
    cache_id: u64,
    /// Nearest ancestor (via `clone`) that had a live entry in [`SOLVER_CACHE`]
    /// when this solver was cloned. A clone starts with no z3 solver of its
    /// own; until it builds one, satisfiability checks can borrow the
    /// ancestor's warm incremental solver, passing this solver's extra
    /// constraints as scoped assumptions (see `try_borrowed_check`).
    parent_id: Option<u64>,
}

impl<'c> Clone for Z3Solver<'c> {
    fn clone(&self) -> Self {
        // Record the nearest ancestor whose z3 solver is live on this thread,
        // so checks on the clone can reuse it instead of solving from scratch.
        // A miss here (entry on another thread, or none yet) only costs the
        // clone a cold build on its first hard query, exactly as before.
        let parent_id = SOLVER_CACHE.with(|cell| {
            let map = cell.borrow();
            if map.contains_key(&self.cache_id) {
                Some(self.cache_id)
            } else {
                self.parent_id.filter(|id| map.contains_key(id))
            }
        });
        Z3Solver {
            ctx: self.ctx,
            assertions: self.assertions.clone(),
            timeout: self.timeout,
            unsat_core: self.unsat_core,
            tracking_vars: self.tracking_vars.clone(),
            cache_id: next_solver_id(),
            parent_id,
        }
    }
}

impl Drop for Z3Solver<'_> {
    fn drop(&mut self) {
        let _ = SOLVER_CACHE.try_with(|cell| {
            if let Ok(mut map) = cell.try_borrow_mut() {
                map.remove(&self.cache_id);
            }
        });
        let _ = MODEL_STASH.try_with(|cell| {
            if let Ok(mut map) = cell.try_borrow_mut() {
                map.remove(&self.cache_id);
            }
        });
    }
}

impl<'c> Z3Solver<'c> {
    pub fn new(ctx: &'c Context<'c>) -> Self {
        Self {
            ctx,
            assertions: vec![],
            timeout: None,
            unsat_core: false,
            tracking_vars: HashMap::new(),
            cache_id: next_solver_id(),
            parent_id: None,
        }
    }

    pub fn new_with_timeout(ctx: &'c Context<'c>, timeout: Option<u32>) -> Self {
        Self {
            ctx,
            assertions: vec![],
            timeout,
            unsat_core: false,
            tracking_vars: HashMap::new(),
            cache_id: next_solver_id(),
            parent_id: None,
        }
    }

    pub fn new_with_options(ctx: &'c Context<'c>, timeout: Option<u32>, unsat_core: bool) -> Self {
        Self {
            ctx,
            assertions: vec![],
            timeout,
            unsat_core,
            tracking_vars: HashMap::new(),
            cache_id: next_solver_id(),
            parent_id: None,
        }
    }

    /// Get the unsat core from the last unsatisfiable check.
    /// Returns a vector of constraint indices that form the unsat core.
    ///
    /// This method only works if the solver was created with unsat_core enabled
    /// and the last satisfiability check returned UNSAT.
    pub fn unsat_core(&mut self) -> Result<Vec<usize>, ClarirsError> {
        if !self.unsat_core {
            return Err(ClarirsError::UnsupportedOperation(
                "Unsat core tracking is not enabled. Use new_with_options with unsat_core=true"
                    .to_string(),
            ));
        }

        self.with_cached_solver(|cached| {
            let z3_solver = &mut cached.solver;
            // Check if UNSAT
            if z3_solver.check()? != Z3_L_FALSE {
                return Err(ClarirsError::UnsupportedOperation(
                    "Can only get unsat core after an UNSAT result".to_string(),
                ));
            }

            let core_vector = z3_solver.get_unsat_core()?;
            let core_size = core_vector.size();

            let mut core_indices = Vec::new();

            // Build a reverse map from tracking variable to index
            let mut track_to_idx: HashMap<String, usize> = HashMap::new();
            for (idx, track_var) in &self.tracking_vars {
                // Extract the variable name
                if let Some(vars) = track_var.variables().iter().next() {
                    track_to_idx.insert(vars.to_string(), *idx);
                }
            }

            for i in 0..core_size {
                let core_ast = core_vector.get(i)?;
                // Convert the Z3 AST back to a AstRef to get its variable name
                let bool_ast = AstRef::from_z3(self.ctx, &core_ast)?;
                if let Some(vars) = bool_ast.variables().iter().next()
                    && let Some(idx) = track_to_idx.get(&vars.to_string())
                {
                    core_indices.push(*idx);
                }
            }

            Ok(core_indices)
        })
    }
}

impl<'c> HasContext<'c> for Z3Solver<'c> {
    fn context(&self) -> &'c Context<'c> {
        self.ctx
    }
}

impl<'c> Z3Solver<'c> {
    /// Build a fresh z3 solver configured with this solver's params (timeout,
    /// unsat_core) but with no assertions yet.
    fn new_z3_solver(&self) -> Result<RcSolver, ClarirsError> {
        let mut z3_solver = RcSolver::new()?;

        let mut params = RcParamSet::new()?;
        if let Some(timeout) = self.timeout {
            params.set_u32("timeout", timeout)?;
        }
        if self.unsat_core {
            params.set_bool("unsat_core", true)?;
        }
        // Z3 >= 4.14 regression: the propagate-values stage of the default
        // tactic loses DAG sharing on fpa2bv output, and the loss compounds
        // per round -- a chained-FP-add goal grows ~50x over the default 4
        // rounds and bit-blasts into an intractable SAT instance (claripy
        // sidesteps this by pinning z3-solver 4.13). One round keeps the
        // encoding compact; the same formula then solves faster than on 4.13.
        params.set_u32("max_rounds", 1)?;
        z3_solver.set_params(params)?;
        Ok(z3_solver)
    }

    /// Assert `self.assertions[idx]` into `z3_solver`, using assert-and-track
    /// when unsat-core extraction is enabled. The converted root is pushed into
    /// `roots` so its conversion-cache entries stay live while the z3 solver
    /// holds the term.
    fn assert_at(
        &self,
        z3_solver: &mut RcSolver,
        roots: &mut Vec<RcAst>,
        idx: usize,
    ) -> Result<(), ClarirsError> {
        let converted = self.assertions[idx].to_z3()?;
        if self.unsat_core
            && let Some(track_var) = self.tracking_vars.get(&idx)
        {
            let track_z3 = track_var.to_z3()?;
            z3_solver.assert_and_track(&converted, &track_z3)?;
        } else {
            z3_solver.assert(&converted)?;
        }
        roots.push(converted);
        Ok(())
    }

    /// Run `f` against this solver's cached z3 solver (per thread), pushing only
    /// the assertions added since the previous call rather than rebuilding and
    /// re-asserting the whole set each time.
    fn with_cached_solver<T>(
        &self,
        f: impl FnOnce(&mut CachedSolver) -> Result<T, ClarirsError>,
    ) -> Result<T, ClarirsError> {
        SOLVER_CACHE.with(|cell| {
            // Reusable only if built with the same params and its asserted
            // constraints are still a prefix of the current set.
            let reusable = match cell.borrow().get(&self.cache_id) {
                Some(c) => {
                    c.timeout == self.timeout
                        && c.unsat_core == self.unsat_core
                        && c.asserted <= self.assertions.len()
                }
                None => false,
            };

            if !reusable {
                // Build outside the cache borrow.
                let mut solver = self.new_z3_solver()?;
                let mut roots = Vec::new();
                for idx in 0..self.assertions.len() {
                    self.assert_at(&mut solver, &mut roots, idx)?;
                }
                cell.borrow_mut().insert(
                    self.cache_id,
                    CachedSolver {
                        solver,
                        roots,
                        asserted: self.assertions.len(),
                        hashes: self.assertions.iter().map(|a| a.hash()).collect(),
                        model: None,
                        timeout: self.timeout,
                        unsat_core: self.unsat_core,
                    },
                );
            }

            let mut map = cell.borrow_mut();
            let cached = map
                .get_mut(&self.cache_id)
                .expect("cache entry just ensured");
            // Push any assertions added since the last call. The stored model
            // reflects only the assertions checked so far, so it goes stale.
            while cached.asserted < self.assertions.len() {
                let idx = cached.asserted;
                self.assert_at(&mut cached.solver, &mut cached.roots, idx)?;
                cached.asserted = idx + 1;
                cached.hashes.push(self.assertions[idx].hash());
                cached.model = None;
            }
            f(cached)
        })
    }

    /// Whether this solver already has a usable [`SOLVER_CACHE`] entry on this
    /// thread (same params, asserted set still a prefix of the current one).
    fn has_own_entry(&self) -> bool {
        SOLVER_CACHE.with(|cell| {
            matches!(
                cell.borrow().get(&self.cache_id),
                Some(c) if c.timeout == self.timeout
                    && c.unsat_core == self.unsat_core
                    && c.asserted <= self.assertions.len()
            )
        })
    }

    /// Answer a satisfiability check by borrowing the nearest ancestor's live
    /// z3 solver, if possible.
    ///
    /// A clone shares its ancestor's asserted constraints as a prefix; the
    /// constraints it added since (plus `extra`) go to `check_assumptions` as
    /// scoped assumptions, which never modify the ancestor's solver but reuse
    /// everything it has already learned. This turns the very common
    /// "clone the state, add a branch guard, check feasibility" pattern from a
    /// from-scratch solve into an incremental one.
    ///
    /// Returns `None` when there is nothing suitable to borrow (no ancestor
    /// entry, params differ, prefix mismatch, or too many trailing
    /// constraints); the caller then falls back to its own solver. On a
    /// successful satisfiable outcome the witness model is stashed under this
    /// solver's id so model queries and the model-cache mixin can use it.
    fn try_borrowed_check(&self, extra: &[RcAst]) -> Option<Result<bool, ClarirsError>> {
        if self.unsat_core {
            return None;
        }
        let parent_id = self.parent_id?;
        SOLVER_CACHE.with(|cell| {
            let mut map = cell.borrow_mut();
            let cached = map.get_mut(&parent_id)?;
            if cached.timeout != self.timeout
                || cached.unsat_core
                || cached.asserted > self.assertions.len()
                || self.assertions.len() - cached.asserted + extra.len() > MAX_BORROW_SUFFIX
            {
                return None;
            }
            // The ancestor's asserted constraints must be exactly our prefix;
            // the ancestor may have diverged since the clone.
            if !cached
                .hashes
                .iter()
                .zip(&self.assertions)
                .all(|(h, a)| *h == a.hash())
            {
                return None;
            }

            let mut assumptions =
                Vec::with_capacity(self.assertions.len() - cached.asserted + extra.len());
            for a in &self.assertions[cached.asserted..] {
                match a.to_z3() {
                    Ok(converted) => assumptions.push(converted),
                    Err(e) => return Some(Err(e)),
                }
            }
            assumptions.extend_from_slice(extra);

            Some(match cached.solver.check_assumptions(&assumptions) {
                Ok(Z3_L_TRUE) => {
                    if let Ok(model) = cached.solver.model() {
                        MODEL_STASH.with(|stash| {
                            stash
                                .borrow_mut()
                                .insert(self.cache_id, (self.assertions.len(), model));
                        });
                    }
                    Ok(true)
                }
                Ok(Z3_L_FALSE) => Ok(false),
                Ok(_) => Err(ClarirsError::SolverUnknown(cached.solver.reason_unknown())),
                Err(e) => Err(e),
            })
        })
    }

    /// Drop this solver's cached z3 solver, forcing a rebuild on next use.
    /// Required whenever the assertion set changes other than by appending.
    fn invalidate_cache(&self) {
        SOLVER_CACHE.with(|cell| {
            cell.borrow_mut().remove(&self.cache_id);
        });
        // A stashed model is validated by assertion count alone, which a
        // non-append rewrite (clear/simplify) could leave coincidentally
        // matching, so drop it explicitly.
        MODEL_STASH.with(|cell| {
            cell.borrow_mut().remove(&self.cache_id);
        });
    }

    fn mk_filled_optimize(&self) -> Result<RcOptimize, ClarirsError> {
        let mut z3_optimize = RcOptimize::new()?;

        for assertion in &self.assertions {
            let converted = assertion.to_z3()?;
            z3_optimize.assert(&converted)?;
        }

        Ok(z3_optimize)
    }

    fn make_model(&self) -> Result<RcModel, ClarirsError> {
        // A model stashed by a borrowed check is still valid if no assertions
        // were added since.
        let stashed = MODEL_STASH.with(|cell| {
            cell.borrow()
                .get(&self.cache_id)
                .filter(|(n, _)| *n == self.assertions.len())
                .map(|(_, m)| m.clone())
        });
        if let Some(model) = stashed {
            return Ok(model);
        }
        // No own z3 solver yet: answer from an ancestor's warm solver if one
        // is available, which stashes the model on success.
        if !self.has_own_entry()
            && let Some(result) = self.try_borrowed_check(&[])
        {
            match result? {
                true => {
                    let stashed = MODEL_STASH
                        .with(|cell| cell.borrow().get(&self.cache_id).map(|(_, m)| m.clone()));
                    if let Some(model) = stashed {
                        return Ok(model);
                    }
                    // Model extraction failed; fall through to an own solve.
                }
                false => return Err(ClarirsError::Unsat),
            }
        }
        self.with_cached_solver(|cached| {
            // A model from an earlier check of the same assertions is still
            // valid; reuse it instead of re-running the solver.
            if let Some(model) = &cached.model {
                return Ok(model.clone());
            }
            match cached.solver.check()? {
                Z3_L_TRUE => {}
                Z3_L_FALSE => return Err(ClarirsError::Unsat),
                _ => {
                    return Err(ClarirsError::SolverUnknown(cached.solver.reason_unknown()));
                }
            }
            let model = cached.solver.model()?;
            cached.model = Some(model.clone());
            Ok(model)
        })
    }

    /// Evaluate `expr` against a single model. More efficient than the generic
    /// `eval_n(_, 1)` path, which rebuilds the solver and adds an exclusion
    /// constraint; used to back the `Solver::eval` override below.
    fn eval_in_model(&self, expr: &AstRef<'c>) -> Result<AstRef<'c>, ClarirsError> {
        let expr = expr.simplify()?.simplify_z3()?;

        // If the expression is concrete, we can return it directly
        if expr.concrete() {
            return Ok(expr);
        }

        // Expression is not concrete, we need to get a model from Z3 and
        // replace the variables with the values from the model
        let model = self.make_model()?;

        AstRef::from_z3(expr.context(), model.eval(&expr.to_z3()?)?)
    }
}

/// Whether `expr` contains an `fp.to_ieee_bv` node anywhere in its tree.
///
/// Such expressions can evaluate to a non-constant term against a Z3 model
/// (fp.to_ieee_bv stays uninterpreted), so eval binds them to an auxiliary
/// variable instead of reading them from the model directly.
fn contains_fp_to_ieeebv(expr: &AstRef<'_>) -> bool {
    matches!(expr.op(), AstOp::FpToIEEEBV(_))
        || expr.child_iter().any(|c| contains_fp_to_ieeebv(&c))
}

impl<'c> Solver<'c> for Z3Solver<'c> {
    fn add(&mut self, constraint: &AstRef<'c>) -> Result<(), ClarirsError> {
        let idx = self.assertions.len();
        self.assertions.push(constraint.clone());

        // Create a tracking variable if unsat_core is enabled
        if self.unsat_core {
            let track_name = format!("__track_{idx}");
            let track_var = self.ctx.bools(&track_name)?;
            self.tracking_vars.insert(idx, track_var);
        }

        Ok(())
    }

    fn clear(&mut self) -> Result<(), ClarirsError> {
        self.assertions.clear();
        self.tracking_vars.clear();
        self.invalidate_cache();
        Ok(())
    }

    fn constraints(&self) -> Result<Vec<AstRef<'c>>, ClarirsError> {
        Ok(self.assertions.clone())
    }

    fn simplify(&mut self) -> Result<(), ClarirsError> {
        self.assertions = self
            .assertions
            .iter()
            .filter_map(|c| {
                let simplified = c.simplify_z3().ok()?;
                if simplified.is_true() {
                    None
                } else {
                    Some(Ok(simplified))
                }
            })
            .collect::<Result<Vec<_>, ClarirsError>>()?;
        // The assertion set changed in place; the cached solver is now stale.
        self.invalidate_cache();
        Ok(())
    }

    fn satisfiable(&mut self) -> Result<bool, ClarirsError> {
        if !self.has_own_entry()
            && let Some(result) = self.try_borrowed_check(&[])
        {
            return result;
        }
        self.with_cached_solver(|cached| {
            if cached.model.is_some() {
                // A model for the current assertions is already known.
                return Ok(true);
            }
            match cached.solver.check()? {
                Z3_L_TRUE => {
                    // The check produced a model; keep it so later model
                    // queries (and the model-cache mixin) get it for free.
                    cached.model = cached.solver.model().ok();
                    Ok(true)
                }
                Z3_L_FALSE => Ok(false),
                _ => Err(ClarirsError::SolverUnknown(cached.solver.reason_unknown())),
            }
        })
    }

    fn satisfiable_with_extra(&mut self, extra: &[AstRef<'c>]) -> Result<bool, ClarirsError> {
        // Check with the extra constraints as assumptions on the persistent
        // incremental solver: no clone, no from-scratch re-assertion. This is
        // angr's hottest solver call (every branch feasibility check).
        let mut assumptions = Vec::with_capacity(extra.len());
        for c in extra {
            assumptions.push(c.simplify_z3()?.to_z3()?);
        }
        if !self.has_own_entry()
            && let Some(result) = self.try_borrowed_check(&assumptions)
        {
            return result;
        }
        self.with_cached_solver(|cached| {
            if assumptions.is_empty() && cached.model.is_some() {
                return Ok(true);
            }
            match cached.solver.check_assumptions(&assumptions)? {
                Z3_L_TRUE => {
                    // The model satisfies the assumptions on top of every
                    // asserted constraint, so it is also a valid model of the
                    // persistent set alone.
                    cached.model = cached.solver.model().ok();
                    Ok(true)
                }
                // UNSAT under assumptions says nothing about the persistent
                // set, so any stored model stays valid.
                Z3_L_FALSE => Ok(false),
                _ => Err(ClarirsError::SolverUnknown(cached.solver.reason_unknown())),
            }
        })
    }

    fn last_model_eval(
        &mut self,
        exprs: &[AstRef<'c>],
    ) -> Result<Option<Vec<AstRef<'c>>>, ClarirsError> {
        // Look only; never build a solver or run a check here. A model is
        // usable only when it covers every current assertion. Borrowed checks
        // stash their model separately from own-solver checks.
        let model = MODEL_STASH.with(|cell| {
            cell.borrow()
                .get(&self.cache_id)
                .filter(|(n, _)| *n == self.assertions.len())
                .map(|(_, m)| m.clone())
        });
        let model = match model {
            Some(model) => Some(model),
            None => SOLVER_CACHE.with(|cell| {
                cell.borrow()
                    .get(&self.cache_id)
                    .filter(|c| c.asserted == self.assertions.len())
                    .and_then(|c| c.model.clone())
            }),
        };
        let Some(model) = model else {
            return Ok(None);
        };
        exprs
            .iter()
            .map(|expr| AstRef::from_z3(expr.context(), model.eval(&expr.to_z3()?)?))
            .collect::<Result<Vec<_>, _>>()
            .map(Some)
    }

    fn eval(&mut self, expr: &AstRef<'c>) -> Result<AstRef<'c>, ClarirsError> {
        self.eval_in_model(expr)
    }

    fn batch_eval(&mut self, exprs: &[AstRef<'c>]) -> Result<Vec<AstRef<'c>>, ClarirsError> {
        if exprs.is_empty() {
            return Ok(Vec::new());
        }
        // Draw every value from one model so the results are mutually
        // consistent (a usable model), unlike eval() called in a loop.
        let model = self.make_model()?;
        exprs
            .iter()
            .map(|expr| {
                let expr = expr.simplify()?.simplify_z3()?;
                if expr.concrete() {
                    return Ok(expr);
                }
                AstRef::from_z3(expr.context(), model.eval(&expr.to_z3()?)?)
            })
            .collect()
    }

    fn is_true(&mut self, expr: &AstRef<'c>) -> Result<bool, ClarirsError> {
        let expr = expr.simplify_z3()?;
        Ok(expr.concrete() && expr.is_true())
    }

    fn is_false(&mut self, expr: &AstRef<'c>) -> Result<bool, ClarirsError> {
        let expr = expr.simplify_z3()?;
        Ok(expr.concrete() && expr.is_false())
    }

    fn has_true(&mut self, expr: &AstRef<'c>) -> Result<bool, ClarirsError> {
        let mut solver = self.clone();
        solver.add(expr)?;
        solver.satisfiable()
    }

    fn has_false(&mut self, expr: &AstRef<'c>) -> Result<bool, ClarirsError> {
        let mut solver = self.clone();
        solver.add(&self.context().not(expr)?)?;
        solver.satisfiable()
    }

    fn min_unsigned(&mut self, expr: &AstRef<'c>) -> Result<AstRef<'c>, ClarirsError> {
        let mut optimize = self.mk_filled_optimize()?;
        optimize.minimize(&expr.to_z3()?)?;
        match optimize.check()? {
            Z3_L_TRUE => {}
            Z3_L_FALSE => return Err(ClarirsError::Unsat),
            _ => return Err(ClarirsError::SolverUnknown(optimize.reason_unknown())),
        }

        let model = optimize.get_model()?;
        AstRef::from_z3(expr.context(), model.eval(&expr.to_z3()?)?)?
            .into_bitvec()
            .ok_or(ClarirsError::TypeError("Expected AstRef".to_string()))
    }

    fn max_unsigned(&mut self, expr: &AstRef<'c>) -> Result<AstRef<'c>, ClarirsError> {
        let mut optimize = self.mk_filled_optimize()?;
        optimize.maximize(&expr.to_z3()?)?;
        match optimize.check()? {
            Z3_L_TRUE => {}
            Z3_L_FALSE => return Err(ClarirsError::Unsat),
            _ => return Err(ClarirsError::SolverUnknown(optimize.reason_unknown())),
        }

        let model = optimize.get_model()?;
        AstRef::from_z3(expr.context(), model.eval(&expr.to_z3()?)?)?
            .into_bitvec()
            .ok_or(ClarirsError::TypeError("Expected AstRef".to_string()))
    }

    fn min_signed(&mut self, expr: &AstRef<'c>) -> Result<AstRef<'c>, ClarirsError> {
        let mut optimize = self.mk_filled_optimize()?;
        // Get the size of the bitvector
        let size = expr.size();

        // For signed minimization, the sign bit should be 1 (for negative numbers)
        // Extract the sign bit
        let sign_bit = self.ctx.extract(expr, size - 1, size - 1)?;
        let one_bit = self.ctx.bvv(BitVec::from((1, 1)))?;

        // Create a target variable equal to the expression
        let target_name = format!("min_signed_target_{size}");
        let target = self.ctx.bvs(&target_name, size)?;
        let equality = self.ctx.eq_(&target, expr)?;
        optimize.assert(&equality.to_z3()?)?;

        // First, maximize the sign bit with a high weight
        // This will prefer negative numbers (sign bit = 1) over positive ones
        let sign_equality = self.ctx.eq_(&sign_bit, &one_bit)?;
        optimize.assert_soft(&sign_equality.to_z3()?, 1000000)?;

        // Then minimize the target value (with lower weight)
        // This will find the smallest value among those with the preferred sign bit
        optimize.minimize(&target.to_z3()?)?;

        match optimize.check()? {
            Z3_L_TRUE => {}
            Z3_L_FALSE => return Err(ClarirsError::Unsat),
            _ => return Err(ClarirsError::SolverUnknown(optimize.reason_unknown())),
        }

        let model = optimize.get_model()?;
        AstRef::from_z3(expr.context(), model.eval(&expr.to_z3()?)?)?
            .into_bitvec()
            .ok_or(ClarirsError::TypeError("Expected AstRef".to_string()))
    }

    fn max_signed(&mut self, expr: &AstRef<'c>) -> Result<AstRef<'c>, ClarirsError> {
        let mut optimize = self.mk_filled_optimize()?;
        // Get the size of the bitvector
        let size = expr.size();

        // For signed maximization, the sign bit should be 0 (for positive numbers)
        // Extract the sign bit
        let sign_bit = self.ctx.extract(expr, size - 1, size - 1)?;
        let zero_bit = self.ctx.bvv(BitVec::from((0, 1)))?;

        // Create a target variable equal to the expression
        let target_name = format!("max_signed_target_{size}");
        let target = self.ctx.bvs(&target_name, size)?;
        let equality = self.ctx.eq_(&target, expr)?;
        optimize.assert(&equality.to_z3()?)?;

        // First, maximize making the sign bit 0 with a high weight
        // This will prefer positive numbers (sign bit = 0) over negative ones
        let sign_equality = self.ctx.eq_(&sign_bit, &zero_bit)?;
        optimize.assert_soft(&sign_equality.to_z3()?, 1000000)?;

        // Then maximize the target value (with lower weight)
        // This will find the largest value among those with the preferred sign bit
        optimize.maximize(&target.to_z3()?)?;

        match optimize.check()? {
            Z3_L_TRUE => {}
            Z3_L_FALSE => return Err(ClarirsError::Unsat),
            _ => return Err(ClarirsError::SolverUnknown(optimize.reason_unknown())),
        }

        let model = optimize.get_model()?;
        AstRef::from_z3(expr.context(), model.eval(&expr.to_z3()?)?)?
            .into_bitvec()
            .ok_or(ClarirsError::TypeError("Expected AstRef".to_string()))
    }

    fn eval_n(&mut self, expr: &AstRef<'c>, n: u32) -> Result<Vec<AstRef<'c>>, ClarirsError> {
        let mut results = Vec::new();

        // Simplify and check if concrete
        let expr = expr.simplify_z3()?;
        if expr.concrete() {
            return Ok(vec![expr]);
        }

        let ctx = self.context();

        // Most expressions are read straight out of the model. `Z3_model_eval`
        // is called with model completion, so bits left unconstrained by the
        // assertions default to zero -- matching claripy, which evaluates the
        // expression the same way.
        //
        // fp.to_ieee_bv is the exception: Z3 keeps it uninterpreted in models
        // even with completion, so an expression containing it can evaluate to
        // a non-constant term. For those we bind the value to a fresh auxiliary
        // bitvector via an asserted equality, which forces the model to assign
        // it a constant. Floats go through the same path (bound by their IEEE
        // bit pattern, since fp equality would be unsat for NaN) and are
        // converted back afterwards. Binding to an auxiliary variable does pull
        // otherwise-free bits into the model with arbitrary values, so it is
        // used only when direct evaluation cannot produce a constant.
        let fp_sort = match expr.ast_type() {
            AstType::Float(fsort) => Some(fsort),
            _ => None,
        };
        let needs_aux = fp_sort.is_some() || contains_fp_to_ieeebv(&expr);

        let aux = if needs_aux {
            let aux_name = format!("__eval_{:x}", expr.hash());
            let (aux, link) = match &fp_sort {
                Some(fsort) => {
                    let aux = ctx.bvs(&aux_name, fsort.size())?;
                    let link = ctx.eq_(&aux, &ctx.fp_to_ieeebv(&expr)?)?;
                    (aux, link)
                }
                None => {
                    let aux = ctx.bvs(&aux_name, expr.size())?;
                    let link = ctx.eq_(&aux, &expr)?;
                    (aux, link)
                }
            };
            Some((aux, link))
        } else {
            None
        };

        // The expression whose model value we read and exclude between
        // iterations: the auxiliary variable when one is used, else `expr`.
        let eval_target = match &aux {
            Some((aux, _)) => aux.clone(),
            None => expr.clone(),
        };
        let z3_eval_target = eval_target.to_z3()?;

        // Create and fill the Z3 solver once, applying this solver's params
        // (timeout in particular) so eval cannot run unbounded.
        let mut z3_solver = self.new_z3_solver()?;

        for assertion in &self.assertions {
            let converted = assertion.to_z3()?;
            z3_solver.assert(&converted)?;
        }
        if let Some((_, link)) = &aux {
            z3_solver.assert(&link.to_z3()?)?;
        }

        for _ in 0..n {
            match z3_solver.check()? {
                Z3_L_TRUE => {}
                Z3_L_FALSE => break,
                _ => return Err(ClarirsError::SolverUnknown(z3_solver.reason_unknown())),
            }

            let model = z3_solver.model()?;
            let eval_result = model.eval(&z3_eval_target)?;

            let solution = AstRef::from_z3(ctx, eval_result)?;

            // Add constraint to exclude this solution
            let neq_constraint = ctx.neq(&eval_target, &solution)?;
            let z3_neq = neq_constraint.to_z3()?;
            z3_solver.assert(&z3_neq)?;

            // Convert the IEEE bit pattern back to a float constant. The
            // bitvector width (32 or 64) selects the format.
            let solution = match (&fp_sort, solution.op()) {
                (Some(_), AstOp::BVV(bv)) => ctx.fpv(Float::try_from_ieee_bits(bv)?)?,
                _ => solution,
            };
            results.push(solution);
        }

        Ok(results)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use clarirs_core::solver_mixins::ModelCacheMixin;

    #[test]
    fn solver_pins_conversion_cache_for_its_lifetime() -> Result<(), ClarirsError> {
        use clarirs_core::cache::Cache;

        let ctx = Context::new();
        let mut solver = Z3Solver::new(&ctx);
        let x = ctx.bvs("pin_x", 64)?;
        let constraint = ctx.eq_(&x, &ctx.bvv(BitVec::from((42, 64)))?)?;
        solver.add(&constraint)?;
        assert!(solver.satisfiable()?);

        crate::Z3_AST_CACHE.with(|cache| {
            assert!(cache.get(&x.hash()).is_some());
            assert!(cache.get(&constraint.hash()).is_some());
        });

        drop(solver);
        crate::Z3_AST_CACHE.with(|cache| {
            assert!(cache.get(&x.hash()).is_none());
            assert!(cache.get(&constraint.hash()).is_none());
        });
        Ok(())
    }

    #[test]
    fn test_solver_simple() -> Result<(), ClarirsError> {
        let ctx = Context::new();

        let mut solver = Z3Solver::new(&ctx);

        let x = ctx.bools("x")?;
        let y = ctx.bools("y")?;

        solver.add(&ctx.neq(&x, &y)?)?;

        let x_val = solver.eval(&x).unwrap();
        let y_val = solver.eval(&y).unwrap();

        assert_ne!(x_val, y_val);

        Ok(())
    }

    #[test]
    fn test_batch_eval_consistent_model() -> Result<(), ClarirsError> {
        let ctx = Context::new();
        let mut solver = Z3Solver::new(&ctx);

        let x = ctx.bvs("x", 8)?;
        let y = ctx.bvs("y", 8)?;
        // y == x + 1, so any model must keep that relationship.
        solver.add(&ctx.eq_(&y, &ctx.add(&x, &ctx.bvv(BitVec::from((1, 8)))?)?)?)?;

        let values = solver.batch_eval(&[x.clone(), y.clone()])?;
        assert_eq!(values.len(), 2);
        let (x_val, y_val) = (values[0].clone(), values[1].clone());

        // The two values come from one model, so y_val == x_val + 1.
        let expected_y = ctx
            .add(&x_val, &ctx.bvv(BitVec::from((1, 8)))?)?
            .simplify()?;
        assert_eq!(y_val, expected_y);
        Ok(())
    }

    /// The model cache must never change an answer: a cached and a cacheless
    /// Z3 solver agree on satisfiability and evaluation.
    #[test]
    fn test_model_cache_matches_cacheless() -> Result<(), ClarirsError> {
        let ctx = Context::new();
        let mut cached = ModelCacheMixin::new(Z3Solver::new(&ctx));
        let mut cacheless = Z3Solver::new(&ctx);

        let x = ctx.bvs("x", 32)?;
        // 10 <= x <= 20
        let c1 = ctx.uge(&x, &ctx.bvv(BitVec::from((10, 32)))?)?;
        let c2 = ctx.ule(&x, &ctx.bvv(BitVec::from((20, 32)))?)?;
        cached.add(&c1)?;
        cached.add(&c2)?;
        cacheless.add(&c1)?;
        cacheless.add(&c2)?;

        // Satisfiability agrees, and a second (cached) check still agrees.
        assert_eq!(cached.satisfiable()?, cacheless.satisfiable()?);
        assert!(cached.satisfiable()?);

        // Any value the cache yields for x must lie within the constraints.
        let v = cached.eval(&x)?;
        let in_range = cached.is_true(&ctx.and2(
            &ctx.uge(&v, &ctx.bvv(BitVec::from((10, 32)))?)?,
            &ctx.ule(&v, &ctx.bvv(BitVec::from((20, 32)))?)?,
        )?)?;
        assert!(
            in_range,
            "cached eval produced an out-of-range value: {v:?}"
        );

        // A satisfiable extra constraint reachable by a cached model.
        let extra_sat = ctx.eq_(&x, v.clone().into_bitvec().unwrap())?;
        assert!(cached.satisfiable_with_extra(&[extra_sat])?);

        // An unsatisfiable extra constraint must fall through and report unsat.
        let extra_unsat = ctx.eq_(&x, &ctx.bvv(BitVec::from((100, 32)))?)?;
        assert_eq!(
            cached.satisfiable_with_extra(std::slice::from_ref(&extra_unsat))?,
            cacheless.satisfiable_with_extra(&[extra_unsat])?,
        );
        assert!(
            !cached.satisfiable_with_extra(&[ctx.eq_(&x, &ctx.bvv(BitVec::from((100, 32)))?)?])?
        );

        Ok(())
    }

    #[test]
    fn test_model_cache_unsat() -> Result<(), ClarirsError> {
        let ctx = Context::new();
        let mut cached = ModelCacheMixin::new(Z3Solver::new(&ctx));

        let x = ctx.bvs("x", 8)?;
        cached.add(&ctx.eq_(&x, &ctx.bvv(BitVec::from((1, 8)))?)?)?;
        cached.add(&ctx.eq_(&x, &ctx.bvv(BitVec::from((2, 8)))?)?)?;

        // Unsat, and the cached flag keeps it unsat on repeated checks.
        assert!(!cached.satisfiable()?);
        assert!(!cached.satisfiable()?);
        Ok(())
    }

    #[test]
    fn test_fp_neq_is_ieee() -> Result<(), ClarirsError> {
        let ctx = Context::new();

        // x != x is satisfiable for floats: NaN is IEEE-unequal to itself.
        // An object-level `distinct` lowering would make this unsatisfiable.
        let mut solver = Z3Solver::new(&ctx);
        let x = ctx.fps("x", FSort::f64())?;
        solver.add(&ctx.neq(&x, &x)?)?;
        assert!(solver.satisfiable()?);

        // ...and NaN is the only witness.
        solver.add(&ctx.not(&ctx.fp_is_nan(&x)?)?)?;
        assert!(!solver.satisfiable()?);

        Ok(())
    }

    #[test]
    fn test_solver_unsat() -> Result<(), ClarirsError> {
        let ctx = Context::new();

        let mut solver = Z3Solver::new(&ctx);

        let x = ctx.bools("x")?;
        let y = ctx.bools("y")?;

        solver.add(&ctx.eq_(&x, &y)?)?;
        solver.add(&ctx.neq(&x, &y)?)?;

        assert!(!solver.satisfiable()?);

        Ok(())
    }

    #[test]
    fn test_solver_bool() -> Result<(), ClarirsError> {
        let ctx = Context::new();

        let mut solver = Z3Solver::new(&ctx);

        let x = ctx.bools("x")?;
        let y = ctx.bools("y")?;

        solver.add(&ctx.not(&ctx.eq_(&x, &y)?)?).unwrap();
        solver.add(&ctx.eq_(&x, &ctx.true_()?)?).unwrap();

        let x_val = solver.eval(&x).unwrap();
        let y_val = solver.eval(&y).unwrap();

        assert_ne!(x_val, y_val);
        assert!(x_val.is_true());
        assert!(y_val.is_false());

        Ok(())
    }

    mod test_eval_bool {
        use super::*;

        #[test]
        fn test_eval_bool_symbol() -> Result<(), ClarirsError> {
            let ctx = Context::new();
            let mut solver = Z3Solver::new(&ctx);

            let x = ctx.bools("x")?;
            solver.add(&ctx.eq_(&x, &ctx.true_()?)?)?;

            let result = solver.eval(&x)?;
            assert!(result.is_true());

            Ok(())
        }

        #[test]
        fn test_eval_bool_value() -> Result<(), ClarirsError> {
            let ctx = Context::new();
            let mut solver = Z3Solver::new(&ctx);

            let t = ctx.true_()?;
            let f = ctx.false_()?;

            assert!(solver.satisfiable()?);
            let t_result = solver.eval(&t)?;
            let f_result = solver.eval(&f)?;

            assert!(t_result.is_true());
            assert!(f_result.is_false());

            Ok(())
        }

        #[test]
        fn test_eval_bool_not() -> Result<(), ClarirsError> {
            let ctx = Context::new();
            let mut solver = Z3Solver::new(&ctx);

            // Test with concrete value
            let t = ctx.true_()?;
            let not_t = ctx.not(&t)?;
            let result = solver.eval(&not_t)?;
            assert!(result.is_false());

            // Test with symbolic value
            let x = ctx.bools("x")?;
            solver.add(&ctx.eq_(&x, &ctx.true_()?)?)?;
            let not_x = ctx.not(&x)?;
            let result = solver.eval(&not_x)?;
            assert!(result.is_false());

            Ok(())
        }

        #[test]
        fn test_eval_bool_and() -> Result<(), ClarirsError> {
            let ctx = Context::new();
            let mut solver = Z3Solver::new(&ctx);

            // Test with concrete values - truth table
            let t = ctx.true_()?;
            let f = ctx.false_()?;

            let tt = solver.eval(&ctx.and2(&t, &t)?)?;
            let tf = solver.eval(&ctx.and2(&t, &f)?)?;
            let ft = solver.eval(&ctx.and2(&f, &t)?)?;
            let ff = solver.eval(&ctx.and2(&f, &f)?)?;

            assert!(tt.is_true());
            assert!(tf.is_false());
            assert!(ft.is_false());
            assert!(ff.is_false());

            // Test with symbolic values
            let x = ctx.bools("x")?;
            let y = ctx.bools("y")?;
            solver.add(&ctx.eq_(&x, &ctx.true_()?)?)?;
            solver.add(&ctx.eq_(&y, &ctx.false_()?)?)?;

            let result = solver.eval(&ctx.and2(&x, &y)?)?;
            assert!(result.is_false());

            Ok(())
        }

        #[test]
        fn test_eval_bool_or() -> Result<(), ClarirsError> {
            let ctx = Context::new();
            let mut solver = Z3Solver::new(&ctx);

            // Test with concrete values - truth table
            let t = ctx.true_()?;
            let f = ctx.false_()?;

            let tt = solver.eval(&ctx.or2(&t, &t)?)?;
            let tf = solver.eval(&ctx.or2(&t, &f)?)?;
            let ft = solver.eval(&ctx.or2(&f, &t)?)?;
            let ff = solver.eval(&ctx.or2(&f, &f)?)?;

            assert!(tt.is_true());
            assert!(tf.is_true());
            assert!(ft.is_true());
            assert!(ff.is_false());

            // Test with symbolic values
            let x = ctx.bools("x")?;
            let y = ctx.bools("y")?;
            solver.add(&ctx.eq_(&x, &ctx.false_()?)?)?;
            solver.add(&ctx.eq_(&y, &ctx.true_()?)?)?;

            let result = solver.eval(&ctx.or2(&x, &y)?)?;
            assert!(result.is_true());

            Ok(())
        }

        #[test]
        fn test_eval_bool_xor() -> Result<(), ClarirsError> {
            let ctx = Context::new();
            let mut solver = Z3Solver::new(&ctx);

            // Test with concrete values - truth table
            let t = ctx.true_()?;
            let f = ctx.false_()?;

            let tt = solver.eval(&ctx.xor2(&t, &t)?)?;
            let tf = solver.eval(&ctx.xor2(&t, &f)?)?;
            let ft = solver.eval(&ctx.xor2(&f, &t)?)?;
            let ff = solver.eval(&ctx.xor2(&f, &f)?)?;

            assert!(tt.is_false());
            assert!(tf.is_true());
            assert!(ft.is_true());
            assert!(ff.is_false());

            // Test with symbolic values
            let x = ctx.bools("x")?;
            let y = ctx.bools("y")?;
            solver.add(&ctx.eq_(&x, &ctx.true_()?)?)?;
            solver.add(&ctx.eq_(&y, &ctx.true_()?)?)?;

            let result = solver.eval(&ctx.xor2(&x, &y)?)?;
            assert!(result.is_false());

            Ok(())
        }

        #[test]
        fn test_eval_bool_eq() -> Result<(), ClarirsError> {
            let ctx = Context::new();
            let mut solver = Z3Solver::new(&ctx);

            // Test with concrete values
            let t = ctx.true_()?;
            let f = ctx.false_()?;

            let tt = solver.eval(&ctx.eq_(&t, &t)?)?;
            let tf = solver.eval(&ctx.eq_(&t, &f)?)?;

            assert!(tt.is_true());
            assert!(tf.is_false());

            // Test with symbolic values
            let x = ctx.bools("x")?;
            let y = ctx.bools("y")?;
            solver.add(&ctx.eq_(&x, &ctx.true_()?)?)?;
            solver.add(&ctx.eq_(&y, &ctx.true_()?)?)?;

            let result = solver.eval(&ctx.eq_(&x, &y)?)?;
            assert!(result.is_true());

            Ok(())
        }

        #[test]
        fn test_eval_bool_neq() -> Result<(), ClarirsError> {
            let ctx = Context::new();
            let mut solver = Z3Solver::new(&ctx);

            // Test with concrete values
            let t = ctx.true_()?;
            let f = ctx.false_()?;

            let tt = solver.eval(&ctx.neq(&t, &t)?)?;
            let tf = solver.eval(&ctx.neq(&t, &f)?)?;

            assert!(tt.is_false());
            assert!(tf.is_true());

            // Test with symbolic values
            let x = ctx.bools("x")?;
            let y = ctx.bools("y")?;
            solver.add(&ctx.eq_(&x, &ctx.true_()?)?)?;
            solver.add(&ctx.eq_(&y, &ctx.false_()?)?)?;

            let result = solver.eval(&ctx.neq(&x, &y)?)?;
            assert!(result.is_true());

            Ok(())
        }

        #[test]
        fn test_eval_bool_if() -> Result<(), ClarirsError> {
            let ctx = Context::new();
            let mut solver = Z3Solver::new(&ctx);

            // Test with concrete values
            let t = ctx.true_()?;
            let f = ctx.false_()?;

            let tt = solver.eval(&ctx.ite(&t, &t, &f)?)?;
            let tf = solver.eval(&ctx.ite(&f, &t, &f)?)?;

            assert!(tt.is_true());
            assert!(tf.is_false());

            // Test with symbolic values
            let c = ctx.bools("c")?;
            let x = ctx.bools("x")?;
            let y = ctx.bools("y")?;

            solver.add(&ctx.eq_(&c, &ctx.true_()?)?)?;
            solver.add(&ctx.eq_(&x, &ctx.true_()?)?)?;
            solver.add(&ctx.eq_(&y, &ctx.false_()?)?)?;

            let result = solver.eval(&ctx.ite(c, x, y)?)?;
            assert!(result.is_true());

            Ok(())
        }
    }

    mod test_bitvec_optimize {
        use super::*;

        #[test]
        fn test_min_unsigned_concrete() -> Result<(), ClarirsError> {
            let ctx = Context::new();
            let mut solver = Z3Solver::new(&ctx);

            // Using a concrete value should return the same value
            let bv = ctx.bvv(BitVec::from((42, 64)))?;
            let result = solver.min_unsigned(&bv)?;

            assert_eq!(result, bv);

            Ok(())
        }

        #[test]
        fn test_max_unsigned_concrete() -> Result<(), ClarirsError> {
            let ctx = Context::new();
            let mut solver = Z3Solver::new(&ctx);

            // Using a concrete value should return the same value
            let bv = ctx.bvv(BitVec::from((42, 64)))?;
            let result = solver.max_unsigned(&bv)?;

            assert_eq!(result, bv);

            Ok(())
        }

        #[test]
        fn test_min_unsigned_constrained() -> Result<(), ClarirsError> {
            let ctx = Context::new();
            let mut solver = Z3Solver::new(&ctx);

            // Create a variable with constraints
            let x = ctx.bvs("x", 64)?;

            // Add constraints: 10 <= x <= 20
            let lower_bound = ctx.bvv(BitVec::from((10, 64)))?;
            let upper_bound = ctx.bvv(BitVec::from((20, 64)))?;

            solver.add(&ctx.uge(&x, &lower_bound)?)?;
            solver.add(&ctx.ule(&x, &upper_bound)?)?;

            // Min value should be 10
            let result = solver.min_unsigned(&x)?;
            assert_eq!(result, lower_bound);

            Ok(())
        }

        #[test]
        fn test_max_unsigned_constrained() -> Result<(), ClarirsError> {
            let ctx = Context::new();
            let mut solver = Z3Solver::new(&ctx);

            // Create a variable with constraints
            let x = ctx.bvs("x", 64)?;

            // Add constraints: 10 <= x <= 20
            let lower_bound = ctx.bvv(BitVec::from((10, 64)))?;
            let upper_bound = ctx.bvv(BitVec::from((20, 64)))?;

            solver.add(&ctx.uge(&x, &lower_bound)?)?;
            solver.add(&ctx.ule(&x, &upper_bound)?)?;

            // Max value should be 20
            let result = solver.max_unsigned(&x)?;
            assert_eq!(result, upper_bound);

            Ok(())
        }

        #[test]
        fn test_min_unsigned_complex() -> Result<(), ClarirsError> {
            let ctx = Context::new();
            let mut solver = Z3Solver::new(&ctx);

            // Create variables
            let x = ctx.bvs("x", 8)?;
            let y = ctx.bvs("y", 8)?;

            // Add constraints:
            // x must be greater than 5
            // y must be less than 10
            // x + y must be even (lowest bit is 0)
            let five = ctx.bvv(BitVec::from((5, 8)))?;
            let ten = ctx.bvv(BitVec::from((10, 8)))?;

            solver.add(&ctx.ugt(&x, &five)?)?;
            solver.add(&ctx.ult(&y, &ten)?)?;

            // x + y must be even
            let sum = ctx.add(&x, &y)?;
            let zero = ctx.bvv(BitVec::from((0, 1)))?;
            solver.add(&ctx.eq_(&ctx.extract(&sum, 0, 0)?, &zero)?)?;

            // Find min value of x
            let result = solver.min_unsigned(&x)?;

            // Min value should be 6
            // Because x > 5, and if x = 6 and y = 0, then 6+0=6 which is even
            let six = ctx.bvv(BitVec::from((6, 8)))?;
            assert_eq!(result, six);

            Ok(())
        }

        #[test]
        fn test_max_unsigned_complex() -> Result<(), ClarirsError> {
            let ctx = Context::new();
            let mut solver = Z3Solver::new(&ctx);

            // Create variables
            let x = ctx.bvs("x", 8)?;
            let y = ctx.bvs("y", 8)?;

            // Add constraints:
            // x must be less than 100
            // y must be greater than 20
            // x must be greater than y
            let hundred = ctx.bvv(BitVec::from((100, 8)))?;
            let twenty = ctx.bvv(BitVec::from((20, 8)))?;

            solver.add(&ctx.ult(&x, &hundred)?)?;
            solver.add(&ctx.ugt(&y, &twenty)?)?;
            solver.add(&ctx.ugt(&x, &y)?)?;

            // Find max value of x
            let result = solver.max_unsigned(&x)?;

            // Max value should be 99 (since x < 100)
            let ninety_nine = ctx.bvv(BitVec::from((99, 8)))?;
            assert_eq!(result, ninety_nine);

            Ok(())
        }

        // Tests for signed bitvector operations

        #[test]
        fn test_min_signed_concrete() -> Result<(), ClarirsError> {
            let ctx = Context::new();
            let mut solver = Z3Solver::new(&ctx);

            // Using a concrete value should return the same value
            let bv = ctx.bvv(BitVec::from((42, 64)))?;
            let result = solver.min_signed(&bv)?;

            assert_eq!(result, bv);

            Ok(())
        }

        #[test]
        fn test_max_signed_concrete() -> Result<(), ClarirsError> {
            let ctx = Context::new();
            let mut solver = Z3Solver::new(&ctx);

            // Using a concrete value should return the same value
            let bv = ctx.bvv(BitVec::from((42, 64)))?;
            let result = solver.max_signed(&bv)?;

            assert_eq!(result, bv);

            Ok(())
        }

        #[test]
        fn test_min_signed_constrained() -> Result<(), ClarirsError> {
            let ctx = Context::new();
            let mut solver = Z3Solver::new(&ctx);

            // Create a variable with constraints
            let x = ctx.bvs("x", 64)?;

            // Add constraints: -10 <= x <= 20 (in signed interpretation)
            // -10 in 64-bit two's complement is 0xfffffffffffffff6
            let lower_bound = ctx.bvv(BitVec::from((0xfffffffffffffff6, 64)))?;
            let upper_bound = ctx.bvv(BitVec::from((20, 64)))?;

            solver.add(&ctx.sge(&x, &lower_bound)?)?;
            solver.add(&ctx.sle(&x, &upper_bound)?)?;

            // Min value should be -10
            let result = solver.min_signed(&x)?;
            assert_eq!(result, lower_bound);

            Ok(())
        }

        #[test]
        fn test_max_signed_constrained() -> Result<(), ClarirsError> {
            let ctx = Context::new();
            let mut solver = Z3Solver::new(&ctx);

            // Create a variable with constraints
            let x = ctx.bvs("x", 64)?;

            // Add constraints: -10 <= x <= 20 (in signed interpretation)
            // -10 in 64-bit two's complement is 0xfffffffffffffff6
            let lower_bound = ctx.bvv(BitVec::from((0xfffffffffffffff6, 64)))?;
            let upper_bound = ctx.bvv(BitVec::from((20, 64)))?;

            solver.add(&ctx.sge(&x, &lower_bound)?)?;
            solver.add(&ctx.sle(&x, &upper_bound)?)?;

            // Max value should be 20
            let result = solver.max_signed(&x)?;
            assert_eq!(result, upper_bound);

            Ok(())
        }

        #[test]
        fn test_min_signed_complex() -> Result<(), ClarirsError> {
            let ctx = Context::new();
            let mut solver = Z3Solver::new(&ctx);

            // Create variables
            let x = ctx.bvs("x", 8)?;
            let y = ctx.bvs("y", 8)?;

            // Add constraints:
            // x must be greater than -5 (signed)
            // y must be less than 10 (signed)
            // x + y must be even (lowest bit is 0)

            // -5 in 8-bit two's complement is 0xfb (251 in unsigned)
            let neg_five = ctx.bvv(BitVec::from((0xfb, 8)))?;
            let ten = ctx.bvv(BitVec::from((10, 8)))?;

            solver.add(&ctx.sgt(&x, &neg_five)?)?;
            solver.add(&ctx.slt(&y, &ten)?)?;

            // x + y must be even
            let sum = ctx.add(&x, &y)?;
            let zero = ctx.bvv(BitVec::from((0, 1)))?;
            solver.add(&ctx.eq_(&ctx.extract(&sum, 0, 0)?, &zero)?)?;

            // Find min value of x
            let result = solver.min_signed(&x)?;

            // Min value should be -4 (0xfc in 8-bit two's complement)
            // Because x > -5, and if x = -4 and y = 0, then -4+0=-4 which is even
            let neg_four = ctx.bvv(BitVec::from((0xfc, 8)))?;
            assert_eq!(result, neg_four);

            Ok(())
        }

        #[test]
        fn test_max_signed_complex() -> Result<(), ClarirsError> {
            let ctx = Context::new();
            let mut solver = Z3Solver::new(&ctx);

            // Create variables
            let x = ctx.bvs("x", 8)?;
            let y = ctx.bvs("y", 8)?;

            // Add constraints:
            // x must be less than 100 (signed)
            // y must be greater than -20 (signed)
            // x must be greater than y (signed)
            let hundred = ctx.bvv(BitVec::from((100, 8)))?;

            // -20 in 8-bit two's complement is 0xec (236 in unsigned)
            let neg_twenty = ctx.bvv(BitVec::from((0xec, 8)))?;

            solver.add(&ctx.slt(&x, &hundred)?)?;
            solver.add(&ctx.sgt(&y, &neg_twenty)?)?;
            solver.add(&ctx.sgt(&x, &y)?)?;

            // Find max value of x
            let result = solver.max_signed(&x)?;

            // Max value should be 99 (since x < 100)
            let ninety_nine = ctx.bvv(BitVec::from((99, 8)))?;
            assert_eq!(result, ninety_nine);

            Ok(())
        }

        #[test]
        fn test_min_signed_negative_range() -> Result<(), ClarirsError> {
            let ctx = Context::new();
            let mut solver = Z3Solver::new(&ctx);

            // Create a variable with constraints
            let x = ctx.bvs("x", 8)?;

            // Add constraints: -100 <= x <= -10 (in signed interpretation)
            // -100 in 8-bit two's complement is 0x9c (156 in unsigned)
            // -10 in 8-bit two's complement is 0xf6 (246 in unsigned)
            let lower_bound = ctx.bvv(BitVec::from((0x9c, 8)))?;
            let upper_bound = ctx.bvv(BitVec::from((0xf6, 8)))?;

            solver.add(&ctx.sge(&x, &lower_bound)?)?;
            solver.add(&ctx.sle(&x, &upper_bound)?)?;

            // Min value should be -100
            let result = solver.min_signed(&x)?;
            assert_eq!(result, lower_bound);

            Ok(())
        }

        #[test]
        fn test_max_signed_negative_range() -> Result<(), ClarirsError> {
            let ctx = Context::new();
            let mut solver = Z3Solver::new(&ctx);

            // Create a variable with constraints
            let x = ctx.bvs("x", 8)?;

            // Add constraints: -100 <= x <= -10 (in signed interpretation)
            // -100 in 8-bit two's complement is 0x9c (156 in unsigned)
            // -10 in 8-bit two's complement is 0xf6 (246 in unsigned)
            let lower_bound = ctx.bvv(BitVec::from((0x9c, 8)))?;
            let upper_bound = ctx.bvv(BitVec::from((0xf6, 8)))?;

            solver.add(&ctx.sge(&x, &lower_bound)?)?;
            solver.add(&ctx.sle(&x, &upper_bound)?)?;

            // Max value should be -10
            let result = solver.max_signed(&x)?;
            assert_eq!(result, upper_bound);

            Ok(())
        }
    }

    #[test]
    fn test_unsat_core_simple() -> Result<(), ClarirsError> {
        let ctx = Context::new();
        let mut solver = Z3Solver::new_with_options(&ctx, None, true);

        let x = ctx.bools("x")?;
        let y = ctx.bools("y")?;

        // Add contradictory constraints
        solver.add(&ctx.eq_(&x, &ctx.true_()?)?)?; // constraint 0
        solver.add(&ctx.eq_(&y, &ctx.true_()?)?)?; // constraint 1
        solver.add(&ctx.eq_(&x, &y)?)?; // constraint 2
        solver.add(&ctx.neq(&x, &y)?)?; // constraint 3 - contradicts with 0, 1, and 2

        // Should be unsat
        assert!(!solver.satisfiable()?);

        // Get unsat core
        let core = solver.unsat_core()?;

        // The core should contain the contradictory constraints
        // At minimum, it should contain constraint 2 and 3 (or 0, 1, and 3)
        assert!(!core.is_empty());
        assert!(core.len() <= 4); // Should be a subset of all constraints

        Ok(())
    }

    #[test]
    fn test_unsat_core_minimal() -> Result<(), ClarirsError> {
        let ctx = Context::new();
        let mut solver = Z3Solver::new_with_options(&ctx, None, true);

        let x = ctx.bvs("x", 8)?;

        // Add constraints
        let c0 = ctx.ugt(&x, &ctx.bvv(BitVec::from((10, 8)))?)?; // x > 10
        let c1 = ctx.ult(&x, &ctx.bvv(BitVec::from((5, 8)))?)?; // x < 5 - contradicts c0
        let c2 = ctx.ugt(&x, &ctx.bvv(BitVec::from((0, 8)))?)?; // x > 0 - doesn't contribute to unsat

        solver.add(&c0)?; // constraint 0
        solver.add(&c1)?; // constraint 1
        solver.add(&c2)?; // constraint 2

        // Should be unsat
        assert!(!solver.satisfiable()?);

        // Get unsat core
        let core = solver.unsat_core()?;

        // The core should contain constraints 0 and 1, but not necessarily 2
        assert!(!core.is_empty());
        assert!(core.contains(&0));
        assert!(core.contains(&1));

        Ok(())
    }

    #[test]
    fn test_unsat_core_not_enabled() -> Result<(), ClarirsError> {
        let ctx = Context::new();
        let mut solver = Z3Solver::new(&ctx); // unsat_core not enabled

        let x = ctx.bools("x")?;

        solver.add(&x)?;
        solver.add(&ctx.not(&x)?)?;

        // Should be unsat
        assert!(!solver.satisfiable()?);

        // Getting unsat core should fail because it's not enabled
        assert!(solver.unsat_core().is_err());

        Ok(())
    }

    #[test]
    fn test_unsat_core_on_sat() -> Result<(), ClarirsError> {
        let ctx = Context::new();
        let mut solver = Z3Solver::new_with_options(&ctx, None, true);

        let x = ctx.bools("x")?;
        solver.add(&x)?;

        // Should be sat
        assert!(solver.satisfiable()?);

        // Getting unsat core on a SAT result should fail
        assert!(solver.unsat_core().is_err());

        Ok(())
    }
}
