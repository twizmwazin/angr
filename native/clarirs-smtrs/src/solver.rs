//! The clarirs [`Solver`] implementation backed by smtrs.
//!
//! Mirrors the structure of the old `Z3Solver`: the solver object itself
//! holds only the assertion list and its options, while the persistent
//! incremental smtrs engine lives in a per-thread cache keyed by `cache_id`
//! and is extended monotonically as assertions are appended. Anything that
//! changes the assertion set other than by appending invalidates the cached
//! engine, forcing a rebuild on next use.
//!
//! Where the Z3 backend emulated angr's query shapes over Z3's API (binary
//! search for extrema via `Optimize`, hand-rolled blocking clauses for value
//! enumeration), smtrs exposes them natively: `check_sat` under assumptions,
//! `minimize`/`maximize` by MSB-first bit fixing, and `eval_n` behind a
//! retired activation literal.

use crate::convert::{bvconst_to_bitvec, needs_aux, to_term, value_to_ast};
use crate::{PoolState, STATE};
use clarirs_core::prelude::*;
use smtrs_core::{BvConst, Op, Sort, SymbolId, TermId, Value};
use smtrs_solver::Answer;
use std::cell::RefCell;
use std::collections::HashMap;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Condvar, Mutex};
use std::time::Duration;

/// A persistent smtrs engine, incrementally extended as constraints are added.
struct CachedSolver {
    solver: smtrs_solver::Solver,
    /// Number of `SmtrsSolver::assertions` already asserted into `solver`.
    asserted: usize,
    /// Activation symbol per asserted constraint when unsat-core tracking is
    /// on (parallel to the assertion list); used to map core members back to
    /// constraint indices.
    tracked: Vec<SymbolId>,
    /// The converted terms asserted into `solver`, in order. A clone forking
    /// this engine verifies that these are exactly its own converted prefix —
    /// the precise condition under which the engine's content is a valid
    /// starting point for it (survives the parent clearing and re-asserting
    /// something else under the same cache id).
    asserted_terms: Vec<TermId>,
    timeout: Option<u32>,
    unsat_core: bool,
    /// Stats already harvested into [`GLOBAL_STATS`] from this engine, so each
    /// harvest adds only the delta since the previous one.
    reported: ReportedStats,
}

/// The portion of an engine's [`smtrs_solver::SolverStats`] already added to
/// the process-global accumulator.
#[derive(Default, Clone, Copy)]
struct ReportedStats {
    checks: u64,
    rebuilds: u64,
    lower_fp: f64,
    lower_str: f64,
    rewrite_preprocess: f64,
    blast: f64,
    sat: f64,
    model: f64,
    prop_abs: f64,
}

/// Process-global solver statistics, aggregated across every engine on every
/// thread. Read through [`global_stats_json`]; costs one mutex lock per
/// solver operation, which is noise next to the operation itself.
#[derive(Default)]
struct GlobalStats {
    /// Engine-side numbers, deltas harvested after each backend operation.
    checks: u64,
    rebuilds: u64,
    lower_fp: f64,
    lower_str: f64,
    rewrite_preprocess: f64,
    blast: f64,
    sat: f64,
    model: f64,
    prop_abs: f64,
    /// Backend-side numbers.
    solver_clones: u64,
    engine_forks: u64,
    cache_invalidations: u64,
    watchdogs_armed: u64,
    backend_checks: u64,
}

static GLOBAL_STATS: Mutex<GlobalStats> = Mutex::new(GlobalStats {
    checks: 0,
    rebuilds: 0,
    lower_fp: 0.0,
    lower_str: 0.0,
    rewrite_preprocess: 0.0,
    blast: 0.0,
    sat: 0.0,
    model: 0.0,
    prop_abs: 0.0,
    solver_clones: 0,
    engine_forks: 0,
    cache_invalidations: 0,
    watchdogs_armed: 0,
    backend_checks: 0,
});

/// Add this engine's stats growth since the last harvest to the global
/// accumulator.
fn harvest(cached: &mut CachedSolver) {
    let s = &cached.solver.stats;
    let p = &s.phases;
    let r = &mut cached.reported;
    let mut g = GLOBAL_STATS.lock().expect("stats lock");
    g.checks += s.checks - r.checks;
    g.rebuilds += s.rebuilds - r.rebuilds;
    g.lower_fp += p.lower_fp - r.lower_fp;
    g.lower_str += p.lower_str - r.lower_str;
    g.rewrite_preprocess += p.rewrite_preprocess - r.rewrite_preprocess;
    g.blast += p.blast - r.blast;
    g.sat += p.sat - r.sat;
    g.model += p.model - r.model;
    g.prop_abs += p.prop_abs - r.prop_abs;
    *r = ReportedStats {
        checks: s.checks,
        rebuilds: s.rebuilds,
        lower_fp: p.lower_fp,
        lower_str: p.lower_str,
        rewrite_preprocess: p.rewrite_preprocess,
        blast: p.blast,
        sat: p.sat,
        model: p.model,
        prop_abs: p.prop_abs,
    };
}

/// The process-global solver statistics as a JSON object.
pub fn global_stats_json() -> String {
    let g = GLOBAL_STATS.lock().expect("stats lock");
    format!(
        concat!(
            "{{\"checks\":{},\"rebuilds\":{},\"lower_fp\":{:.3},\"lower_str\":{:.3},",
            "\"rewrite_preprocess\":{:.3},\"blast\":{:.3},\"sat\":{:.3},\"model\":{:.3},",
            "\"prop_abs\":{:.3},\"solver_clones\":{},\"engine_forks\":{},",
            "\"cache_invalidations\":{},",
            "\"watchdogs_armed\":{},\"backend_checks\":{}}}"
        ),
        g.checks,
        g.rebuilds,
        g.lower_fp,
        g.lower_str,
        g.rewrite_preprocess,
        g.blast,
        g.sat,
        g.model,
        g.prop_abs,
        g.solver_clones,
        g.engine_forks,
        g.cache_invalidations,
        g.watchdogs_armed,
        g.backend_checks,
    )
}

/// Zero the process-global solver statistics.
pub fn reset_global_stats() {
    let mut g = GLOBAL_STATS.lock().expect("stats lock");
    *g = GlobalStats::default();
    // Engines keep their cumulative internal stats; the per-engine `reported`
    // marks are NOT reset, so the next harvests keep adding only fresh deltas.
}

thread_local! {
    static SOLVER_CACHE: RefCell<HashMap<u64, CachedSolver>> = RefCell::new(HashMap::new());
}

static NEXT_SOLVER_ID: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(1);

fn next_solver_id() -> u64 {
    NEXT_SOLVER_ID.fetch_add(1, Ordering::Relaxed)
}

/// Arms a cooperative-termination flag after `timeout_ms`, unless dropped
/// first. smtrs has no wall-clock timeout of its own — it exposes a terminate
/// flag that a running check polls — so the deadline lives on a watchdog
/// thread. The flag armed here is installed fresh for each check, so a stale
/// watchdog firing late cannot interrupt a later check.
struct Watchdog {
    cancel: Arc<(Mutex<bool>, Condvar)>,
    handle: Option<std::thread::JoinHandle<()>>,
}

impl Watchdog {
    fn arm(timeout_ms: u32, flag: Arc<AtomicBool>) -> Watchdog {
        let cancel = Arc::new((Mutex::new(false), Condvar::new()));
        let cancel2 = Arc::clone(&cancel);
        let handle = std::thread::spawn(move || {
            let (lock, cv) = &*cancel2;
            let guard = lock.lock().expect("watchdog lock");
            let (guard, _) = cv
                .wait_timeout_while(guard, Duration::from_millis(u64::from(timeout_ms)), |c| !*c)
                .expect("watchdog wait");
            if !*guard {
                flag.store(true, Ordering::SeqCst);
            }
        });
        Watchdog {
            cancel,
            handle: Some(handle),
        }
    }
}

impl Drop for Watchdog {
    fn drop(&mut self) {
        let (lock, cv) = &*self.cancel;
        *lock.lock().expect("watchdog lock") = true;
        cv.notify_all();
        if let Some(h) = self.handle.take() {
            let _ = h.join();
        }
    }
}

#[derive(Debug)]
pub struct SmtrsSolver<'c> {
    ctx: &'c Context<'c>,
    assertions: Vec<AstRef<'c>>,
    timeout: Option<u32>,
    unsat_core: bool,
    /// Identifies this solver's persistent engine in [`SOLVER_CACHE`].
    cache_id: u64,
    /// The cache id of the solver this one was cloned from, consumed by the
    /// first engine build to fork the parent's engine instead of rebuilding.
    /// `Cell` because the build path runs behind `&self`.
    fork_source: std::cell::Cell<Option<u64>>,
}

impl<'c> Clone for SmtrsSolver<'c> {
    fn clone(&self) -> Self {
        GLOBAL_STATS.lock().expect("stats lock").solver_clones += 1;
        // Remember where this clone came from: on its first check it can fork
        // that solver's engine instead of rebuilding from scratch. Lazily,
        // because angr clones far more often than it checks (state splits,
        // has_true probes), and an eager fork would tax every clone for the
        // few that ever solve. When this solver has no engine of its own yet
        // (a clone of a clone that never checked), pass its own fork source
        // through, so a chain of copies still reaches the ancestor that
        // actually solved.
        let source = SOLVER_CACHE.with(|cell| {
            if cell.borrow().contains_key(&self.cache_id) {
                Some(self.cache_id)
            } else {
                self.fork_source.get()
            }
        });
        SmtrsSolver {
            ctx: self.ctx,
            assertions: self.assertions.clone(),
            timeout: self.timeout,
            unsat_core: self.unsat_core,
            cache_id: next_solver_id(),
            fork_source: std::cell::Cell::new(source),
        }
    }
}

impl Drop for SmtrsSolver<'_> {
    fn drop(&mut self) {
        let _ = SOLVER_CACHE.try_with(|cell| {
            if let Ok(mut map) = cell.try_borrow_mut() {
                map.remove(&self.cache_id);
            }
        });
    }
}

impl<'c> SmtrsSolver<'c> {
    pub fn new(ctx: &'c Context<'c>) -> Self {
        Self::new_with_options(ctx, None, false)
    }

    pub fn new_with_timeout(ctx: &'c Context<'c>, timeout: Option<u32>) -> Self {
        Self::new_with_options(ctx, timeout, false)
    }

    pub fn new_with_options(ctx: &'c Context<'c>, timeout: Option<u32>, unsat_core: bool) -> Self {
        Self {
            ctx,
            assertions: vec![],
            timeout,
            unsat_core,
            cache_id: next_solver_id(),
            fork_source: std::cell::Cell::new(None),
        }
    }

    /// Get the unsat core from the last unsatisfiable check, as constraint
    /// indices. Requires the solver to have been created with unsat-core
    /// tracking enabled.
    pub fn unsat_core(&mut self) -> Result<Vec<usize>, ClarirsError> {
        if !self.unsat_core {
            return Err(ClarirsError::UnsupportedOperation(
                "Unsat core tracking is not enabled. Use new_with_options with unsat_core=true"
                    .to_string(),
            ));
        }
        self.with_cached_solver(|st, cached| {
            match check(st, cached, &[])? {
                Answer::Unsat => {}
                _ => {
                    return Err(ClarirsError::UnsupportedOperation(
                        "Can only get unsat core after an UNSAT result".to_string(),
                    ));
                }
            }
            let core = cached
                .solver
                .unsat_core()
                .map_err(|why| ClarirsError::UnsupportedOperation(why.to_string()))?;
            let mut indices: Vec<usize> = core
                .iter()
                .filter_map(|sym| cached.tracked.iter().position(|s| s == sym))
                .collect();
            indices.sort_unstable();
            Ok(indices)
        })
    }

    /// Drop this solver's cached engine, forcing a rebuild on next use.
    /// Required whenever the assertion set changes other than by appending.
    fn invalidate_cache(&self) {
        SOLVER_CACHE.with(|cell| {
            if cell.borrow_mut().remove(&self.cache_id).is_some() {
                GLOBAL_STATS.lock().expect("stats lock").cache_invalidations += 1;
            }
        });
    }

    /// Run `f` against this solver's cached persistent engine (per thread),
    /// asserting only the constraints added since the previous call rather
    /// than rebuilding and re-asserting the whole set each time.
    fn with_cached_solver<T>(
        &self,
        f: impl FnOnce(&mut PoolState, &mut CachedSolver) -> Result<T, ClarirsError>,
    ) -> Result<T, ClarirsError> {
        STATE.with(|state| {
            SOLVER_CACHE.with(|cell| {
                let st = &mut *state.borrow_mut();
                let reusable = match cell.borrow().get(&self.cache_id) {
                    Some(c) => {
                        c.timeout == self.timeout
                            && c.unsat_core == self.unsat_core
                            && c.asserted <= self.assertions.len()
                    }
                    None => false,
                };
                if !reusable {
                    // First build for this solver: fork the engine of the
                    // solver it was cloned from when that engine's asserted
                    // terms are exactly this solver's own converted prefix.
                    // The fork keeps the blasted formula and learned clauses,
                    // so only the post-clone assertions get asserted below —
                    // instead of paying the whole rewrite-and-blast pipeline
                    // again, which angr's clone-heavy call patterns
                    // (state splits, has_true probes) otherwise force on
                    // every first check.
                    let mut seeded = false;
                    if let Some(parent_id) = self.fork_source.take() {
                        let parent_terms: Option<Vec<TermId>> = {
                            let map = cell.borrow();
                            map.get(&parent_id)
                                .filter(|p| {
                                    p.timeout == self.timeout
                                        && p.unsat_core == self.unsat_core
                                        && p.asserted <= self.assertions.len()
                                })
                                .map(|p| p.asserted_terms.clone())
                        };
                        if let Some(pterms) = parent_terms {
                            let mut matches = true;
                            for (i, pt) in pterms.iter().enumerate() {
                                if to_term(&self.assertions[i], st)? != *pt {
                                    matches = false;
                                    break;
                                }
                            }
                            if matches {
                                let forked = {
                                    let map = cell.borrow();
                                    map.get(&parent_id)
                                        .map(|p| (p.solver.fork(), p.tracked.clone()))
                                };
                                if let Some((solver, tracked)) = forked {
                                    GLOBAL_STATS.lock().expect("stats lock").engine_forks += 1;
                                    cell.borrow_mut().insert(
                                        self.cache_id,
                                        CachedSolver {
                                            solver,
                                            asserted: pterms.len(),
                                            tracked,
                                            asserted_terms: pterms,
                                            timeout: self.timeout,
                                            unsat_core: self.unsat_core,
                                            // fork() resets the engine's own
                                            // stats, so deltas start at zero.
                                            reported: ReportedStats::default(),
                                        },
                                    );
                                    seeded = true;
                                }
                            }
                        }
                    }
                    if !seeded {
                        let mut solver = smtrs_solver::Solver::new();
                        if self.unsat_core {
                            solver.set_produce_unsat_cores(true);
                        }
                        cell.borrow_mut().insert(
                            self.cache_id,
                            CachedSolver {
                                solver,
                                asserted: 0,
                                tracked: Vec::new(),
                                asserted_terms: Vec::new(),
                                timeout: self.timeout,
                                unsat_core: self.unsat_core,
                                reported: ReportedStats::default(),
                            },
                        );
                    }
                }
                let mut map = cell.borrow_mut();
                let cached = map
                    .get_mut(&self.cache_id)
                    .expect("cache entry just ensured");
                while cached.asserted < self.assertions.len() {
                    let t = to_term(&self.assertions[cached.asserted], st)?;
                    if self.unsat_core {
                        let sym = cached.solver.assert_tracked(&mut st.pool, t);
                        cached.tracked.push(sym);
                    } else {
                        cached.solver.assert(t);
                    }
                    cached.asserted_terms.push(t);
                    cached.asserted += 1;
                }
                let out = f(st, cached);
                harvest(cached);
                out
            })
        })
    }

    /// The term to read a model value from for `expr`, together with the
    /// linking assumption when an auxiliary variable is required.
    ///
    /// Pure Bool/BV expressions are their own target. Anything float- or
    /// string-sorted (or containing such subterms) cannot be evaluated
    /// against a model — the theory content is lowered away before solving —
    /// so it is bound to a fresh auxiliary variable by an assumed equality:
    /// floats through their IEEE bit patterns (NaN would make float equality
    /// unsatisfiable), strings to an auxiliary string variable whose bounded
    /// encoding is then read back from the model.
    fn eval_target(
        &self,
        st: &mut PoolState,
        expr: &AstRef<'c>,
        force_bv: bool,
    ) -> Result<(TermId, Vec<TermId>, Option<String>), ClarirsError> {
        let t = to_term(expr, st)?;
        if !needs_aux(expr) {
            // The native bit-level operations (eval_n, minimize/maximize)
            // want a bit-vector target; a boolean becomes its 1-bit value.
            if force_bv && expr.ast_type().is_bool() {
                let one = st.pool.bv_u64(1, 1);
                let zero = st.pool.bv_u64(1, 0);
                let bit = st
                    .pool
                    .mk(Op::Ite, &[t, one, zero])
                    .map_err(crate::sort_err)?;
                return Ok((bit, vec![], None));
            }
            return Ok((t, vec![], None));
        }
        match expr.ast_type() {
            AstType::String => {
                let name = format!("__evals_{:x}", expr.hash());
                let sym = st.symbol(&name, Sort::Str);
                let aux = st.pool.var(sym);
                let link = st.pool.mk(Op::Eq, &[aux, t]).map_err(crate::sort_err)?;
                Ok((aux, vec![link], Some(name)))
            }
            ty => {
                let (target, width) = match ty {
                    AstType::Float(_) => (
                        st.pool.mk(Op::FpToIeeeBv, &[t]).map_err(crate::sort_err)?,
                        expr.size(),
                    ),
                    AstType::Bool => {
                        let one = st.pool.bv_u64(1, 1);
                        let zero = st.pool.bv_u64(1, 0);
                        (
                            st.pool
                                .mk(Op::Ite, &[t, one, zero])
                                .map_err(crate::sort_err)?,
                            1,
                        )
                    }
                    _ => (t, expr.size()),
                };
                let name = format!("__eval_{:x}", expr.hash());
                let sym = st.symbol(&name, Sort::BitVec(width));
                let aux = st.pool.var(sym);
                let link = st
                    .pool
                    .mk(Op::Eq, &[aux, target])
                    .map_err(crate::sort_err)?;
                Ok((aux, vec![link], None))
            }
        }
    }

    /// Read the bounded-string encoding of the auxiliary string variable
    /// `name` out of the current model: `{name}!len` characters of
    /// `{name}!c{i}`.
    fn string_from_model(
        st: &PoolState,
        cached: &CachedSolver,
        name: &str,
    ) -> Result<String, ClarirsError> {
        let model = cached.solver.model().ok_or_else(|| {
            ClarirsError::BackendError("smtrs", "no model available".to_string())
        })?;
        let len_name = format!("{name}!len");
        let char_prefix = format!("{name}!c");
        let mut len: Option<u64> = None;
        let mut chars: Vec<(u32, u8)> = Vec::new();
        for (sym, value) in model {
            let sym_name = &st.pool.symbol(*sym).name;
            if *sym_name == len_name {
                len = value.as_bv().and_then(BvConst::as_u64);
            } else if let Some(idx) = sym_name.strip_prefix(&char_prefix) {
                if let (Ok(i), Some(b)) = (idx.parse::<u32>(), value.as_bv().and_then(BvConst::as_u64))
                {
                    chars.push((i, b as u8));
                }
            }
        }
        let len = len.ok_or_else(|| {
            ClarirsError::BackendError(
                "smtrs",
                format!("model does not bind the string variable {name}"),
            )
        })?;
        chars.sort_unstable_by_key(|(i, _)| *i);
        Ok(chars
            .into_iter()
            .take(len as usize)
            .map(|(_, b)| b as char)
            .collect())
    }

    /// Evaluate `exprs` against one model of the current constraints. All
    /// values come from a single check, so the results are mutually
    /// consistent.
    fn model_eval(&self, exprs: &[AstRef<'c>]) -> Result<Vec<AstRef<'c>>, ClarirsError> {
        let ctx = self.ctx;
        let mut simplified = Vec::with_capacity(exprs.len());
        for e in exprs {
            simplified.push(e.simplify()?);
        }
        self.with_cached_solver(|st, cached| {
            let mut targets: Vec<Option<(TermId, Option<String>, AstType)>> =
                Vec::with_capacity(simplified.len());
            let mut assumptions = Vec::new();
            for e in &simplified {
                if e.concrete() {
                    targets.push(None);
                } else {
                    let (t, links, str_name) = self.eval_target(st, e, false)?;
                    assumptions.extend(links);
                    targets.push(Some((t, str_name, e.ast_type())));
                }
            }
            if targets.iter().all(Option::is_none) {
                return Ok(simplified.clone());
            }
            match check(st, cached, &assumptions)? {
                Answer::Sat => {}
                Answer::Unsat => return Err(ClarirsError::Unsat),
                Answer::Unknown(r) => return Err(ClarirsError::SolverUnknown(r)),
            }
            let mut out = Vec::with_capacity(simplified.len());
            for (e, target) in simplified.iter().zip(&targets) {
                match target {
                    None => out.push(e.clone()),
                    Some((_, Some(str_name), _)) => {
                        let s = Self::string_from_model(st, cached, str_name)?;
                        out.push(ctx.stringv(s)?);
                    }
                    Some((t, None, ty)) => {
                        let values = cached
                            .solver
                            .eval_terms(&st.pool, &[*t])
                            .map_err(|e| ClarirsError::BackendError("smtrs", e))?;
                        out.push(value_to_ast(ctx, &values[0], ty)?);
                    }
                }
            }
            Ok(out)
        })
    }

    /// Native unsigned extremum of `expr` under the current constraints.
    fn extremum_unsigned(
        &mut self,
        expr: &AstRef<'c>,
        maximize: bool,
    ) -> Result<AstRef<'c>, ClarirsError> {
        let expr = expr.simplify()?;
        if expr.concrete() {
            return expr
                .clone()
                .into_bitvec()
                .ok_or(ClarirsError::TypeError("Expected AstRef".to_string()));
        }
        let ctx = self.ctx;
        self.with_cached_solver(|st, cached| {
            let (t, assumptions, _) = self.eval_target(st, &expr, true)?;
            match check(st, cached, &assumptions)? {
                Answer::Sat => {}
                Answer::Unsat => return Err(ClarirsError::Unsat),
                Answer::Unknown(r) => return Err(ClarirsError::SolverUnknown(r)),
            }
            let _guard = watch(cached);
            let result = if maximize {
                cached.solver.maximize(&mut st.pool, t, &assumptions)
            } else {
                cached.solver.minimize(&mut st.pool, t, &assumptions)
            };
            let value = result.ok_or_else(|| {
                ClarirsError::SolverUnknown("extremum computation gave up".to_string())
            })?;
            ctx.bvv(bvconst_to_bitvec(&value)?)
                .and_then(|a| {
                    a.into_bitvec()
                        .ok_or(ClarirsError::TypeError("Expected AstRef".to_string()))
                })
        })
    }

    /// Signed extremum via the sign-flip embedding: XOR with the sign mask
    /// maps signed order onto unsigned order exactly, so one unsigned
    /// extremum on the flipped term (flipped back afterwards) is the answer.
    fn extremum_signed(
        &mut self,
        expr: &AstRef<'c>,
        maximize: bool,
    ) -> Result<AstRef<'c>, ClarirsError> {
        let expr = expr.simplify()?;
        if expr.concrete() {
            return expr
                .clone()
                .into_bitvec()
                .ok_or(ClarirsError::TypeError("Expected AstRef".to_string()));
        }
        let w = expr.size();
        // The sign mask 1 << (w-1) as a clarirs constant.
        let sign_mask = bvconst_to_bitvec(&BvConst::from_bits(w, |i| i == w - 1))?;
        let flipped = self.ctx.xor2(&expr, &self.ctx.bvv(sign_mask.clone())?)?;
        let extreme = self.extremum_unsigned(&flipped, maximize)?;
        let result = self
            .ctx
            .xor2(&extreme, &self.ctx.bvv(sign_mask)?)?
            .simplify()?;
        result
            .into_bitvec()
            .ok_or(ClarirsError::TypeError("Expected AstRef".to_string()))
    }
}

/// Install this check's termination flag (fresh each time, so nothing stale
/// can fire into it) and arm the watchdog when a timeout is configured.
fn watch(cached: &mut CachedSolver) -> Option<Watchdog> {
    cached.timeout.map(|ms| {
        GLOBAL_STATS.lock().expect("stats lock").watchdogs_armed += 1;
        let flag = Arc::new(AtomicBool::new(false));
        cached.solver.set_terminate(Arc::clone(&flag));
        Watchdog::arm(ms, flag)
    })
}

/// One satisfiability check on the cached engine, with the solver's declared
/// symbols synced so models are complete over every clarirs variable seen on
/// this thread, and the timeout watchdog armed.
fn check(
    st: &mut PoolState,
    cached: &mut CachedSolver,
    assumptions: &[TermId],
) -> Result<Answer, ClarirsError> {
    GLOBAL_STATS.lock().expect("stats lock").backend_checks += 1;
    cached.solver.declared.clone_from(&st.declared);
    let _guard = watch(cached);
    Ok(cached.solver.check_sat(&mut st.pool, assumptions))
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
                let simplified = c.simplify().ok()?;
                if simplified.is_true() {
                    None
                } else {
                    Some(Ok(simplified))
                }
            })
            .collect::<Result<Vec<_>, ClarirsError>>()?;
        // The assertion set changed in place; the cached engine is now stale.
        self.invalidate_cache();
        Ok(())
    }

    fn satisfiable(&mut self) -> Result<bool, ClarirsError> {
        self.with_cached_solver(|st, cached| match check(st, cached, &[])? {
            Answer::Sat => Ok(true),
            Answer::Unsat => Ok(false),
            Answer::Unknown(r) => Err(ClarirsError::SolverUnknown(r)),
        })
    }

    fn satisfiable_with_extra(&mut self, extra: &[AstRef<'c>]) -> Result<bool, ClarirsError> {
        // Check with the extra constraints as assumptions on the persistent
        // incremental engine: no clone, no from-scratch re-assertion. This is
        // angr's hottest solver call (every branch feasibility check), and
        // check-sat-assuming is native to smtrs.
        let mut simplified = Vec::with_capacity(extra.len());
        for c in extra {
            simplified.push(c.simplify()?);
        }
        self.with_cached_solver(|st, cached| {
            let mut assumptions = Vec::with_capacity(simplified.len());
            for c in &simplified {
                assumptions.push(to_term(c, st)?);
            }
            match check(st, cached, &assumptions)? {
                Answer::Sat => Ok(true),
                Answer::Unsat => Ok(false),
                Answer::Unknown(r) => Err(ClarirsError::SolverUnknown(r)),
            }
        })
    }

    fn eval(&mut self, expr: &AstRef<'c>) -> Result<AstRef<'c>, ClarirsError> {
        Ok(self.model_eval(std::slice::from_ref(expr))?.remove(0))
    }

    fn batch_eval(&mut self, exprs: &[AstRef<'c>]) -> Result<Vec<AstRef<'c>>, ClarirsError> {
        if exprs.is_empty() {
            return Ok(Vec::new());
        }
        self.model_eval(exprs)
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
        self.extremum_unsigned(expr, false)
    }

    fn max_unsigned(&mut self, expr: &AstRef<'c>) -> Result<AstRef<'c>, ClarirsError> {
        self.extremum_unsigned(expr, true)
    }

    fn min_signed(&mut self, expr: &AstRef<'c>) -> Result<AstRef<'c>, ClarirsError> {
        self.extremum_signed(expr, false)
    }

    fn max_signed(&mut self, expr: &AstRef<'c>) -> Result<AstRef<'c>, ClarirsError> {
        self.extremum_signed(expr, true)
    }

    fn eval_n(&mut self, expr: &AstRef<'c>, n: u32) -> Result<Vec<AstRef<'c>>, ClarirsError> {
        let expr = expr.simplify()?;
        if expr.concrete() {
            return Ok(vec![expr]);
        }
        let ctx = self.ctx;

        // Strings enumerate by iterated exclusion: read a value from the
        // model, exclude it, repeat. Everything else uses the native value
        // enumeration on the target bit-vector (the expression itself, or the
        // auxiliary variable binding its float bits / boolean value).
        if matches!(expr.ast_type(), AstType::String) {
            let mut results = Vec::new();
            let mut exclusions: Vec<AstRef<'c>> = Vec::new();
            for _ in 0..n {
                let mut probe = self.clone();
                for e in &exclusions {
                    probe.add(e)?;
                }
                match probe.eval(&expr) {
                    Ok(value) => {
                        exclusions.push(ctx.neq(&expr, &value)?);
                        results.push(value);
                    }
                    Err(ClarirsError::Unsat) => break,
                    Err(e) => return Err(e),
                }
            }
            return Ok(results);
        }

        let ty = expr.ast_type();
        self.with_cached_solver(|st, cached| {
            let (t, assumptions, _) = self.eval_target(st, &expr, true)?;
            match check(st, cached, &assumptions)? {
                Answer::Sat => {}
                Answer::Unsat => return Ok(Vec::new()),
                Answer::Unknown(r) => return Err(ClarirsError::SolverUnknown(r)),
            }
            let _guard = watch(cached);
            let values = cached
                .solver
                .eval_n(&mut st.pool, t, n as usize, &assumptions);
            values
                .iter()
                .map(|c| value_to_ast(ctx, &Value::Bv(c.clone()), &ty))
                .collect()
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use clarirs_core::solver_mixins::ModelCacheMixin;

    /// Clones fork the parent's engine: answers stay correct across the
    /// clone-then-diverge pattern angr uses everywhere (has_true probes,
    /// state splits), including a chain of never-checked copies.
    #[test]
    fn test_clone_forks_engine() -> Result<(), ClarirsError> {
        let ctx = Context::new();
        let mut parent = SmtrsSolver::new(&ctx);
        let x = ctx.bvs("fork_x", 32)?;
        parent.add(&ctx.ugt(&x, &ctx.bvv(BitVec::from((10, 32)))?)?)?;
        assert!(parent.satisfiable()?);

        // Direct clone: diverges with its own constraint.
        let mut child = parent.clone();
        child.add(&ctx.ult(&x, &ctx.bvv(BitVec::from((5, 32)))?)?)?;
        assert!(!child.satisfiable()?);
        // The parent is unaffected.
        assert!(parent.satisfiable()?);

        // A chain of unchecked copies still resolves against the ancestor.
        let mut grandchild = parent.clone().clone().clone();
        grandchild.add(&ctx.eq_(&x, &ctx.bvv(BitVec::from((11, 32)))?)?)?;
        assert!(grandchild.satisfiable()?);
        grandchild.add(&ctx.eq_(&x, &ctx.bvv(BitVec::from((12, 32)))?)?)?;
        assert!(!grandchild.satisfiable()?);
        Ok(())
    }

    /// A parent that clears and re-asserts something else under the same
    /// cache id must not leak its new engine into an older clone: the fork
    /// guard compares asserted terms, not counts.
    #[test]
    fn test_fork_guard_rejects_diverged_parent() -> Result<(), ClarirsError> {
        let ctx = Context::new();
        let mut parent = SmtrsSolver::new(&ctx);
        let x = ctx.bvs("guard_x", 8)?;
        parent.add(&ctx.eq_(&x, &ctx.bvv(BitVec::from((1, 8)))?)?)?;
        assert!(parent.satisfiable()?);

        let mut child = parent.clone(); // remembers parent as fork source

        // Parent rebuilds under the same cache id with a different set.
        parent.clear()?;
        parent.add(&ctx.eq_(&x, &ctx.bvv(BitVec::from((2, 8)))?)?)?;
        assert!(parent.satisfiable()?);

        // The child still answers for ITS constraints (x == 1), so x == 2
        // must be unsat on top of them.
        child.add(&ctx.eq_(&x, &ctx.bvv(BitVec::from((2, 8)))?)?)?;
        assert!(!child.satisfiable()?);
        Ok(())
    }

    #[test]
    fn test_solver_simple() -> Result<(), ClarirsError> {
        let ctx = Context::new();
        let mut solver = SmtrsSolver::new(&ctx);
        let x = ctx.bools("x")?;
        let y = ctx.bools("y")?;
        solver.add(&ctx.neq(&x, &y)?)?;
        let x_val = solver.eval(&x).unwrap();
        let y_val = solver.eval(&y).unwrap();
        assert_ne!(x_val, y_val);
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
        Ok(())
    }

    #[test]
    fn test_batch_eval_consistent_model() -> Result<(), ClarirsError> {
        let ctx = Context::new();
        let mut solver = SmtrsSolver::new(&ctx);
        let x = ctx.bvs("x", 8)?;
        let y = ctx.bvs("y", 8)?;
        solver.add(&ctx.eq_(&y, &ctx.add(&x, &ctx.bvv(BitVec::from((1, 8)))?)?)?)?;
        let values = solver.batch_eval(&[x.clone(), y.clone()])?;
        assert_eq!(values.len(), 2);
        let (x_val, y_val) = (values[0].clone(), values[1].clone());
        let expected_y = ctx
            .add(&x_val, &ctx.bvv(BitVec::from((1, 8)))?)?
            .simplify()?;
        assert_eq!(y_val, expected_y);
        Ok(())
    }

    #[test]
    fn test_model_cache_matches_cacheless() -> Result<(), ClarirsError> {
        let ctx = Context::new();
        let mut cached = ModelCacheMixin::new(SmtrsSolver::new(&ctx));
        let mut cacheless = SmtrsSolver::new(&ctx);
        let x = ctx.bvs("x", 32)?;
        let c1 = ctx.uge(&x, &ctx.bvv(BitVec::from((10, 32)))?)?;
        let c2 = ctx.ule(&x, &ctx.bvv(BitVec::from((20, 32)))?)?;
        cached.add(&c1)?;
        cached.add(&c2)?;
        cacheless.add(&c1)?;
        cacheless.add(&c2)?;
        assert_eq!(cached.satisfiable()?, cacheless.satisfiable()?);
        assert!(cached.satisfiable()?);
        let v = cached.eval(&x)?;
        let in_range = cached.is_true(&ctx.and2(
            &ctx.uge(&v, &ctx.bvv(BitVec::from((10, 32)))?)?,
            &ctx.ule(&v, &ctx.bvv(BitVec::from((20, 32)))?)?,
        )?)?;
        assert!(in_range, "cached eval produced an out-of-range value: {v:?}");
        assert!(!cached.satisfiable_with_extra(&[ctx.eq_(&x, &ctx.bvv(BitVec::from((100, 32)))?)?])?);
        Ok(())
    }

    #[test]
    fn test_fp_neq_is_ieee() -> Result<(), ClarirsError> {
        let ctx = Context::new();
        // x != x is satisfiable for floats: NaN is IEEE-unequal to itself.
        let mut solver = SmtrsSolver::new(&ctx);
        let x = ctx.fps("x", FSort::f64())?;
        solver.add(&ctx.neq(&x, &x)?)?;
        assert!(solver.satisfiable()?);
        // ...and NaN is the only witness.
        solver.add(&ctx.not(&ctx.fp_is_nan(&x)?)?)?;
        assert!(!solver.satisfiable()?);
        Ok(())
    }

    #[test]
    fn test_min_max_unsigned() -> Result<(), ClarirsError> {
        let ctx = Context::new();
        let mut solver = SmtrsSolver::new(&ctx);
        let x = ctx.bvs("x", 64)?;
        let lower = ctx.bvv(BitVec::from((10, 64)))?;
        let upper = ctx.bvv(BitVec::from((20, 64)))?;
        solver.add(&ctx.uge(&x, &lower)?)?;
        solver.add(&ctx.ule(&x, &upper)?)?;
        assert_eq!(solver.min_unsigned(&x)?, lower);
        assert_eq!(solver.max_unsigned(&x)?, upper);
        Ok(())
    }

    #[test]
    fn test_min_max_signed() -> Result<(), ClarirsError> {
        let ctx = Context::new();
        let mut solver = SmtrsSolver::new(&ctx);
        let x = ctx.bvs("x", 64)?;
        // -10 <= x <= 20 signed.
        let lower = ctx.bvv(BitVec::from((0xfffffffffffffff6u64, 64)))?;
        let upper = ctx.bvv(BitVec::from((20, 64)))?;
        solver.add(&ctx.sge(&x, &lower)?)?;
        solver.add(&ctx.sle(&x, &upper)?)?;
        assert_eq!(solver.min_signed(&x)?, lower);
        assert_eq!(solver.max_signed(&x)?, upper);
        Ok(())
    }

    #[test]
    fn test_eval_n_distinct() -> Result<(), ClarirsError> {
        let ctx = Context::new();
        let mut solver = SmtrsSolver::new(&ctx);
        let x = ctx.bvs("x", 8)?;
        solver.add(&ctx.ult(&x, &ctx.bvv(BitVec::from((3, 8)))?)?)?;
        let mut values = solver.eval_n(&x, 10)?;
        assert_eq!(values.len(), 3);
        values.sort_by_key(|v| format!("{v:?}"));
        values.dedup();
        assert_eq!(values.len(), 3);
        Ok(())
    }

    #[test]
    fn test_unsat_core_simple() -> Result<(), ClarirsError> {
        let ctx = Context::new();
        let mut solver = SmtrsSolver::new_with_options(&ctx, None, true);
        let x = ctx.bvs("x", 8)?;
        let c0 = ctx.ugt(&x, &ctx.bvv(BitVec::from((10, 8)))?)?;
        let c1 = ctx.ult(&x, &ctx.bvv(BitVec::from((5, 8)))?)?;
        let c2 = ctx.ugt(&x, &ctx.bvv(BitVec::from((0, 8)))?)?;
        solver.add(&c0)?;
        solver.add(&c1)?;
        solver.add(&c2)?;
        assert!(!solver.satisfiable()?);
        let core = solver.unsat_core()?;
        assert!(!core.is_empty());
        assert!(core.contains(&0));
        assert!(core.contains(&1));
        Ok(())
    }

    #[test]
    fn test_string_eval() -> Result<(), ClarirsError> {
        let ctx = Context::new();
        let mut solver = SmtrsSolver::new(&ctx);
        let s = ctx.strings("s")?;
        solver.add(&ctx.eq_(&s, &ctx.stringv("hello")?)?)?;
        let v = solver.eval(&s)?;
        assert_eq!(v, ctx.stringv("hello")?);
        Ok(())
    }

    #[test]
    fn test_strlen_constraint() -> Result<(), ClarirsError> {
        let ctx = Context::new();
        let mut solver = SmtrsSolver::new(&ctx);
        let s = ctx.strings("s")?;
        let len = ctx.str_len(&s)?;
        solver.add(&ctx.eq_(&len, &ctx.bvv(BitVec::from((3, 64)))?)?)?;
        assert!(solver.satisfiable()?);
        let v = solver.eval(&s)?;
        if let AstOp::StringV(sv) = v.op() {
            assert_eq!(sv.len(), 3);
        } else {
            panic!("expected a concrete string, got {v:?}");
        }
        // A contradictory length is a real unsat.
        solver.add(&ctx.eq_(&len, &ctx.bvv(BitVec::from((5, 64)))?)?)?;
        assert!(!solver.satisfiable()?);
        Ok(())
    }
}
