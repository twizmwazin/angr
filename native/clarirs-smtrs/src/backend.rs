//! Thread-local smtrs state: one term pool shared by every solver on the
//! thread, and one persistent engine per live [`SmtrsSolver`](crate::SmtrsSolver).
//!
//! # Ownership
//!
//! smtrs is built on `&mut TermPool` and `TermId`: terms belong to a pool,
//! and an engine's assertions are terms in that pool. clarirs solvers, on the
//! other hand, are cloned freely (every state copy in angr clones its
//! solver) and must be `Send`. So the pool and the engines live here, in
//! thread-local storage, and a solver value carries only an id: cloning a
//! solver copies a `Vec<AstRef>`, and moving it to another thread means its
//! engine is rebuilt there from those ASTs on first use.
//!
//! # Engines, forks and borrowed queries
//!
//! An engine is built on a solver's first query and then extended in place
//! as constraints are added. A clone records the nearest ancestor that had
//! an engine when it was cloned, and answers its *first* query by pushing a
//! level onto that engine, asserting whatever it added, and popping again —
//! angr's `eval(expr, extra_constraints=...)` clones a solver, adds the
//! extras, evaluates once and drops the clone, and this makes that scoped
//! query a push/pop on a warm engine instead of a solver build. A clone that
//! keeps being queried gets its own engine, forked from the ancestor's with
//! its learned clauses when that is still possible.

use std::cell::RefCell;
use std::collections::HashMap;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU64};
use std::time::Duration;

use clarirs_core::prelude::*;
use rustc_hash::FxHashMap;
use smtrs_core::{BvConst, SymbolId, TermId, TermPool, Value};
use smtrs_solver::Answer;

use crate::convert::{Converter, Kind, eval_completed, string_value, value_to_ast};
use crate::deadline;

/// The per-engine configuration that must match for an engine to be reused.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub(crate) struct Config {
    /// Milliseconds per query, as z3's `timeout` parameter.
    pub timeout: Option<u32>,
    pub unsat_core: bool,
}

/// A persistent smtrs engine holding a prefix of one solver's constraints.
pub(crate) struct Engine {
    pub solver: smtrs_solver::Solver,
    /// Hash of each constraint asserted, in order; the solver's constraint
    /// list must start with exactly these for the engine to stand for it.
    asserted: Vec<u64>,
    /// Activation symbol of each asserted constraint, in unsat-core mode.
    pub tracked: Vec<SymbolId>,
    config: Config,
    /// Cooperative-interrupt flag wired into `solver`, in timeout mode.
    terminate: Option<Arc<AtomicBool>>,
    token: Arc<AtomicU64>,
    /// The last answer was `sat` and nothing changed since, so the engine's
    /// model is a model of the current constraints.
    model_fresh: bool,
}

impl Engine {
    fn new(config: Config) -> Self {
        let _t = crate::stats::ENGINE_SETUP.enter();
        crate::stats::ENGINE_BUILDS.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        let mut solver = smtrs_solver::Solver::new();
        // Model validation re-evaluates every assertion under the model on
        // each sat answer: a debugging aid, not something to pay for on
        // angr's hot path.
        solver.validate_models = std::env::var_os("CLARIRS_SMTRS_VALIDATE_MODELS").is_some();
        // Every push here is a scoped query (see the module docs), so levels
        // are encoded under activation literals from the start.
        solver.set_always_guard_levels(true);
        if config.unsat_core {
            solver.set_produce_unsat_cores(true);
        }
        let mut engine = Engine {
            solver,
            asserted: Vec::new(),
            tracked: Vec::new(),
            config,
            terminate: None,
            token: Arc::new(AtomicU64::new(0)),
            model_fresh: false,
        };
        engine.wire_terminate();
        engine
    }

    fn fork(&self) -> Self {
        let _t = crate::stats::ENGINE_SETUP.enter();
        crate::stats::ENGINE_FORKS.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        let mut engine = Engine {
            solver: self.solver.fork(),
            asserted: self.asserted.clone(),
            tracked: self.tracked.clone(),
            config: self.config,
            terminate: None,
            token: Arc::new(AtomicU64::new(0)),
            model_fresh: false,
        };
        engine.wire_terminate();
        engine
    }

    fn wire_terminate(&mut self) {
        if self.config.timeout.is_some() {
            let flag = Arc::new(AtomicBool::new(false));
            self.solver.set_terminate(flag.clone());
            self.terminate = Some(flag);
        }
    }

    /// Arm this engine's deadline for one query, if it has a timeout.
    fn arm(&self) -> Option<deadline::Armed> {
        let timeout = self.config.timeout?;
        let flag = self.terminate.as_ref()?;
        Some(deadline::arm(
            flag,
            &self.token,
            Duration::from_millis(u64::from(timeout)),
        ))
    }

    /// Whether `constraints` starts with everything asserted here.
    fn is_prefix_of(&self, constraints: &[AstRef<'_>]) -> bool {
        self.asserted.len() <= constraints.len()
            && self
                .asserted
                .iter()
                .zip(constraints)
                .all(|(h, c)| *h == c.hash())
    }

    fn assert(&mut self, pool: &mut TermPool, term: TermId, hash: u64) {
        if self.config.unsat_core {
            let sym = self.solver.assert_tracked(pool, term);
            self.tracked.push(sym);
        } else {
            self.solver.assert(term);
        }
        self.asserted.push(hash);
        self.model_fresh = false;
    }

    /// Assert `constraints[asserted..]`.
    fn sync(
        &mut self,
        conv: &mut Converter<'_>,
        constraints: &[AstRef<'_>],
    ) -> Result<(), ClarirsError> {
        for c in &constraints[self.asserted.len()..] {
            let t = conv.term(c)?;
            self.assert(conv.pool, t, c.hash());
        }
        Ok(())
    }

    pub(crate) fn check(
        &mut self,
        pool: &mut TermPool,
        assumptions: &[TermId],
    ) -> Result<bool, ClarirsError> {
        let snap = crate::stats::SolverSnapshot::of(&self.solver);
        let answer = {
            let _t = crate::stats::CHECK.enter();
            self.solver.check_sat(pool, assumptions)
        };
        snap.account(&self.solver);
        self.model_fresh = answer == Answer::Sat;
        match answer {
            Answer::Sat => Ok(true),
            Answer::Unsat => Ok(false),
            Answer::Unknown(reason) => Err(ClarirsError::SolverUnknown(reason)),
        }
    }

    /// `minimize` / `maximize` of `target` over the current constraints.
    pub(crate) fn extremum(
        &mut self,
        pool: &mut TermPool,
        target: TermId,
        maximize: bool,
    ) -> Option<BvConst> {
        let snap = crate::stats::SolverSnapshot::of(&self.solver);
        let found = {
            let _t = crate::stats::EXTREMUM.enter();
            if maximize {
                self.solver.maximize(pool, target, &[])
            } else {
                self.solver.minimize(pool, target, &[])
            }
        };
        snap.account(&self.solver);
        found
    }

    /// Up to `n` distinct values of `term` over the current constraints.
    pub(crate) fn enumerate(
        &mut self,
        pool: &mut TermPool,
        term: TermId,
        n: usize,
    ) -> Vec<BvConst> {
        let snap = crate::stats::SolverSnapshot::of(&self.solver);
        let values = {
            let _t = crate::stats::ENUMERATE.enter();
            self.solver.eval_n(pool, term, n, &[])
        };
        snap.account(&self.solver);
        values
    }

    /// Make sure the engine holds a model of the current constraints,
    /// re-checking only when something changed since the last `sat`.
    pub(crate) fn ensure_model(&mut self, pool: &mut TermPool) -> Result<(), ClarirsError> {
        if self.model_fresh && self.solver.model().is_some() {
            return Ok(());
        }
        if self.check(pool, &[])? {
            Ok(())
        } else {
            Err(ClarirsError::Unsat)
        }
    }

    /// Values of `terms` under the current model (see [`ensure_model`]),
    /// lowering floating point the way the assertions were lowered.
    ///
    /// [`ensure_model`]: Engine::ensure_model
    pub(crate) fn eval_terms(
        &self,
        pool: &mut TermPool,
        terms: &[TermId],
    ) -> Result<Vec<Value>, ClarirsError> {
        let _t = crate::stats::EVAL.enter();
        let lowered;
        let terms = if smtrs_fp::contains_fp(pool, terms) {
            lowered = smtrs_fp::lower(pool, terms).map_err(|e| {
                ClarirsError::UnsupportedOperation(format!(
                    "smtrs cannot evaluate this expression: {e}"
                ))
            })?;
            &lowered[..]
        } else {
            terms
        };
        let model = self
            .solver
            .model()
            .ok_or_else(|| ClarirsError::SolverUnknown("no model available".to_string()))?;
        eval_completed(pool, model, terms)
    }

    /// The value of `expr` under the current model, by substituting every
    /// variable's value and folding: the path for expressions whose value
    /// is not a term's (strings, whose lowering scatters them over derived
    /// symbols).
    pub(crate) fn eval_by_substitution<'c>(
        &self,
        conv: &mut Converter<'_>,
        expr: &AstRef<'c>,
    ) -> Result<AstRef<'c>, ClarirsError> {
        let _t = crate::stats::EVAL.enter();
        let ctx = expr.context();
        let mut values: HashMap<u64, AstRef<'c>> = HashMap::new();
        let mut stack = vec![expr.clone()];
        let mut seen = rustc_hash::FxHashSet::default();
        while let Some(node) = stack.pop() {
            if !seen.insert(node.hash()) {
                continue;
            }
            match node.op() {
                AstOp::StringS(name) => {
                    let model = self.solver.model().ok_or_else(|| {
                        ClarirsError::SolverUnknown("no model available".to_string())
                    })?;
                    let text = match conv.existing_var(name, smtrs_core::Sort::Str) {
                        Some(sym) => string_value(conv.pool, model, sym),
                        None => String::new(),
                    };
                    values.insert(node.hash(), ctx.stringv(text)?);
                }
                AstOp::BoolS(_) | AstOp::BVS(_, _) | AstOp::FPS(_, _) => {
                    let (t, kind) = conv.query_term(&node, false)?;
                    let v = self.eval_terms(conv.pool, &[t])?;
                    values.insert(node.hash(), value_to_ast(ctx, &v[0], kind)?);
                }
                _ => stack.extend(node.child_iter()),
            }
        }
        let folded = expr.replace_many(&values)?.simplify()?;
        if crate::convert::is_literal(&folded) {
            Ok(folded)
        } else {
            Err(ClarirsError::UnsupportedOperation(format!(
                "the smtrs backend cannot evaluate this expression to a literal: {folded:?}"
            )))
        }
    }

    /// Whether a query on `term` must take the substitution path: its value
    /// is a string, or a string is somewhere inside it (a length, an index),
    /// where the lowering's side constraints give the fresh symbols their
    /// meaning and a bare lowered term would not evaluate.
    pub(crate) fn needs_substitution(pool: &TermPool, term: TermId, kind: Kind) -> bool {
        matches!(kind, Kind::String) || smtrs_str::contains_strings(pool, &[term])
    }

    /// The value of every `(term, kind)` under the current model, in order;
    /// expressions involving strings take the substitution path on `exprs`.
    pub(crate) fn eval_kinds<'c>(
        &self,
        conv: &mut Converter<'_>,
        exprs: &[AstRef<'c>],
        terms: &[TermId],
        kinds: &[Kind],
    ) -> Result<Vec<AstRef<'c>>, ClarirsError> {
        let _t = crate::stats::EVAL.enter();
        let ctx = exprs[0].context();
        let substitute: Vec<bool> = terms
            .iter()
            .zip(kinds)
            .map(|(t, k)| Self::needs_substitution(conv.pool, *t, *k))
            .collect();
        let scalar: Vec<TermId> = terms
            .iter()
            .zip(&substitute)
            .filter(|(_, s)| !**s)
            .map(|(t, _)| *t)
            .collect();
        let mut scalar_values = self.eval_terms(conv.pool, &scalar)?.into_iter();
        let mut out = Vec::with_capacity(exprs.len());
        for ((expr, kind), substitute) in exprs.iter().zip(kinds).zip(substitute) {
            out.push(if substitute {
                self.eval_by_substitution(conv, expr)?
            } else {
                let v = scalar_values.next().expect("one value per scalar term");
                value_to_ast(ctx, &v, *kind)?
            });
        }
        Ok(out)
    }
}

/// What a query needs to know about the solver it runs for.
pub(crate) struct Request<'a, 'c> {
    pub id: u64,
    pub parent: Option<u64>,
    pub constraints: &'a [AstRef<'c>],
    pub config: Config,
    /// This is the solver's first query, so it may borrow its parent's engine.
    pub first: bool,
}

pub(crate) struct Backend {
    pool: TermPool,
    terms: FxHashMap<u64, TermId>,
    vars: FxHashMap<(InternedString, smtrs_core::Sort), SymbolId>,
    names: FxHashMap<String, SymbolId>,
    engines: HashMap<u64, Engine>,
}

thread_local! {
    static BACKEND: RefCell<Backend> = RefCell::new(Backend {
        pool: TermPool::new(),
        terms: FxHashMap::default(),
        vars: FxHashMap::default(),
        names: FxHashMap::default(),
        engines: HashMap::new(),
    });
}

/// Run `f` against this thread's backend.
pub(crate) fn with_backend<R>(f: impl FnOnce(&mut Backend) -> R) -> R {
    BACKEND.with(|cell| f(&mut cell.borrow_mut()))
}

/// Forget a solver's engine. Safe to call from `Drop`, including during
/// thread teardown or while the backend is already borrowed.
pub(crate) fn forget_engine(id: u64) {
    let _ = BACKEND.try_with(|cell| {
        if let Ok(mut backend) = cell.try_borrow_mut() {
            backend.engines.remove(&id);
        }
    });
}

impl Backend {
    pub(crate) fn has_engine(&self, id: u64) -> bool {
        self.engines.contains_key(&id)
    }

    pub(crate) fn drop_engine(&mut self, id: u64) {
        self.engines.remove(&id);
    }

    /// Run `f` against an engine holding exactly `req.constraints`,
    /// following the policy in the module docs.
    pub(crate) fn run<R>(
        &mut self,
        req: &Request<'_, '_>,
        f: impl FnOnce(&mut Converter<'_>, &mut Engine) -> Result<R, ClarirsError>,
    ) -> Result<R, ClarirsError> {
        let Backend {
            pool,
            terms,
            vars,
            names,
            engines,
        } = self;
        let mut conv = Converter::new(pool, terms, vars, names);

        // An engine of our own that still stands for our constraints.
        let own_ok = engines
            .get(&req.id)
            .is_some_and(|e| e.config == req.config && e.is_prefix_of(req.constraints));
        if !own_ok {
            engines.remove(&req.id);
        }
        if let Some(engine) = engines.get_mut(&req.id) {
            engine.sync(&mut conv, req.constraints)?;
            let _armed = engine.arm();
            return f(&mut conv, engine);
        }

        // Our ancestor's engine, if it still stands for a prefix of ours.
        let parent = req.parent.filter(|pid| {
            engines
                .get(pid)
                .is_some_and(|e| e.config == req.config && e.is_prefix_of(req.constraints))
        });

        // First query: borrow the ancestor's engine under a push level. Not
        // in unsat-core mode, where the core would name its tracked symbols.
        if req.first
            && !req.config.unsat_core
            && let Some(pid) = parent
        {
            let engine = engines.get_mut(&pid).expect("checked above");
            let base = engine.asserted.len();
            crate::stats::BORROWED.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            engine.solver.push(1);
            // The level is popped whatever happens inside, a panic included:
            // an engine left with a foreign level would answer wrongly for
            // its owner from then on.
            let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                for c in &req.constraints[base..] {
                    let t = conv.term(c)?;
                    engine.solver.assert(t);
                }
                engine.model_fresh = false;
                let _armed = engine.arm();
                f(&mut conv, engine)
            }));
            engine.solver.pop(1);
            engine.model_fresh = false;
            return match result {
                Ok(result) => result,
                Err(payload) => std::panic::resume_unwind(payload),
            };
        }

        let mut engine = match parent {
            Some(pid) => engines[&pid].fork(),
            None => Engine::new(req.config),
        };
        engine.sync(&mut conv, req.constraints)?;
        let engine = engines.entry(req.id).or_insert(engine);
        let _armed = engine.arm();
        f(&mut conv, engine)
    }
}
