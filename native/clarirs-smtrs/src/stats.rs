//! Wall-clock accounting of the time spent inside the backend, for
//! profiling an embedding: the whole of every query (`run`), and the parts
//! of it spent converting ASTs, checking, optimising, enumerating and
//! reading models, plus smtrs's own phase times and search counters summed
//! over every call. Process-global relaxed atomics: cheap enough to stay
//! on, and readable from Python through `smtrs_stats()`.

use std::cell::Cell;
use std::sync::atomic::{AtomicU64, Ordering::Relaxed};
use std::time::Instant;

pub struct Counter {
    id: usize,
    pub ns: AtomicU64,
    pub calls: AtomicU64,
}

impl Counter {
    const fn new(id: usize) -> Self {
        Counter {
            id,
            ns: AtomicU64::new(0),
            calls: AtomicU64::new(0),
        }
    }

    /// Time the enclosing scope; nested entries of the same counter on the
    /// same thread count once, so a recursive entry point is not double
    /// counted.
    pub fn enter(&'static self) -> Timer {
        let outermost = DEPTH.with(|d| {
            let n = d[self.id].get();
            d[self.id].set(n + 1);
            n == 0
        });
        Timer {
            counter: self,
            start: Instant::now(),
            outermost,
        }
    }

    fn add_secs(&self, secs: f64) {
        self.ns.fetch_add((secs * 1e9) as u64, Relaxed);
        self.calls.fetch_add(1, Relaxed);
    }
}

pub struct Timer {
    counter: &'static Counter,
    start: Instant,
    outermost: bool,
}

impl Drop for Timer {
    fn drop(&mut self) {
        DEPTH.with(|d| d[self.counter.id].set(d[self.counter.id].get() - 1));
        if self.outermost {
            self.counter
                .ns
                .fetch_add(self.start.elapsed().as_nanos() as u64, Relaxed);
            self.counter.calls.fetch_add(1, Relaxed);
        }
    }
}

const N: usize = 14;
thread_local! {
    static DEPTH: [Cell<u32>; N] = [const { Cell::new(0) }; N];
}

/// A whole query against the backend: everything below is part of it.
pub static RUN: Counter = Counter::new(0);
/// clarirs AST to smtrs term conversion (cached per thread).
pub static CONVERT: Counter = Counter::new(1);
/// `check_sat`, with or without assumptions.
pub static CHECK: Counter = Counter::new(2);
/// `minimize` / `maximize`.
pub static EXTREMUM: Counter = Counter::new(3);
/// `eval_n` enumeration (bit-level or by exclusion).
pub static ENUMERATE: Counter = Counter::new(4);
/// Reading values off a model, including by substitution.
pub static EVAL: Counter = Counter::new(5);
/// smtrs's own phases, summed over every solver call.
pub static PHASE_LOWER_FP: Counter = Counter::new(6);
pub static PHASE_LOWER_STR: Counter = Counter::new(7);
pub static PHASE_REWRITE: Counter = Counter::new(8);
pub static PHASE_BLAST: Counter = Counter::new(9);
pub static PHASE_SAT: Counter = Counter::new(10);
pub static PHASE_MODEL: Counter = Counter::new(11);
pub static PHASE_PROP_ABS: Counter = Counter::new(12);
/// Wall time of `Engine::new` and `Engine::fork`.
pub static ENGINE_SETUP: Counter = Counter::new(13);

pub static ENGINE_BUILDS: AtomicU64 = AtomicU64::new(0);
pub static ENGINE_FORKS: AtomicU64 = AtomicU64::new(0);
/// First queries of a clone answered under a push level on its ancestor.
pub static BORROWED: AtomicU64 = AtomicU64::new(0);
/// smtrs engine rebuilds (a non-incremental step), summed.
pub static REBUILDS: AtomicU64 = AtomicU64::new(0);
pub static SAT_CONFLICTS: AtomicU64 = AtomicU64::new(0);
pub static SAT_DECISIONS: AtomicU64 = AtomicU64::new(0);
pub static SAT_PROPAGATIONS: AtomicU64 = AtomicU64::new(0);

/// Snapshot of a solver's cumulative statistics, to diff around a call.
#[derive(Clone, Copy, Default)]
pub struct SolverSnapshot {
    phases: [f64; 7],
    rebuilds: u64,
    conflicts: u64,
    decisions: u64,
    propagations: u64,
}

impl SolverSnapshot {
    pub fn of(s: &smtrs_solver::Solver) -> Self {
        let p = &s.stats.phases;
        let (c, d, pr) = s
            .stats
            .sat_counters
            .as_ref()
            .map_or((0, 0, 0), |c| (c.conflicts, c.decisions, c.propagations));
        SolverSnapshot {
            phases: [
                p.lower_fp,
                p.lower_str,
                p.rewrite_preprocess,
                p.blast,
                p.sat,
                p.model,
                p.prop_abs,
            ],
            rebuilds: s.stats.rebuilds,
            conflicts: c,
            decisions: d,
            propagations: pr,
        }
    }

    /// Add what happened between `self` and the solver's current state.
    pub fn account(&self, s: &smtrs_solver::Solver) {
        let now = Self::of(s);
        let phase = [
            &PHASE_LOWER_FP,
            &PHASE_LOWER_STR,
            &PHASE_REWRITE,
            &PHASE_BLAST,
            &PHASE_SAT,
            &PHASE_MODEL,
            &PHASE_PROP_ABS,
        ];
        for (i, c) in phase.iter().enumerate() {
            let d = now.phases[i] - self.phases[i];
            if d > 0.0 {
                c.add_secs(d);
            }
        }
        REBUILDS.fetch_add(now.rebuilds.wrapping_sub(self.rebuilds), Relaxed);
        SAT_CONFLICTS.fetch_add(now.conflicts.wrapping_sub(self.conflicts), Relaxed);
        SAT_DECISIONS.fetch_add(now.decisions.wrapping_sub(self.decisions), Relaxed);
        SAT_PROPAGATIONS.fetch_add(now.propagations.wrapping_sub(self.propagations), Relaxed);
    }
}

/// Every counter as `(name, nanoseconds, calls)`; the plain counts carry
/// their value in the `calls` slot with zero nanoseconds.
pub fn snapshot() -> Vec<(&'static str, u64, u64)> {
    let timed: [(&str, &Counter); N] = [
        ("run", &RUN),
        ("convert", &CONVERT),
        ("check", &CHECK),
        ("extremum", &EXTREMUM),
        ("enumerate", &ENUMERATE),
        ("eval", &EVAL),
        ("phase_lower_fp", &PHASE_LOWER_FP),
        ("phase_lower_str", &PHASE_LOWER_STR),
        ("phase_rewrite", &PHASE_REWRITE),
        ("phase_blast", &PHASE_BLAST),
        ("phase_sat", &PHASE_SAT),
        ("phase_model", &PHASE_MODEL),
        ("phase_prop_abs", &PHASE_PROP_ABS),
        ("engine_setup", &ENGINE_SETUP),
    ];
    let counts: [(&str, &AtomicU64); 7] = [
        ("engine_builds", &ENGINE_BUILDS),
        ("engine_forks", &ENGINE_FORKS),
        ("borrowed_queries", &BORROWED),
        ("rebuilds", &REBUILDS),
        ("sat_conflicts", &SAT_CONFLICTS),
        ("sat_decisions", &SAT_DECISIONS),
        ("sat_propagations", &SAT_PROPAGATIONS),
    ];
    timed
        .iter()
        .map(|(n, c)| (*n, c.ns.load(Relaxed), c.calls.load(Relaxed)))
        .chain(counts.iter().map(|(n, c)| (*n, 0, c.load(Relaxed))))
        .collect()
}
