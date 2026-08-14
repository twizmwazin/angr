//! smtrs-solver: the check-sat pipeline.
//!
//! Correctness first: every sat answer reconstructs a full model and (unless
//! disabled) validates it against the *original*, pre-rewrite assertions.
//!
//! The solver keeps a persistent `Engine` — SAT solver, AIG/blaster caches,
//! rewriter — alive across checks while the assertion set only grows;
//! assumptions become SAT-level assumption literals, so a query that differs
//! by one constraint costs one SAT call rather than a rebuild. On top of that
//! sit the operations symbolic execution actually leans on: `minimize`/
//! `maximize` (bit-fixing over the live engine, replacing claripy's ~64
//! round-trip binary search), `eval_n` (blocking-clause enumeration behind a
//! retired activation literal), `fork` (clone with learned clauses intact),
//! and a cooperative terminate flag for timeouts/interrupts.

mod abstraction;
mod preprocess;

use preprocess::preprocess;
use rustc_hash::FxHashMap;
use smtrs_bitblast::BitBlaster;
use smtrs_core::{eval, BvConst, Op, Sort, SymbolId, TermId, TermPool, Value};
use smtrs_rewrite::Rewriter;
/// Re-exported so a caller can read [`Solver::sat_counters`] without taking a
/// direct dependency on the SAT layer.
pub use smtrs_sat::SatCounters;
use smtrs_sat::{Backend, SatBackend, SatResult};

/// How far the term pool may grow during preprocessing before the run is
/// abandoned and redone conservatively (see `Rewriter::set_size_budget`).
///
/// Measured over the QF_BV corpus, healthy instances grow the pool by well
/// under a factor of two; the shape this exists to catch — a bit-reversal
/// network, where the mask boundaries double at every level — grows it by
/// more than two thousand. Anything in between is a judgement call, and the
/// factor is set far above the observed healthy maximum so that the retry
/// costs nothing on instances that were never in trouble. The additive slack
/// keeps small inputs (where a constant-factor budget would be a few hundred
/// nodes) from tripping on ordinary work.
fn rewrite_size_budget(initial_terms: usize) -> usize {
    const GROWTH: usize = 16;
    const SLACK: usize = 50_000;
    initial_terms.saturating_mul(GROWTH).saturating_add(SLACK)
}

#[derive(Clone, PartialEq, Eq, Debug)]
pub enum Answer {
    Sat,
    Unsat,
    Unknown(String),
}

impl std::fmt::Display for Answer {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Answer::Sat => write!(f, "sat"),
            Answer::Unsat => write!(f, "unsat"),
            Answer::Unknown(_) => write!(f, "unknown"),
        }
    }
}

/// Wall time spent in each stage, in seconds, **accumulated over every
/// `check_sat` on this solver** — unlike the sibling counters in
/// [`SolverStats`], which describe only the last check. Divide by
/// `SolverStats::checks` for a per-query figure, and do not read these as
/// attribution for one query of an incremental session.
///
/// The point of splitting these out is to answer, per benchmark, whether we
/// are *encode-bound* (rewriting/blasting dominates) or *search-bound* (the
/// SAT engine dominates) — the two call for completely different work.
#[derive(Default, Clone, Copy)]
pub struct PhaseTimes {
    pub lower_fp: f64,
    pub lower_str: f64,
    pub rewrite_preprocess: f64,
    pub blast: f64,
    pub sat: f64,
    pub model: f64,
    /// Boolean-skeleton fallback, only ever run on a path that would otherwise
    /// answer `unknown`.
    pub prop_abs: f64,
}

impl PhaseTimes {
    pub fn total(&self) -> f64 {
        self.lower_fp
            + self.lower_str
            + self.rewrite_preprocess
            + self.blast
            + self.sat
            + self.model
            + self.prop_abs
    }
}

#[derive(Default)]
pub struct SolverStats {
    pub checks: u64,
    /// Checks that could not reuse the persistent engine and rebuilt it from
    /// scratch. On a monotone incremental script this should be 1; anything
    /// higher means the whole preprocess-and-blast pipeline is being paid
    /// again per query, which is what the incremental tier is meant to avoid.
    ///
    /// Load-independent, so it is the number an A/B on incremental work should
    /// be read off first.
    pub rebuilds: u64,
    pub rewrites_applied: FxHashMap<&'static str, u64>,
    pub sat_vars: u32,
    pub aig_gates: u64,
    pub aig_strash_hits: u64,
    pub aig_folds: u64,
    pub terms: usize,
    pub assertions_blasted: usize,
    /// `post_order` calls and term nodes visited *inside model
    /// reconstruction*, summed over every check. Deterministic where the
    /// `model` phase time is not, so this is the number an A/B of anything
    /// touching model building should move.
    pub model_traversals: u64,
    pub model_visits: u64,
    pub phases: PhaseTimes,
    /// Term-node visits and traversals made against the shared pool, over its
    /// whole life rather than this solver's. Deterministic — a walk visits the
    /// same nodes however loaded the machine is — which is what makes it
    /// usable as A/B evidence where wall time is not.
    pub walk: smtrs_core::WalkCounters,
    /// SAT search counters after the last check (deterministic, unlike wall
    /// time — these are what A/B comparisons should be based on). `None` when
    /// the selected backend does not keep them, which is not the same as a
    /// search that had zero conflicts.
    pub sat_counters: Option<smtrs_sat::SatCounters>,
}

impl SolverStats {
    /// The `n` most-applied rewrite rules, ties broken by name so that two
    /// runs of the same input print the same list.
    pub fn top_rules(&self, n: usize) -> Vec<(&'static str, u64)> {
        let mut rules: Vec<(&'static str, u64)> = self
            .rewrites_applied
            .iter()
            .map(|(k, v)| (*k, *v))
            .collect();
        rules.sort_by_key(|&(k, v)| (std::cmp::Reverse(v), k));
        rules.truncate(n);
        rules
    }

    /// One-line JSON record (no dependency on a serialization crate).
    /// `wall` is the caller's end-to-end time, which includes parsing.
    pub fn to_json(&self, wall: f64) -> String {
        let p = &self.phases;
        let rules_json: Vec<String> = self
            .top_rules(15)
            .iter()
            .map(|(k, v)| format!("\"{k}\":{v}"))
            .collect();
        // The counter keys are always present so the record has one shape, but
        // a backend that keeps no counters reports JSON `null` rather than 0 —
        // 0 conflicts is a real and common outcome, and the two must not read
        // the same to a consumer.
        let counters_json = match &self.sat_counters {
            Some(c) => format!(
                "\"conflicts\":{},\"decisions\":{},\"propagations\":{},\"restarts\":{},\
\"prepro_vars_elim\":{},\"prepro_clauses_before\":{},\"prepro_clauses_after\":{},\
\"t_prepro\":{:.6},\"restored_vars\":{},\"reused_models\":{},\"reused_levels\":{}",
                c.conflicts,
                c.decisions,
                c.propagations,
                c.restarts,
                c.prepro_vars_elim,
                c.prepro_clauses_before,
                c.prepro_clauses_after,
                c.prepro_secs,
                c.restored_vars,
                c.reused_models,
                c.reused_levels,
            ),
            None => "\"conflicts\":null,\"decisions\":null,\"propagations\":null,\
\"restarts\":null,\"prepro_vars_elim\":null,\"prepro_clauses_before\":null,\
\"prepro_clauses_after\":null,\"t_prepro\":null,\"restored_vars\":null,\
\"reused_models\":null,\"reused_levels\":null"
                .to_string(),
        };
        format!(
            "{{\"wall\":{wall:.6},\"checks\":{},\"rebuilds\":{},\"terms\":{},\"assertions_blasted\":{},\"sat_vars\":{},\
\"aig_gates\":{},\"aig_strash_hits\":{},\"aig_folds\":{},\
\"model_traversals\":{},\"model_visits\":{},\
\"t_lower_fp\":{:.6},\"t_lower_str\":{:.6},\"t_rewrite\":{:.6},\"t_blast\":{:.6},\
\"t_sat\":{:.6},\"t_prop_abs\":{:.6},\"t_model\":{:.6},\"t_total\":{:.6},\
\"walk_visits\":{},\"walks\":{},\
{counters_json},\"rules\":{{{}}}}}",
            self.checks,
            self.rebuilds,
            self.terms,
            self.assertions_blasted,
            self.sat_vars,
            self.aig_gates,
            self.aig_strash_hits,
            self.aig_folds,
            self.model_traversals,
            self.model_visits,
            p.lower_fp,
            p.lower_str,
            p.rewrite_preprocess,
            p.blast,
            p.sat,
            p.prop_abs,
            p.model,
            p.total(),
            self.walk.visits,
            self.walk.walks,
            rules_json.join(",")
        )
    }
}

/// Render a set of Bool-sorted terms as a standalone SMT-LIB script, for
/// eyeballing an over-approximation or cross-checking it against another
/// solver. Debugging aid; reached only through an environment variable.
fn dump_smt2(pool: &TermPool, roots: &[TermId]) -> String {
    let mut decls: Vec<String> = Vec::new();
    let mut seen: FxHashMap<SymbolId, ()> = FxHashMap::default();
    pool.post_order(roots, |pool, t| {
        if let Op::Var(s) = pool.op(t) {
            if seen.insert(s, ()).is_none() {
                let sym = pool.symbol(s);
                decls.push(format!("(declare-fun {} () {})", sym.name, sym.sort));
            }
        }
    });
    let asserts: Vec<String> = roots
        .iter()
        .map(|&r| format!("(assert {})", pool.display(r)))
        .collect();
    format!(
        "(set-logic QF_BV)\n{}\n{}\n(check-sat)",
        decls.join("\n"),
        asserts.join("\n")
    )
}

/// What [`Solver::unsat_core`] may say about the last check.
#[derive(Clone, PartialEq, Eq, Debug)]
enum CoreState {
    /// No `unsat` since the last check started, or core tracking is off.
    Absent,
    /// Activation symbols of the tracked assertions in the core.
    Core(Vec<SymbolId>),
    /// The answer was `unsat`, but it came from somewhere a core cannot be
    /// read from. Refusing is the only correct option: a core assembled from
    /// the wrong engine is a wrong answer, and the whole named set — while
    /// trivially sound — is not what a caller asked for and would hide the
    /// fact that nothing was actually computed.
    Refused(&'static str),
}

/// How a tracked assertion's activation literal survived encoding.
///
/// Preprocessing can substitute a variable away, so an activation literal does
/// not automatically survive as itself. Writing out what it can turn into is
/// what keeps "it is not in the circuit" from being read as "it is not needed".
///
/// Only `Lit` and `Refuted` should be reachable, and the argument is a case
/// analysis on `defining_equality` (`preprocess.rs`), whose three shapes are
/// the only way a variable becomes a definition. Let `R` be the guard
/// `act -> phi` after rewriting.
///
/// * `R = x`: taking `act` false makes the guard true, so `R` would have to be
///   a tautology — a variable is not.
/// * `R = not x`: with `x = act` this needs `phi |= not act`, and `act` is
///   fresh and absent from `phi`, so `phi` is `false` — the `Refuted` case.
///   With `x` any other variable the same tautology argument applies.
/// * `R = (= x v)`: with `x = act`, taking `act` false forces `not v` to be a
///   tautology, so `v` is `false` and again `Refuted`. With `x` some other
///   variable, `act` is not the one being defined and survives; if `v` mentions
///   `act`, the substitution is a no-op at `act = false` and the guard is still
///   switchable.
///
/// `Forced` and `Rewritten` are the two ways that argument could be wrong.
/// Neither is a wrong answer: one over-approximates the core, the other
/// refuses it.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum ActLit {
    /// It reached the circuit as this SAT literal, and assuming it turns the
    /// tracked assertion on.
    Lit(smtrs_sat::Lit),
    /// Preprocessing proved the activation literal *false*: the guard
    /// `act -> phi` collapsed to `not act`, which happens exactly when `phi`
    /// rewrote to `false`. That assertion is a one-element core by itself.
    Refuted,
    /// The activation literal disappeared into `true`, so the assertion is in
    /// the formula unconditionally and cannot be switched off. Reported as
    /// always-in-the-core, which over-approximates rather than guesses.
    Forced,
    /// Preprocessing replaced the activation literal by something that is
    /// neither itself nor a constant. Assuming this literal still enables the
    /// assertion — it is what the definition says `act` equals — but the
    /// failed-assumption set would then be about a literal the caller never
    /// named, so the core is refused.
    Rewritten(smtrs_sat::Lit),
}

pub struct Solver {
    /// Assertion stack: (assertion, push-level alive marker via levels).
    assertions: Vec<TermId>,
    /// The assertions exactly as asserted, before any theory lowering.
    ///
    /// `assertions` is *replaced* by the string lowering with a vector of a
    /// different length — the rewritten roots followed by the encoding's own
    /// side constraints — while `levels` goes on holding indices into the
    /// pre-lowering vector. A `pop` then truncates to one of those stale
    /// indices and deletes every side constraint, leaving the lowered
    /// assertions with nothing defining their encoding variables. That was a
    /// wrong `sat`: asserting `(= (str.len s) 3)`, pushing, popping, and then
    /// asserting `(= (str.len s) 5)` answered `sat`.
    ///
    /// Keeping the originals lets `pop` restore a set that `levels` really does
    /// index, and re-lower from there. The cost is one re-lowering per `pop` on
    /// string problems, which already forced a full engine rebuild anyway.
    pristine: Vec<TermId>,
    levels: Vec<usize>,
    /// Per entry of `assertions`: the activation symbol and the *unguarded*
    /// formula the user asserted, or `None` for an untracked assertion. Same
    /// length as `assertions`. Empty and untouched unless core tracking is on.
    ///
    /// The unguarded form is kept because the over-approximation fallbacks
    /// must reason about the problem as stated, not about `act -> phi`.
    tracked: Vec<Option<(SymbolId, TermId)>>,
    /// Core tracking is on. Off by default and deliberately so: guarding every
    /// assertion with an activation literal blocks the top-level equality
    /// substitution that `preprocess` runs on it, which is a real encoding
    /// cost on a solver whose median query is milliseconds.
    produce_cores: bool,
    /// Core of the last `unsat`.
    core: CoreState,
    /// This solver's assertions have been through the bounded-string lowering.
    /// Sticky, because the lowering replaces `assertions` once and every later
    /// check runs against the lowered form. See [`Solver::set_core`].
    string_lowered: bool,
    /// Set once the FP lowering has replaced `assertions` with their
    /// word-blasted bit-vector forms.
    ///
    /// Unlike the string lowering this preserves the assertion *count*, so
    /// `levels` stays valid and `push`/`pop` were never affected. What it does
    /// change is the terms: after it, `f` in an existing assertion is a
    /// bit-vector, so asserting more FP content and lowering only the new
    /// formula gives the two occurrences of `f` different variables and they
    /// never meet. `(fp.lt f g)` then `(fp.lt g f)` answered `sat` — and the
    /// same severing reaches a check through raw theory content in its
    /// *assumptions*, which never pass through `assert`; the lowering
    /// branches below consult this flag and restore the pristine assertions
    /// first so everything is lowered in one consistent run.
    fp_lowered: bool,
    /// Model from the last sat answer (complete over `declared`).
    model: Option<FxHashMap<SymbolId, Value>>,
    /// All 0-ary symbols that should appear in models.
    pub declared: Vec<SymbolId>,
    pub validate_models: bool,
    pub stats: SolverStats,
    /// Persistent solving state. Survives a growing assertion set, and — once
    /// it is built guarded (see [`Engine::acts`] and [`GUARD_AFTER_POPS`]) — a
    /// `pop` as well. A change of assertion *identity*, i.e. string or
    /// floating-point lowering rewriting the whole set, still discards it.
    engine: Option<Engine>,
    /// Cooperative termination flag, installed into every engine.
    terminate: Option<std::sync::Arc<std::sync::atomic::AtomicBool>>,
    /// False when the problem was encoded under a bound (bounded strings), so
    /// an `unsat` from the SAT engine only means "no model within the bound"
    /// and must be reported as `unknown`.
    unsat_trustworthy: bool,
    /// Assertions plus assumptions of the current check, as they were *before*
    /// any lowering. The Boolean-skeleton fallback needs the original formula,
    /// and several `unknown` paths are reached only after `assertions` has
    /// already been replaced by its lowering.
    orig_roots: Vec<TermId>,
    /// The last check's assumptions in the form the engine actually solved:
    /// identical to what the caller passed when no theory lowering ran, the
    /// lowered forms otherwise. The bit-level operations that follow a check
    /// (`minimize`/`maximize`/`eval_n`) re-literalize the assumptions against
    /// the engine, and the engine speaks post-lowering Bool/BV — handing it a
    /// raw `fp.*` or `str.*` term is a blaster panic.
    lowered_assumptions: Vec<TermId>,
    /// When the current check started, so that the last-resort
    /// over-approximations can be given a budget proportional to what the
    /// attempt they are backstopping has already spent.
    check_start: std::time::Instant,
    /// How long the first encoding may take before the alternative one (the
    /// same formula with the flattening sharing guard off) is skipped, in
    /// seconds. Zero builds only the guarded encoding. Seeded from
    /// `SMTRS_DUAL_ENCODE`; a field rather than an env read per check so tests
    /// can drive both sides without a process-global switch.
    dual_encode_max_secs: f64,
    /// Cached DAG analysis of the assertion prefix; see [`PrefixScan`].
    scan: PrefixScan,
    /// Push levels retired so far. Guarded mode is engaged once this reaches
    /// [`GUARD_AFTER_POPS`]; see [`Solver::guard_levels`].
    pops: u32,
    /// Consecutive guarded engines collected before they had amortised their
    /// construction. See [`Solver::guard_futile`].
    futile_collections: u8,
    /// Guarding has been switched back off for this solver, permanently.
    ///
    /// [`Engine::retired_dominates`] collects a guarded engine once its
    /// retired levels outweigh its live ones. If that keeps happening before
    /// the engine has answered [`MIN_CHECKS_PER_ENGINE`] queries, each round
    /// is about as big as the base: there is no large shared encoding for the
    /// guard to protect, and guarding buys a rebuild per round or two while
    /// charging every query the enlarged formula. That is the shape of the
    /// highest-`pop` scripts in the corpus (`sum_10x0_true` runs 4 069 rounds
    /// over a 274-variable formula) and of the search-bound BMC unrollings
    /// (`VexRiscv-regch0-20`), and for both the honest answer is the old path,
    /// exactly.
    guard_futile: bool,
}

/// Premature collections in a row before guarding is abandoned for good (see
/// [`Solver::guard_futile`]). More than one, so a single unrepresentative round
/// does not decide it; small, so a script that is never going to benefit stops
/// paying almost immediately.
const GUARD_FUTILE_STREAK: u8 = 3;

/// How many `pop`s a script must do before its push levels are encoded under
/// activation literals (see [`Engine::acts`]) instead of being retired by
/// rebuilding the engine.
///
/// Guarding is not free: substitution rewrites the terms of every assertion
/// around a definition, so a retractable level cannot supply one, and the
/// preprocessor's reach shrinks to the base level. Making that trade needs
/// evidence that the script is going to keep popping, and the threshold is
/// what that evidence costs.
///
/// **One pop is not evidence.** The engine a first pop finds was built by a
/// preprocessor that could draw definitions from the level being retracted, so
/// that engine has to go whatever we do — guarding cannot save that rebuild,
/// it can only make the *next* pop cheap. Engaging at one pop therefore pays
/// the encoding penalty immediately and collects nothing until a second pop
/// arrives — and of the 738 files in the incremental tier that pop at all,
/// **352 stop at exactly two**, so for nearly half of them the penalty is the
/// whole story. Measured on the two-round `push/check-sat/pop` script
/// `20190307-CPAchecker_kInduction/32_1_cilled_…marvell.ko`: engaging at the
/// first pop encodes 1 310 SAT variables where rebuilding encodes 312 — 4.2x,
/// for zero rebuilds saved.
///
/// **Two is.** A script that has popped twice is running a loop, and the loop
/// is what the machinery is for. The price is one extra rebuild, and the
/// repeating shapes run 4 to 7 267 rounds, so it is amortised immediately.
///
/// (Counts from the 2 503 files of `corpus/incremental/incremental/QF_BV`
/// under 4 MB: 1 765 never pop, 45 pop once, 352 pop twice, 316 pop 4-10
/// times, 25 pop more.)
const GUARD_AFTER_POPS: u32 = 2;

/// Floor and ceiling on the time the length abstraction may spend. See
/// [`Solver::unknown_or_prop_unsat`].
const MIN_ABS_BUDGET: std::time::Duration = std::time::Duration::from_millis(250);
const MAX_ABS_BUDGET: std::time::Duration = std::time::Duration::from_secs(2);

struct Engine {
    sat: Backend,
    blaster: BitBlaster,
    rewriter: Rewriter,
    /// Prefix of `Solver::assertions` already blasted into `sat`.
    blasted: Vec<TermId>,
    /// Eliminated variables (from preprocessing), recording order.
    defs: Vec<(SymbolId, TermId)>,
    /// Raw substitution map (var term -> per-round RHS) applied to everything
    /// that arrives after the initial preprocess. RHS chains have depth at
    /// most `subst_rounds`, so `apply_subst` iterates to a fixpoint.
    subst: FxHashMap<TermId, TermId>,
    subst_rounds: u32,
    /// An asserted formula that can never be retracted rewrote to false: unsat
    /// for good. A formula inside a guarded push level that does the same
    /// retires *its level* instead (a unit `¬act`), which is a fact about the
    /// level and dies with it.
    hard_unsat: bool,
    /// One entry per open push level, outermost first.
    ///
    /// Popping a level adds the permanent unit `¬act`, which retires its
    /// clauses in place. Without it a pop had to discard the whole engine, and
    /// a BMC script that brackets each query with `push`/`pop` — which is most
    /// of the incremental tier — paid a full preprocess-and-blast per query
    /// and threw away every learned clause with it.
    ///
    /// Learned clauses stay valid across the retirement: adding `¬act` only
    /// strengthens the clause database, and everything learned from it was
    /// already implied by the weaker one.
    ///
    /// Empty unless this engine was *built* guarded, which is what makes the
    /// unguarded mode byte-for-byte the old encoding rather than a special
    /// case of this one.
    acts: Vec<Level>,
    /// SAT variables belonging to levels already retired. Retiring a level
    /// leaves its clauses in the database — satisfied, but still there — so
    /// this is how much of the engine is dead weight, and it is what
    /// [`Engine::retired_dominates`] weighs against the live part.
    retired_vars: u32,
    /// This engine was built with push levels held back from preprocessing, so
    /// its levels can be retired in place. Recorded on the engine rather than
    /// read off the solver at pop time, because it is a property of *how this
    /// circuit was encoded*: an engine built before guarding was engaged has
    /// definitions drawn from levels that are still open, and retiring one of
    /// those in place would leave the definitions behind.
    guarded: bool,
    /// `SolverStats::checks` when this engine was built, so that collecting it
    /// can say how many queries it answered. See [`Solver::guard_futile`].
    checks_at_build: u64,
    /// Activation literal per tracked assertion, in this engine's variable
    /// numbering. Cached because the mapping is a property of the engine, not
    /// of the check: it must not change between the solve that produced a core
    /// and the one that verifies it, and freezing a variable twice would grow
    /// the SAT solver's pinned list on every incremental query.
    act_lits: FxHashMap<SymbolId, ActLit>,
}

/// An open push level inside a guarded [`Engine`].
#[derive(Clone, Copy)]
struct Level {
    /// Length `blasted` had when the level was opened.
    start: usize,
    /// The literal everything asserted inside the level is blasted under.
    /// Allocated on first use, so a level that asserts nothing — or asserts
    /// only formulas that rewrite to `true` — costs no variable and no
    /// assumption.
    act: Option<smtrs_sat::Lit>,
    /// SAT variable count when the level was opened. The difference against
    /// the count at pop time is what the level cost, and therefore what
    /// retiring it strands in the clause database.
    vars_at_open: u32,
}

/// Checks a guarded engine must answer before its construction counts as
/// amortised. Below this, [`Solver::guard_futile`] starts counting against it.
///
/// The trade guarding makes is fewer rebuilds in exchange for a slightly
/// larger query formula (retired levels are satisfied, not deleted — see
/// [`Engine::retired_dominates`]). An engine collected without having answered
/// more than one query saved no rebuild at all and charged the enlargement to
/// the one query it did answer, which is a pure loss.
const MIN_CHECKS_PER_ENGINE: u64 = 2;

/// How much dead weight a guarded engine may carry, as a percentage of its
/// live encoding, before [`Engine::retired_dominates`] collects it.
///
/// This is the whole risk budget of the change, so it is set by what may be
/// risked rather than by what could be gained. Retired levels are satisfied
/// clauses, not deleted ones, and their Tseitin cones are unguarded — every
/// query still assigns those variables. So this number *is* the ceiling on
/// how much bigger a query gets than it was under the old rebuild-per-pop
/// path, and 25 % is chosen to keep that ceiling small on a change whose
/// benefit could not be timed.
///
/// It was 100 % first, and the instance that argued it down is
/// `2018-Wolf-fmbench/VexRiscv-regch0-20-unrolled`: 21 propagation-only checks
/// followed by one five-million-conflict proof. At 100 % its formula reached
/// 1.34x and that final proof went from `unsat` to `unknown` under a 300 s
/// per-check budget — the old path closes it within 5 026 783 conflicts, the
/// enlarged one had not closed it after 8 620 128. A rebuild it does not need
/// costs that instance a fraction of a second; a formula it does not need
/// costs it the answer.
const COLLECT_MAX_DEAD_PERCENT: u32 = 25;

/// Whether a guarded engine reached [`Engine::retired_dominates`] without ever
/// having amortised its construction — the signal [`Solver::guard_futile`]
/// counts.
///
/// Measured in *checks answered*, not in pops. A persistent engine earns its
/// construction by answering queries; scripts that pop several times between
/// two `check-sat`s are common (`gcd_1` pops 1 097 times across 785 checks),
/// and counting pops would read those engines as long and productive.
fn collected_too_soon(checks_now: u64, e: &Engine) -> bool {
    e.guarded && checks_now.saturating_sub(e.checks_at_build) < MIN_CHECKS_PER_ENGINE
}

impl Engine {
    /// The clone starts without the parent's interrupt, matching the SAT
    /// backend (see `smtrs_cdcl::Solver::try_clone`). Inheriting it would
    /// also inherit the *sticky* "already interrupted" bit, which would leave
    /// the fork permanently answering `unknown`.
    fn try_clone(&self) -> Option<Engine> {
        let mut blaster = self.blaster.clone();
        blaster.clear_terminate();
        let mut rewriter = self.rewriter.clone();
        rewriter.clear_terminate();
        Some(Engine {
            sat: self.sat.try_clone()?,
            blaster,
            rewriter,
            blasted: self.blasted.clone(),
            defs: self.defs.clone(),
            subst: self.subst.clone(),
            subst_rounds: self.subst_rounds,
            hard_unsat: self.hard_unsat,
            act_lits: self.act_lits.clone(),
            acts: self.acts.clone(),
            retired_vars: self.retired_vars,
            guarded: self.guarded,
            checks_at_build: self.checks_at_build,
        })
    }

    /// Activation literals of the open push levels. Every solve has to assume
    /// these, or the clauses they guard carry no force at all.
    fn live_acts(&self) -> Vec<smtrs_sat::Lit> {
        self.acts.iter().filter_map(|l| l.act).collect()
    }

    /// The activation literal covering the assertion at index `idx`, creating
    /// it if this is the level's first blasted assertion. `None` for the base
    /// level, whose assertions are never retracted.
    fn guard_for(&mut self, idx: usize) -> Option<smtrs_sat::Lit> {
        let k = self.acts.iter().rposition(|l| l.start <= idx)?;
        if self.acts[k].act.is_none() {
            let v = self.sat.new_var();
            // The level literal is assumed on every solve for as long as the
            // level is open, and a unit `¬v` retires it. Both work on an
            // eliminated variable — `add_clause` restores it — but pinning it
            // keeps CNF preprocessing from doing that work and then undoing it.
            self.sat.freeze_var(v);
            self.acts[k].act = Some(v);
        }
        self.acts[k].act
    }

    /// Has this engine accumulated more dead weight than
    /// [`COLLECT_MAX_DEAD_PERCENT`] of its live encoding?
    ///
    /// Retiring a level does not remove its clauses, it satisfies them, so a
    /// script that runs thousands of `push`/`check-sat`/`pop` rounds against
    /// one engine accumulates every round it has ever run. Left alone that
    /// turns a fixed-size query into one whose clause database grows without
    /// bound: measured on `20170501-Heizmann/sum_10x0_true`, 4 069 rounds over
    /// a 274-variable formula end at 142 264 variables, and the search pays for
    /// all of them on every query.
    ///
    /// So the engine is dropped and rebuilt once the dead part passes its
    /// share. That is the standard amortised-collection bound, and it replaces
    /// a hope with two guarantees: the database never exceeds the live formula
    /// by more than that share, and total encoding work becomes proportional
    /// to what the script asserts rather than to (rounds x whole formula). On
    /// the shape this machinery exists for — a large base with a sliver added
    /// per round — the trigger is reached rarely and rebuilds still collapse.
    ///
    /// The estimate is deliberately loose in one direction only. A
    /// `vars_at_open` delta counts structure that later levels share and
    /// therefore keep alive, and nested levels retired by separate `pop` calls
    /// are charged twice. Both make the dead part look bigger than it is, so
    /// the engine is collected slightly early — which is a step back towards
    /// the old rebuild-per-pop behaviour, the safe direction to be wrong in.
    fn retired_dominates(&self) -> bool {
        let total = u64::from(self.sat.num_vars());
        let dead = u64::from(self.retired_vars);
        dead * 100 > total.saturating_sub(dead) * u64::from(COLLECT_MAX_DEAD_PERCENT)
    }
}

/// Conflicts after which the CDCL search is interrupted once and immediately
/// re-entered, or `None` to run it straight through (`SMTRS_HARD_RESTART=0`).
///
/// Re-entering `solve` keeps every learned clause and every variable activity
/// but resets the Luby restart sequence to its first, shortest interval — a
/// *hard restart*, in the sense that the schedule starts over rather than
/// continuing to stretch. On instances where 20 000 conflicts have already
/// pushed the Luby interval into the tens of thousands, that is the difference
/// between diversifying and grinding, and it costs nothing on instances the
/// search closes inside the budget: they never reach the interrupt.
fn hard_restart_at() -> Option<u64> {
    let v = std::env::var("SMTRS_HARD_RESTART");
    match v.as_deref() {
        Ok("0") => None,
        Ok(s) => s.parse().ok().or(Some(20_000)),
        Err(_) => Some(20_000),
    }
}

/// How long the *first* encoding may take before the alternative one is
/// skipped, in seconds. `SMTRS_DUAL_ENCODE=0` disables the second encoding
/// entirely, which is what makes the change a clean A/B against itself.
///
/// The bound is on the first encoding's own cost rather than on a fraction of
/// the search budget, because the solver is handed a terminate flag and not a
/// deadline. The default is deliberately small: at 0.5 s a Sage2 sample paid
/// 40 % more wall time for nothing, because that family encodes in a few
/// hundred milliseconds and doubling it is the whole run. Instances where
/// encoding *is* the difficulty (a 3.2 M-term Labyrinth expansion, the
/// `bitrev*` family) exceed any such cap on the first pass and never pay it.
fn dual_encode_max_secs() -> f64 {
    match std::env::var("SMTRS_DUAL_ENCODE").as_deref() {
        Ok("0") => 0.0,
        Ok(s) => s.parse().ok().unwrap_or(0.05),
        Err(_) => 0.05,
    }
}

fn apply_subst(
    pool: &mut TermPool,
    subst: &FxHashMap<TermId, TermId>,
    rounds: u32,
    t: TermId,
) -> TermId {
    let mut cur = t;
    for _ in 0..=rounds {
        let next = pool
            .substitute(cur, subst)
            .expect("substitution is sort-preserving");
        if next == cur {
            break;
        }
        cur = next;
    }
    cur
}

/// Everything the `check_sat` prologue needs to know about a term DAG.
///
/// Four questions — is there a string in here, is there a float, is there
/// anything outside the Bool/BV fragment, and which variables need a value in
/// the model — used to be four independent full post-orders over
/// `assertions + assumptions`, on every single check. Each is *node-local*: it
/// reads `pool.op(t)` and `pool.sort(t)` and nothing else. So one traversal
/// answers all four, and a node already accounted for cannot change any answer
/// by being visited again.
#[derive(Default)]
struct WalkFacts {
    has_strings: bool,
    has_fp: bool,
    /// The first term found outside the Bool/BV fragment, in post-order — the
    /// same one the full walk latched. Kept as a term rather than as a message
    /// so the supported case never formats one.
    unsupported: Option<TermId>,
    /// `Op::Var` symbols met on this walk, in traversal order. A symbol appears
    /// at most once: `pool.var` interns `Op::Var(sym)` with the symbol's own
    /// sort, so one symbol is one term, and each term is visited at most once.
    vars: Vec<SymbolId>,
}

/// Stamp meaning "reachable from the cached assertion prefix". Query walks use
/// marks from 2 upwards, so a prefix node is skipped by every query.
const PREFIX_MARK: u32 = 1;

/// Cached whole-DAG analysis of a prefix of the assertion stack.
///
/// In the workload this solver exists for — angr replaying a stream of
/// feasibility queries against one long-lived solver — the assertions are fixed
/// and only the assumptions change, so all four answers above are the same on
/// every call. Keeping them, together with the set of terms they were derived
/// from, turns a per-query walk of the whole path condition into a walk of the
/// one new constraint.
///
/// **Why it is allowed to be a cache.** The four facts are monotone unions over
/// the node set: adding a term can turn `has_strings` on but never off, and can
/// add a model symbol but never retract one. So extending the prefix is folding
/// one more walk's facts in. Retracting the prefix is *not* expressible that
/// way, and no attempt is made: [`PrefixScan::refresh`] throws the whole cache
/// away the moment the live assertion vector stops extending the cached one,
/// which is exactly what `pop` does to it.
///
/// **Why the stamps stay valid.** Terms are interned and never mutated or
/// removed, so `stamp[t] == PREFIX_MARK` — "t and everything under it is
/// already folded in" — cannot go stale while the prefix stands. It is dropped
/// wholesale with the rest of the cache when the prefix does not.
#[derive(Clone, Default)]
struct PrefixScan {
    /// Copy of the assertion prefix these facts cover. The live `assertions`
    /// must still start with it for the cache to be reusable — a check that
    /// catches `pop`'s truncation without `pop` having to know this exists.
    asserts: Vec<TermId>,
    /// Likewise for `declared`, which is public and may be assigned to.
    declared: Vec<SymbolId>,
    /// `stamp[t] == PREFIX_MARK` when `t` is reachable from `asserts`, and
    /// equals the current query's mark when it was reached from this query's
    /// assumptions.
    stamp: Vec<u32>,
    /// Mark used by the last query walk; the next one gets `mark + 1`.
    mark: u32,
    /// Parked DFS stack, so a query costs no allocation.
    stack: Vec<(TermId, bool)>,
    has_strings: bool,
    has_fp: bool,
    unsupported: Option<TermId>,
    /// Symbols needing a model value: `declared` first (as before), then the
    /// variables reachable from `asserts`, deduplicated.
    model_syms: Vec<SymbolId>,
    seen_syms: rustc_hash::FxHashSet<SymbolId>,
}

impl PrefixScan {
    fn clear(&mut self) {
        self.asserts.clear();
        self.declared.clear();
        // Emptying the stamp array is load-bearing, not tidying: `walk` only
        // ever *grows* it, so anything left behind would read as already
        // folded in and the rebuild would skip it — losing whatever fact that
        // term carried. See `prefix_scan_rebuild_rewalks_already_stamped_terms`.
        self.stamp.clear();
        self.mark = PREFIX_MARK;
        self.has_strings = false;
        self.has_fp = false;
        self.unsupported = None;
        self.model_syms.clear();
        self.seen_syms.clear();
    }

    /// One post-order sweep over `roots`, stamping each term with `mark` and
    /// collecting the node-local facts of every term not already covered.
    ///
    /// Post-order, in `TermPool::post_order`'s exact order, even though nothing
    /// here needs children before parents: it is what makes "the first
    /// unsupported term" the same term the four separate walks reported.
    fn walk(&mut self, pool: &TermPool, roots: &[TermId], mark: u32) -> WalkFacts {
        if self.stamp.len() < pool.num_terms() {
            self.stamp.resize(pool.num_terms(), 0);
        }
        let stamp = &mut self.stamp;
        let stack = &mut self.stack;
        let mut facts = WalkFacts::default();
        let mut visits = 0u64;
        stack.clear();
        stack.extend(roots.iter().rev().map(|&r| (r, false)));
        while let Some((t, children_done)) = stack.pop() {
            let s = stamp[t.0 as usize];
            // A prefix-stamped term has every descendant stamped too
            // (reachability), so not descending into it is safe.
            if s == PREFIX_MARK || s == mark {
                continue;
            }
            if children_done {
                stamp[t.0 as usize] = mark;
                visits += 1;
                let sort = pool.sort(t);
                let op = pool.op(t);
                if matches!(sort, Sort::Str | Sort::RegLan) {
                    facts.has_strings = true;
                }
                if op.is_fp() || matches!(sort, Sort::Float(..) | Sort::RoundingMode) {
                    facts.has_fp = true;
                }
                if let Op::Var(sym) = op {
                    facts.vars.push(sym);
                }
                if facts.unsupported.is_none() && Solver::unsupported_node(pool, t) {
                    facts.unsupported = Some(t);
                }
            } else {
                stack.push((t, true));
                for &c in pool.args(t).iter().rev() {
                    let cs = stamp[c.0 as usize];
                    if cs != PREFIX_MARK && cs != mark {
                        stack.push((c, false));
                    }
                }
            }
        }
        pool.record_walk(visits);
        facts
    }

    /// Fold `roots` into the persistent prefix.
    fn extend_prefix(&mut self, pool: &TermPool, roots: &[TermId]) {
        let f = self.walk(pool, roots, PREFIX_MARK);
        self.has_strings |= f.has_strings;
        self.has_fp |= f.has_fp;
        // `or`, not `unwrap_or`: an earlier assertion's offending term comes
        // first in the walk of the whole set, so it is the one to report.
        self.unsupported = self.unsupported.or(f.unsupported);
        for s in f.vars {
            if self.seen_syms.insert(s) {
                self.model_syms.push(s);
            }
        }
    }

    /// Bring the cache up to date with `assertions` and `declared`, rebuilding
    /// from scratch if the live vectors no longer extend the cached ones.
    fn refresh(&mut self, pool: &TermPool, assertions: &[TermId], declared: &[SymbolId]) {
        let extends = assertions.len() >= self.asserts.len()
            && assertions[..self.asserts.len()] == self.asserts[..]
            && declared.len() >= self.declared.len()
            && declared[..self.declared.len()] == self.declared[..]
            // Query marks are never reused, so a term stamped by an earlier
            // query reads as unvisited now. On the (unreachable in practice)
            // wrap, throw the cache away rather than believe a stale stamp.
            && self.mark < u32::MAX;
        if !extends {
            self.clear();
        }
        // `declared` is folded in before the assertion walk so that a solver
        // configured the usual way — declarations, then assertions, then checks
        // — produces exactly the model-symbol order the from-scratch walk did.
        let n_declared = self.declared.len();
        if declared.len() > n_declared {
            for &s in &declared[n_declared..] {
                if self.seen_syms.insert(s) {
                    self.model_syms.push(s);
                }
            }
            self.declared.extend_from_slice(&declared[n_declared..]);
        }
        if assertions.len() > self.asserts.len() {
            // `assertions` is the caller's slice, not borrowed from `self`, so
            // the new tail can be walked in place rather than copied first.
            let n = self.asserts.len();
            self.extend_prefix(pool, &assertions[n..]);
            self.asserts.extend_from_slice(&assertions[n..]);
        }
    }

    /// Answer the four questions for `assertions + assumptions`, walking only
    /// what the prefix does not already cover.
    fn query(&mut self, pool: &TermPool, assumptions: &[TermId]) -> QueryFacts {
        self.mark = self.mark.max(PREFIX_MARK) + 1;
        let mark = self.mark;
        let f = self.walk(pool, assumptions, mark);
        let mut model_syms = Vec::with_capacity(self.model_syms.len() + f.vars.len());
        model_syms.extend_from_slice(&self.model_syms);
        model_syms.extend(f.vars.iter().filter(|s| !self.seen_syms.contains(s)));
        QueryFacts {
            has_strings: self.has_strings || f.has_strings,
            has_fp: self.has_fp || f.has_fp,
            unsupported: self.unsupported.or(f.unsupported),
            model_syms,
        }
    }
}

/// Facts about one check's roots: the cached prefix answers, widened by
/// whatever the assumptions on top of them contribute.
struct QueryFacts {
    has_strings: bool,
    has_fp: bool,
    unsupported: Option<TermId>,
    /// `declared`, then the variables reachable from the assertions, then those
    /// only the assumptions reach — the order the from-scratch walk produced.
    model_syms: Vec<SymbolId>,
}

impl Default for Solver {
    fn default() -> Self {
        Self::new()
    }
}

impl Solver {
    pub fn new() -> Self {
        Solver {
            assertions: Vec::new(),
            pristine: Vec::new(),
            levels: Vec::new(),
            tracked: Vec::new(),
            produce_cores: false,
            core: CoreState::Absent,
            string_lowered: false,
            fp_lowered: false,
            model: None,
            declared: Vec::new(),
            validate_models: true,
            stats: SolverStats::default(),
            engine: None,
            terminate: None,
            unsat_trustworthy: true,
            orig_roots: Vec::new(),
            lowered_assumptions: Vec::new(),
            check_start: std::time::Instant::now(),
            dual_encode_max_secs: dual_encode_max_secs(),
            scan: PrefixScan::default(),
            pops: 0,
            futile_collections: 0,
            guard_futile: false,
        }
    }

    /// Install a cooperative termination flag (settable from other threads or
    /// signal handlers); a running check returns `unknown` shortly after.
    pub fn set_terminate(&mut self, flag: std::sync::Arc<std::sync::atomic::AtomicBool>) {
        if let Some(e) = &mut self.engine {
            e.sat.set_terminate(flag.clone());
            e.rewriter.set_terminate(flag.clone());
            e.blaster.set_terminate(flag.clone());
        }
        self.terminate = Some(flag);
    }

    /// Rewriting or bit-blasting was cut short. Everything downstream of an
    /// interrupted encoding is untrustworthy — the rewriter may have left ops
    /// the blaster cannot encode, and the blaster may have substituted
    /// placeholder literals for whole subterms — so the engine is thrown away
    /// and the answer is `unknown`. Deliberately not routed through
    /// `unknown_or_prop_unsat`: the Boolean skeleton is another solve, and we
    /// are out of budget by construction.
    fn interrupted_answer(&mut self) -> Answer {
        self.engine = None;
        Answer::Unknown("interrupted".into())
    }

    /// Fork the solver, preserving learned state where the SAT backend
    /// supports it (cdcl); otherwise the fork lazily rebuilds on its next
    /// check. Terms live in the shared TermPool, so forks stay cheap.
    pub fn fork(&self) -> Solver {
        Solver {
            assertions: self.assertions.clone(),
            pristine: self.pristine.clone(),
            levels: self.levels.clone(),
            tracked: self.tracked.clone(),
            produce_cores: self.produce_cores,
            core: self.core.clone(),
            string_lowered: self.string_lowered,
            fp_lowered: self.fp_lowered,
            model: self.model.clone(),
            declared: self.declared.clone(),
            validate_models: self.validate_models,
            stats: SolverStats::default(),
            engine: self.engine.as_ref().and_then(Engine::try_clone),
            terminate: None,
            unsat_trustworthy: self.unsat_trustworthy,
            orig_roots: self.orig_roots.clone(),
            lowered_assumptions: self.lowered_assumptions.clone(),
            check_start: std::time::Instant::now(),
            dual_encode_max_secs: dual_encode_max_secs(),
            // The fork's assertions and declarations are the parent's, so the
            // parent's analysis of them is the fork's too. The two copies then
            // diverge over a shared pool, which is fine: each is validated
            // against its own solver's assertion vector.
            scan: self.scan.clone(),
            pops: self.pops,
            futile_collections: self.futile_collections,
            guard_futile: self.guard_futile,
        }
    }

    pub fn assert(&mut self, t: TermId) {
        self.undo_lowering();
        self.assertions.push(t);
        self.pristine.push(t);
        if self.produce_cores {
            self.tracked.push(None);
        }
    }

    /// Put `assertions` back to what the user asserted, discarding any theory
    /// lowering held over from a previous check.
    ///
    /// Needed wherever the assertion set changes, because a lowering leaves
    /// `assertions` holding rewritten roots plus the encoding's side
    /// constraints. Appending a raw term to *that* produces a set that is
    /// half-lowered and half not, which the next lowering pass then runs over
    /// again — the second `push`/`assert`/`pop` cycle on a string problem
    /// answered `sat` where a fresh solver said `unsat`.
    ///
    /// Cheap in the case that matters: no lowering has run on the overwhelming
    /// majority of problems, and the flag is false.
    fn undo_lowering(&mut self) {
        if self.string_lowered || self.fp_lowered {
            self.string_lowered = false;
            self.fp_lowered = false;
            self.unsat_trustworthy = true;
            self.engine = None;
            self.assertions = self.pristine.clone();
            // The lowerings pad `tracked` out to the lowered length (side
            // constraints belong to no named assertion); put it back in step
            // with the restored originals so the next tracked assert stays
            // aligned with its index.
            self.tracked.truncate(self.pristine.len());
        }
    }

    /// Is unsat-core tracking on?
    pub fn produce_unsat_cores(&self) -> bool {
        self.produce_cores
    }

    /// Turn unsat-core tracking on or off. Call before asserting: assertions
    /// made while it is off are never core members, only hard constraints the
    /// core is taken relative to.
    pub fn set_produce_unsat_cores(&mut self, on: bool) {
        if on && !self.produce_cores {
            self.tracked.resize(self.assertions.len(), None);
        }
        self.produce_cores = on;
    }

    /// Assert `t` as a core-trackable constraint, returning the fresh Bool
    /// symbol that identifies it in [`Solver::unsat_core`].
    ///
    /// What is actually asserted is `act -> t` for a fresh `act`, and every
    /// check then runs with all live `act`s as SAT assumptions. Two properties
    /// follow, and the whole feature rests on them:
    ///
    /// 1. **Any subset works.** Setting `act` false satisfies `act -> t`
    ///    whatever `t` says, so a failed-assumption set `S` witnesses that the
    ///    untracked assertions together with `{t_i : i in S}` are already
    ///    unsatisfiable — the other tracked assertions can simply be switched
    ///    off. That is exactly the definition of an unsat core.
    /// 2. **Substitution cannot swallow it.** `preprocess` eliminates a
    ///    variable when an assertion *is* a top-level equality; `act -> t`
    ///    is a disjunction, so a tracked assertion never becomes a definition
    ///    and never disappears into `defs` with its identity lost. The one
    ///    shape that still reduces is `t = false`, which collapses the guard
    ///    to `not act` — and that is recognised on its own (see [`ActLit`]).
    pub fn assert_tracked(&mut self, pool: &mut TermPool, t: TermId) -> SymbolId {
        self.set_produce_unsat_cores(true);
        // The name is for diagnostics only; identity is the SymbolId, so a
        // user variable of the same name is a display collision, not a term
        // collision.
        let sym = pool.fresh_symbol(format!("smtrs!core!{}", self.tracked.len()), Sort::Bool);
        let act = pool.var(sym);
        let not_act = pool.mk(Op::Not, &[act]).expect("not of Bool is Bool");
        let guarded = pool.mk(Op::Or, &[not_act, t]).expect("or of Bools is Bool");
        self.undo_lowering();
        self.assertions.push(guarded);
        self.pristine.push(guarded);
        self.tracked.push(Some((sym, t)));
        sym
    }

    /// This check's roots and over-approximation roots, rebuilt from the
    /// current (freshly restored) assertion set. The same computation
    /// `check_sat` does on entry; needed again by the lowering branches after
    /// [`Solver::undo_lowering`] has put the originals back.
    fn rebuilt_roots(&self, assumptions: &[TermId]) -> (Vec<TermId>, Vec<TermId>) {
        let mut roots: Vec<TermId> = self.assertions.clone();
        roots.extend_from_slice(assumptions);
        let orig = if self.produce_cores {
            let mut orig: Vec<TermId> = Vec::with_capacity(roots.len());
            for (i, &a) in self.assertions.iter().enumerate() {
                orig.push(match self.tracked.get(i) {
                    Some(&Some((_, unguarded))) => unguarded,
                    _ => a,
                });
            }
            orig.extend_from_slice(assumptions);
            orig
        } else {
            roots.clone()
        };
        (roots, orig)
    }

    /// Record a core, downgrading it to a refusal when this problem's `unsat`
    /// is only established *for the assertion set as a whole*.
    ///
    /// That is the bounded-string case, and it is subtle enough to be worth
    /// spelling out. `crates/smtrs-str/src/bounds.rs` decides that the length
    /// bound removes no model by harvesting length facts from the **top-level
    /// conjuncts of the problem** — `(= (str.len s) 3)`, `(str.prefixof y x)`
    /// and so on. Delete a named assertion and you may delete the very fact
    /// that justified the bound, at which point the subset's `unsat` is again
    /// only "no model this short". The whole-problem argument does not
    /// transfer to a subset, so a core taken from a bounded encoding cannot be
    /// justified even when the full answer can. Every wrong answer in this
    /// project's history has been in exactly this analysis; refuse.
    fn set_core(&mut self, state: CoreState) {
        self.core = match state {
            CoreState::Core(_) if self.string_lowered => CoreState::Refused(
                "the problem was encoded under a string length bound, whose \
                 completeness argument is made for the whole assertion set and \
                 does not transfer to a subset",
            ),
            other => other,
        };
    }

    /// Activation symbols of the tracked assertions in the core of the last
    /// `unsat`, or why one is not available.
    ///
    /// The returned set is a genuine core: asserting only those tracked
    /// assertions (together with every untracked one, and under the same
    /// assumptions the check ran with) is still unsatisfiable. It is not
    /// promised to be minimal.
    pub fn unsat_core(&self) -> Result<&[SymbolId], &'static str> {
        match &self.core {
            CoreState::Core(syms) => Ok(syms),
            CoreState::Refused(why) => Err(why),
            CoreState::Absent => Err("no unsat core available"),
        }
    }

    pub fn push(&mut self, n: u32) {
        self.core = CoreState::Absent;
        for _ in 0..n {
            // Index into `pristine`, not `assertions`: a lowering can already
            // have replaced `assertions` with a longer vector, and a level
            // recorded against that length would not survive being restored.
            self.levels.push(self.pristine.len());
        }
    }

    /// Should an engine built *now* hold push levels back from preprocessing
    /// and encode them under activation literals?
    ///
    /// Two conditions. [`GUARD_AFTER_POPS`] is the evidence that the script
    /// pops repeatedly and the trade is worth making. The second is bounded
    /// string lowering: it replaces the assertion set with
    /// `lowered ++ side_constraints`, and the side constraints land at the
    /// *end*, i.e. inside whatever push level happens to be open. Guarding
    /// those would let a `pop` retire an encoding constraint that belongs to a
    /// base-level assertion, so a lowered problem keeps the rebuild-on-pop
    /// path.
    fn guard_levels(&self) -> bool {
        self.pops >= GUARD_AFTER_POPS && !self.string_lowered && !self.guard_futile
    }

    /// Retract the innermost `n` push levels.
    ///
    /// Against a guarded engine the circuit survives *and stays usable*:
    /// everything asserted inside a level was blasted under that level's
    /// activation literal, so falsifying it permanently retires the level's
    /// clauses while the base encoding, the AIG, and every learned clause stay
    /// where they are.
    ///
    /// An unguarded engine is left exactly as it is. It cannot be trusted for
    /// the smaller assertion set — its preprocessor was free to draw
    /// definitions from the level just retracted — but it does not have to be
    /// discarded here to say so: `check_sat_lowered` reuses an engine only
    /// while the assertion set still extends `Engine::blasted`, and a pop is
    /// what breaks that. Throwing it away here would also throw away the one
    /// case where it survives honestly — a script that re-asserts the same
    /// terms after popping them restores the prefix, and the engine it built
    /// still describes them exactly.
    pub fn pop(&mut self, n: u32) {
        // A core names activation symbols; `pop` can retire the assertions
        // they belong to, so the previous check's core stops being a statement
        // about the current assertion set. Drop it rather than let it be read.
        self.core = CoreState::Absent;
        for _ in 0..n {
            let Some(len) = self.levels.pop() else { break };
            // Truncate `pristine`, not `assertions`: `levels` indexes the
            // originals (see `push`), and the working set is rebuilt from them
            // below. In guarded mode no lowering has run (`guard_levels`
            // refuses to guard a lowered set), so `pristine`, `assertions` and
            // `Engine::blasted` share this indexing.
            self.pristine.truncate(len);
            self.tracked.truncate(len);
            self.pops += 1;
            match &mut self.engine {
                Some(e) if e.guarded => {
                    // Everything allocated since the outermost retired level
                    // was opened is now dead weight; see `retired_dominates`.
                    // Taken once over the whole retirement so that nested
                    // levels are not counted twice.
                    let mut oldest = e.sat.num_vars();
                    while e.acts.len() > self.levels.len() {
                        let level = e.acts.pop().expect("acts outnumber levels");
                        oldest = oldest.min(level.vars_at_open);
                        if let Some(a) = level.act {
                            // Not needed to retire the level — dropping the
                            // literal from the assumption set already lets the
                            // guarded clauses be satisfied by a false `act`.
                            // It is added because it is *permanent*: at level
                            // zero the solver can propagate through the
                            // retirement instead of re-deciding `act` on every
                            // later query.
                            e.sat.add_clause(&[!a]);
                        }
                    }
                    e.retired_vars = e.retired_vars.saturating_add(e.sat.num_vars() - oldest);
                    e.blasted.truncate(len);
                }
                _ => {}
            }
        }
        // Rebuild the working set from the originals. When no lowering has run
        // this is exactly the old `assertions.truncate(len)`. When one has, it
        // is the difference between a correct answer and a wrong one: the
        // lowering appends side constraints that define its encoding
        // variables, `levels` cannot address them, and truncating to a stale
        // index deletes them while keeping the assertions that need them.
        //
        // Re-lowering is not optional here — a partially lowered set is not a
        // formula anyone can reason about — so the lowering state is cleared
        // and the next check starts over from the originals.
        self.undo_lowering();
        self.assertions = self.pristine.clone();
    }

    pub fn model(&self) -> Option<&FxHashMap<SymbolId, Value>> {
        self.model.as_ref()
    }

    /// Live SAT search counters of the current engine, or `None` when there is
    /// no engine or the backend keeps none.
    ///
    /// `stats.sat_counters` is a snapshot taken at the end of `check_sat`, so
    /// it misses the solves `minimize`/`maximize`/`eval_n` run on top of one.
    /// This reads the engine directly, which is what an A/B on those streams
    /// has to compare — they are the queries angr floods the solver with.
    pub fn sat_counters(&self) -> Option<smtrs_sat::SatCounters> {
        self.engine.as_ref().and_then(|e| e.sat.counters())
    }

    /// Report unsatisfiability, downgrading to `unknown` when the encoding
    /// was bounded (bounded strings): no model *within the bound* does not
    /// establish that no model exists.
    fn unsat_answer(&mut self, pool: &mut TermPool) -> Answer {
        if self.unsat_trustworthy {
            Answer::Unsat
        } else {
            self.unknown_or_prop_unsat(pool, "unsat only within the string length bound")
        }
    }

    /// Last resort before conceding `unknown`: check over-approximations of the
    /// original problem. Each one has *more* models than the original, so an
    /// unsatisfiable approximation proves the problem unsatisfiable no matter
    /// which theory content we could not encode — while a satisfiable one tells
    /// us nothing and we report the `unknown` we were going to report anyway.
    ///
    /// Two are tried, cheapest first: the Boolean skeleton, which keeps only
    /// the propositional structure, and — for string problems — the length
    /// abstraction, which additionally tracks how long each string is. The
    /// second subsumes the first but costs a real arithmetic solve, so it only
    /// runs when the skeleton comes back satisfiable.
    fn unknown_or_prop_unsat(&mut self, pool: &mut TermPool, reason: &str) -> Answer {
        if std::env::var_os("SMTRS_NO_PROP_ABS").is_some() || self.orig_roots.is_empty() {
            return Answer::Unknown(reason.into());
        }
        let t0 = std::time::Instant::now();
        let roots = self.orig_roots.clone();
        let skeleton = abstraction::boolean_abstraction(pool, &roots);
        let mut unsat_by = self
            .sub_unsat(pool, skeleton, None)
            .then_some("the Boolean skeleton");
        if unsat_by.is_none()
            && std::env::var_os("SMTRS_NO_LEN_ABS").is_none()
            && smtrs_str::contains_strings(pool, &roots)
        {
            if let Some(lengths) = smtrs_str::length::abstraction(pool, &roots) {
                if std::env::var_os("SMTRS_DUMP_LEN_ABS").is_some() {
                    eprintln!("{}", dump_smt2(pool, &lengths));
                }
                // The length abstraction is a real arithmetic solve and can be
                // as hard as the problem it approximates — the PCP family turns
                // into a system of word-equation lengths that grinds for
                // minutes. Cap it at what the failed attempt has already cost,
                // so this can never more than double the run, and at two
                // seconds regardless: a refutation that has not appeared by
                // then was not going to pay for itself.
                let budget = self
                    .check_start
                    .elapsed()
                    .clamp(MIN_ABS_BUDGET, MAX_ABS_BUDGET);
                unsat_by = self
                    .sub_unsat(pool, lengths, Some(budget))
                    .then_some("the length abstraction");
            }
        }
        self.stats.phases.prop_abs += t0.elapsed().as_secs_f64();
        match unsat_by {
            Some(how) => {
                if std::env::var_os("SMTRS_DEBUG").is_some() {
                    eprintln!("; unsat established by {how} ({reason})");
                }
                // This `unsat` was proved by a *different* formula — an
                // over-approximation solved in a fresh sub-solver that knows
                // nothing about the activation literals. Any core assembled
                // from the main engine's last search would describe a search
                // that did not establish this answer.
                self.core = CoreState::Refused(
                    "unsat was established by an over-approximation, \
                     which carries no core",
                );
                Answer::Unsat
            }
            None => Answer::Unknown(reason.into()),
        }
    }

    /// Solve an over-approximation in a fresh solver. `true` means the
    /// approximation is unsatisfiable, which settles the original; a `budget`
    /// gives up after that long and reports `false`, which only ever costs the
    /// `unknown` we were going to report anyway.
    fn sub_unsat(
        &self,
        pool: &mut TermPool,
        roots: Vec<TermId>,
        budget: Option<std::time::Duration>,
    ) -> bool {
        use std::sync::atomic::{AtomicBool, Ordering};
        use std::sync::Arc;
        let mut sub = Solver::new();
        sub.validate_models = false;
        let watchdog = budget.map(|budget| {
            // A fresh flag rather than the outer one, so the deadline is the
            // sub-solve's own; the watchdog forwards an outer interrupt too,
            // and `done` stops it as soon as the sub-solve returns.
            let flag = Arc::new(AtomicBool::new(false));
            let done = Arc::new(AtomicBool::new(false));
            sub.set_terminate(flag.clone());
            let outer = self.terminate.clone();
            let (f, d) = (flag, done.clone());
            std::thread::spawn(move || {
                let deadline = std::time::Instant::now() + budget;
                while !d.load(Ordering::Relaxed) {
                    if std::time::Instant::now() >= deadline
                        || outer.as_ref().is_some_and(|o| o.load(Ordering::Relaxed))
                    {
                        f.store(true, Ordering::Relaxed);
                        return;
                    }
                    std::thread::sleep(std::time::Duration::from_millis(5));
                }
            });
            done
        });
        if watchdog.is_none() {
            if let Some(f) = &self.terminate {
                sub.set_terminate(f.clone());
            }
        }
        for r in roots {
            sub.assert(r);
        }
        let unsat = matches!(sub.check_sat(pool, &[]), Answer::Unsat);
        if let Some(done) = watchdog {
            done.store(true, Ordering::Relaxed);
        }
        unsat
    }

    /// Lower any floating-point content to BV/Bool terms. Returns None when
    /// the FP fragment used is not implemented (caller answers `unknown`).
    fn lower_fp(pool: &mut TermPool, roots: &[TermId]) -> Option<Vec<TermId>> {
        if !smtrs_fp::contains_fp(pool, roots) {
            return Some(roots.to_vec());
        }
        match smtrs_fp::lower(pool, roots) {
            Ok(v) => Some(v),
            Err(e) => {
                if std::env::var_os("SMTRS_DEBUG").is_some() {
                    eprintln!("; fp lowering failed: {e}");
                }
                None
            }
        }
    }

    /// Is this one node outside the supported Bool/BV fragment?
    ///
    /// Node-local by construction — it reads `op(t)` and `sort(t)` and nothing
    /// else — which is what lets the answer for a whole DAG be cached and
    /// extended one subtree at a time (see [`PrefixScan`]).
    fn unsupported_node(pool: &TermPool, t: TermId) -> bool {
        match pool.op(t) {
            Op::Other { .. } => true,
            // `pool.var` interns with the symbol's own sort, so the node sort
            // and `pool.symbol(sym).sort` are the same thing.
            Op::Var(sym) => !matches!(pool.symbol(sym).sort, Sort::Bool | Sort::BitVec(_)),
            _ => false,
        }
    }

    /// Why `t` is outside the fragment. Formatted on demand, so the supported
    /// case never builds a string.
    fn unsupported_message(pool: &TermPool, t: TermId) -> String {
        match pool.op(t) {
            Op::Other { name, .. } => format!("operator {}", pool.symbol(name).name),
            Op::Var(sym) => format!("sort {}", pool.symbol(sym).sort),
            // Only the two arms above can be reported by `unsupported_node`.
            _ => format!("term {}", pool.display(t)),
        }
    }

    /// Everything the prologue needs to know about `assertions + assumptions`,
    /// answered against the cached analysis of the assertion prefix.
    ///
    /// The assertions are *not* passed in: they are the prefix, so `refresh`
    /// has just folded every one of them in and a query only ever walks what
    /// the assumptions add on top.
    fn scan_roots(&mut self, pool: &TermPool, assumptions: &[TermId]) -> QueryFacts {
        self.scan.refresh(pool, &self.assertions, &self.declared);
        self.scan.query(pool, assumptions)
    }

    /// Detect content outside the supported Bool/BV fragment.
    ///
    /// Uncached, and used only off the common path (`term_bit_lits`); the
    /// prologue reads the same answer out of [`PrefixScan`]. Stopping at the
    /// first offending node reports the same node the old full walk latched,
    /// because `find_post_order` visits in the same order.
    fn unsupported_reason(&self, pool: &TermPool, roots: &[TermId]) -> Option<String> {
        pool.find_post_order(roots, Self::unsupported_node)
            .map(|t| Self::unsupported_message(pool, t))
    }

    pub fn check_sat(&mut self, pool: &mut TermPool, assumptions: &[TermId]) -> Answer {
        let answer = self.check_sat_inner(pool, assumptions);
        // Every `unknown` path returns early out of `check_sat_inner`, so the
        // walk counters are read here rather than at any one of them.
        self.stats.walk = pool.walk_counters();
        answer
    }

    fn check_sat_inner(&mut self, pool: &mut TermPool, assumptions: &[TermId]) -> Answer {
        self.stats.checks += 1;
        self.check_start = std::time::Instant::now();
        self.model = None;
        self.core = CoreState::Absent;
        self.lowered_assumptions = assumptions.to_vec();
        let mut roots: Vec<TermId> = self.assertions.clone();
        roots.extend_from_slice(assumptions);
        // The over-approximation fallbacks want the problem as the *user*
        // stated it. Handing them the guards `act -> phi` would cripple them:
        // a Boolean skeleton can satisfy every guard by making its activation
        // literal false, so a formula the skeleton used to refute would come
        // back `unknown` the moment core tracking was switched on. Unguarding
        // here keeps the answer independent of the option.
        self.orig_roots = if self.produce_cores {
            let mut orig: Vec<TermId> = Vec::with_capacity(roots.len());
            for (i, &a) in self.assertions.iter().enumerate() {
                orig.push(match self.tracked.get(i) {
                    Some(&Some((_, unguarded))) => unguarded,
                    _ => a,
                });
            }
            orig.extend_from_slice(assumptions);
            orig
        } else {
            roots.clone()
        };

        // One walk for all four questions, and only over what the cached
        // analysis of the assertion prefix does not already cover. The order of
        // the tests below is the order it always was, and it matters:
        // `unsupported` is only consulted once strings and floats have been
        // lowered away, because before that a `Float` sort *is* an unsupported
        // sort.
        let facts = self.scan_roots(pool, assumptions);

        // Strings are reduced to bounded bit-vectors up front.
        if facts.has_strings {
            // A previous check's lowering replaced the assertion set, and its
            // encoding variables are minted per run: lowering this check's
            // raw string content (assumptions, typically — `assert` already
            // undoes on its own) against the already-lowered assertions would
            // give the same source variable two unrelated encodings. Restore
            // the originals and lower everything in one consistent run. The
            // scan cache self-heals on the prefix change (see `refresh`).
            if self.string_lowered || self.fp_lowered {
                self.undo_lowering();
                (roots, self.orig_roots) = self.rebuilt_roots(assumptions);
            }
            let t0 = std::time::Instant::now();
            let lowered_result = smtrs_str::lower(pool, &roots, smtrs_str::Config::default());
            self.stats.phases.lower_str += t0.elapsed().as_secs_f64();
            match lowered_result {
                Ok(lowered) => {
                    self.unsat_trustworthy = lowered.unsat_trustworthy;
                    self.string_lowered = true;
                    let n = self.assertions.len();
                    let mut new_assertions = lowered.roots[..n].to_vec();
                    new_assertions.extend(lowered.side.iter().copied());
                    let lowered_assumptions: Vec<TermId> = lowered.roots[n..].to_vec();
                    self.assertions = new_assertions;
                    // Lowering rewrites assertion `i` in place and appends its
                    // side constraints after all of them, so the tracked
                    // prefix still lines up; the side constraints are the
                    // encoding's own and belong to no named assertion.
                    if self.produce_cores {
                        self.tracked.resize(self.assertions.len(), None);
                    }
                    self.engine = None;
                    self.lowered_assumptions = lowered_assumptions.clone();
                    let mut roots2 = self.assertions.clone();
                    roots2.extend_from_slice(&lowered_assumptions);
                    // Lowering replaced the assertions, so the cached analysis
                    // is of formulas that no longer exist.
                    //
                    // Belt and braces, and known to be: mutation testing says
                    // deleting this line fails nothing, because `refresh`
                    // notices anyway — the live vector no longer extends the
                    // cached one. It is kept because that argument runs through
                    // a property of `smtrs_str::lower` in another crate (an
                    // assertion carrying string content cannot come back
                    // unchanged), and this line does not.
                    self.scan.clear();
                    let f2 = self.scan_roots(pool, &lowered_assumptions);
                    if let Some(t) = f2.unsupported {
                        let r = format!("unsupported: {}", Self::unsupported_message(pool, t));
                        return self.unknown_or_prop_unsat(pool, &r);
                    }
                    return self.check_sat_lowered(
                        pool,
                        &lowered_assumptions,
                        roots2,
                        f2.model_syms,
                    );
                }
                Err(e) => {
                    if std::env::var_os("SMTRS_DEBUG").is_some() {
                        eprintln!("; string lowering failed: {e}");
                    }
                    return self.unknown_or_prop_unsat(pool, "unsupported: string fragment");
                }
            }
        }

        // Floating point is word-blasted to bit-vectors up front, so the rest
        // of the pipeline only ever sees Bool/BV.
        if facts.has_fp {
            // As for strings above: raw FP content in the assumptions after a
            // lowered check must not be encoded against a different vintage of
            // bit-variables than the lowered assertions use. See `fp_lowered`.
            if self.fp_lowered || self.string_lowered {
                self.undo_lowering();
                (roots, self.orig_roots) = self.rebuilt_roots(assumptions);
            }
            let t0 = std::time::Instant::now();
            let lowered_opt = Self::lower_fp(pool, &roots);
            self.stats.phases.lower_fp += t0.elapsed().as_secs_f64();
            let Some(lowered) = lowered_opt else {
                return self.unknown_or_prop_unsat(pool, "unsupported: floating-point fragment");
            };
            let n = self.assertions.len();
            self.assertions = lowered[..n].to_vec();
            self.fp_lowered = true;
            let lowered_assumptions: Vec<TermId> = lowered[n..].to_vec();
            if self.produce_cores {
                self.tracked.resize(self.assertions.len(), None);
            }
            self.engine = None; // assertion terms changed identity
            self.lowered_assumptions = lowered_assumptions.clone();
            let mut roots2 = self.assertions.clone();
            roots2.extend_from_slice(&lowered_assumptions);
            roots = roots2;
            // Same rescan-from-scratch as the string path, and the same
            // belt-and-braces note: FP lowering gives the assertions new term
            // identities, which `refresh` would notice on its own.
            self.scan.clear();
            let f2 = self.scan_roots(pool, &lowered_assumptions);
            if let Some(t) = f2.unsupported {
                let r = format!("unsupported: {}", Self::unsupported_message(pool, t));
                return self.unknown_or_prop_unsat(pool, &r);
            }
            return self.check_sat_lowered(pool, &lowered_assumptions, roots, f2.model_syms);
        }

        if let Some(t) = facts.unsupported {
            let r = format!("unsupported: {}", Self::unsupported_message(pool, t));
            return self.unknown_or_prop_unsat(pool, &r);
        }
        self.check_sat_lowered(pool, assumptions, roots, facts.model_syms)
    }

    fn check_sat_lowered(
        &mut self,
        pool: &mut TermPool,
        assumptions: &[TermId],
        roots: Vec<TermId>,
        model_syms: Vec<SymbolId>,
    ) -> Answer {
        // Collect an engine whose retired levels have come to outweigh its
        // live ones, before asking whether it can be reused. An engine that
        // never survived more than one round says guarding is not paying here;
        // a streak of those switches it off (see `Solver::guard_futile`).
        if self.engine.as_ref().is_some_and(Engine::retired_dominates) {
            let futile = self
                .engine
                .as_ref()
                .is_some_and(|e| collected_too_soon(self.stats.checks, e));
            self.futile_collections = if futile {
                self.futile_collections.saturating_add(1)
            } else {
                0
            };
            if self.futile_collections >= GUARD_FUTILE_STREAK {
                self.guard_futile = true;
            }
            self.engine = None;
        }
        // (Re)build the engine, or extend it with newly asserted formulas.
        let reusable = self
            .engine
            .as_ref()
            .is_some_and(|e| self.assertions.starts_with(&e.blasted));
        // In guarded mode, substitution-based preprocessing may only draw
        // definitions from assertions that can never be retracted, since it
        // rewrites the terms of every assertion around them. That is exactly
        // the base level; anything above the first open push is left to the
        // extension pass below, which blasts it under the level's activation
        // literal. Until guarding is engaged there is nothing to protect, and
        // preprocessing sees the whole assertion set as it always did.
        let guard_levels = self.guard_levels();
        let base_len = match self.levels.first() {
            Some(&n) if guard_levels => n.min(self.assertions.len()),
            _ => self.assertions.len(),
        };
        let mut blast_secs = 0.0f64;
        if !reusable {
            self.stats.rebuilds += 1;
            self.engine = None;
            let base = &self.assertions[..base_len];
            // The flattening rules consult a *refcount* to decide whether
            // re-associating a sum would destroy blaster reuse, and that proxy
            // is wrong in both directions: honouring it cost `Sage2/bench_16251`
            // a 0.026 s proof, ignoring it cost five other Sage2 instances.
            // Neither answer is available from the term graph, but the thing
            // the guard is a proxy *for* — how big a formula the search gets —
            // is available as soon as the circuit exists. So build it both ways
            // and keep the one with fewer SAT variables. The second encoding is
            // skipped when the guard declined nothing (the two are then
            // identical) and when the first one was already slow, which is what
            // keeps it off the encode-bound instances that cannot afford it.
            let mut best: Option<Engine> = None;
            let mut best_size = u64::MAX;
            let mut build_alt = self.dual_encode_max_secs > 0.0;
            // Roots of the guarded encoding, kept so the alternative can be
            // abandoned before it is blasted when it rewrote to the same thing.
            let mut first_roots: Vec<TermId> = Vec::new();
            'encode: for share_guard in [true, false] {
                if !share_guard && !build_alt {
                    break;
                }
                let t_enc = std::time::Instant::now();
                let mut rewriter = Rewriter::new();
                rewriter.share_guard = share_guard;
                // Parent counts across the assertion set, for sharing-aware
                // flattening decisions in the rewriter. This is the "assertion set
                // was rebuilt" case `count_parents` exists for; the per-round
                // recounts inside `preprocess` are the other caller.
                preprocess::count_parents(pool, base, &mut rewriter);
                if let Some(f) = &self.terminate {
                    rewriter.set_terminate(f.clone());
                }
                rewriter.set_size_budget(rewrite_size_budget(pool.num_terms()));
                let allow_subst = std::env::var_os("SMTRS_NO_SUBST").is_none();
                let t_rw = std::time::Instant::now();
                let mut pre = preprocess(pool, &mut rewriter, base, allow_subst);
                if rewriter.over_budget() && !rewriter.interrupted() {
                    // Rewriting grew the DAG out of all proportion to the input
                    // — extract pushdown across a term whose slice boundaries
                    // multiply with depth. The partially-rewritten result is
                    // unusable, so start over with those rules switched off;
                    // what survives is what the bit-blaster would have done
                    // anyway, and its structural hashing handles this shape
                    // well. Applied per encoding, since each pass rewrites
                    // independently.
                    rewriter = Rewriter::new();
                    rewriter.share_guard = share_guard;
                    preprocess::count_parents(pool, base, &mut rewriter);
                    if let Some(f) = &self.terminate {
                        rewriter.set_terminate(f.clone());
                    }
                    rewriter.set_conservative(true);
                    pre = preprocess(pool, &mut rewriter, base, allow_subst);
                    rewriter.stats.insert("size-budget-retry", 1);
                }
                self.stats.phases.rewrite_preprocess += t_rw.elapsed().as_secs_f64();
                if rewriter.interrupted() {
                    if best.is_some() {
                        // The guarded encoding is already built and usable; an
                        // interrupted *alternative* is simply not considered.
                        break 'encode;
                    }
                    return self.interrupted_answer();
                }
                // The sharing guard declining *something* does not mean the two
                // encodings differ: on the fast corpus 23 of 33 dual-encoded
                // instances rewrite to byte-identical roots, and building the
                // second circuit costs 34.6% of common-case wall for nothing.
                // Identical roots give an identical circuit, and the selector
                // below keeps the first on a tie, so abandoning here is not a
                // heuristic — it returns exactly the engine the full path would
                // have chosen.
                if share_guard {
                    if let Some(p) = &pre {
                        first_roots = p.roots.clone();
                    }
                } else {
                    let same = match (&pre, &first_roots) {
                        (Some(p), fr) => p.roots == *fr,
                        (None, _) => false,
                    };
                    if same {
                        break 'encode;
                    }
                }
                let mut engine = Engine {
                    sat: {
                        let mut s = Backend::from_env();
                        if let Some(f) = &self.terminate {
                            s.set_terminate(f.clone());
                        }
                        s
                    },
                    blaster: {
                        let mut b = BitBlaster::new();
                        if let Some(f) = &self.terminate {
                            b.set_terminate(f.clone());
                        }
                        b
                    },
                    rewriter,
                    blasted: base.to_vec(),
                    defs: Vec::new(),
                    subst: FxHashMap::default(),
                    subst_rounds: 0,
                    hard_unsat: false,
                    act_lits: FxHashMap::default(),
                    acts: Vec::new(),
                    retired_vars: 0,
                    guarded: guard_levels,
                    checks_at_build: self.stats.checks,
                };
                match pre {
                    None => engine.hard_unsat = true,
                    Some(pre) => {
                        let trace = std::env::var_os("SMTRS_TRACE_BLAST").is_some();
                        // SMTRS_COUNT_MUL=1 reports the post-preprocessing shape of
                        // the term graph. `const_mul` is the count linear
                        // normalization exists to drive to zero: it is what the
                        // multiplier-dominated SAGE encodings are made of, and it is
                        // directly comparable to Bitwuzla's normalize_eq counters.
                        if std::env::var_os("SMTRS_COUNT_MUL").is_some() {
                            let (mut cmul, mut vmul, mut nodes) = (0u32, 0u32, 0u32);
                            pool.post_order(&pre.roots, |pool, t| {
                                nodes += 1;
                                if pool.op(t) == Op::BvMul {
                                    if pool.args(t).iter().any(|&a| pool.as_bv_const(a).is_some()) {
                                        cmul += 1;
                                    } else {
                                        vmul += 1;
                                    }
                                }
                            });
                            eprintln!(
                            "; count_mul: const_mul={cmul} var_mul={vmul} nodes={nodes} roots={} defs={}",
                            pre.roots.len(),
                            pre.defs.len()
                        );
                        }
                        let t_bl = std::time::Instant::now();
                        for (ri, &r) in pre.roots.iter().enumerate() {
                            engine.blaster.assert_true(pool, r, &mut engine.sat);
                            if engine.blaster.interrupted() {
                                self.stats.phases.blast += t_bl.elapsed().as_secs_f64();
                                if best.is_some() {
                                    // Keep the encoding that did finish.
                                    break 'encode;
                                }
                                return self.interrupted_answer();
                            }
                            if trace {
                                let mut nodes = 0u32;
                                pool.post_order(&[r], |_, _| nodes += 1);
                                eprintln!(
                                    "; blast[{ri}] vars={} op={:?} term_nodes={nodes}",
                                    engine.sat.num_vars(),
                                    pool.op(r)
                                );
                            }
                        }
                        blast_secs += t_bl.elapsed().as_secs_f64();
                        engine.subst = pre
                            .defs
                            .iter()
                            .map(|&(sym, rhs)| (pool.var(sym), rhs))
                            .collect();
                        engine.subst_rounds = pre.rounds;
                        engine.defs = pre.defs;
                    }
                }
                // A trivially-unsat preprocessing result needs no circuit and
                // no alternative; take it and stop.
                if engine.hard_unsat {
                    best = Some(engine);
                    break 'encode;
                }
                if share_guard {
                    // Worth a second encoding only if the guard actually
                    // changed a decision, and only if this one was cheap
                    // enough that building it again is a rounding error
                    // against the search budget.
                    build_alt = build_alt
                        && engine.rewriter.share_declines > 0
                        && t_enc.elapsed().as_secs_f64() <= self.dual_encode_max_secs;
                }
                // Selected on *SAT variables*, not on AIG and-gates. The two
                // disagree and the difference matters: `num_and_gates` counts
                // every AND ever constructed, including cones that structural
                // hashing later leaves unreachable, while the variable count is
                // the size of the formula the search actually receives. On
                // `Sage2/bench_16251` the guarded encoding is the smaller of
                // the two by and-gates (25 103 against 25 332) and the larger
                // by variables (16 916 against 16 550) — and it is the one that
                // does not solve: 20 s against 3 ms of search.
                let size = engine.sat.num_vars() as u64;
                if std::env::var_os("SMTRS_DEBUG").is_some() {
                    eprintln!(
                        "; encode[guard={share_guard}] vars={size} gates={} declines={} secs={:.3}",
                        engine.blaster.aig.num_and_gates,
                        engine.rewriter.share_declines,
                        t_enc.elapsed().as_secs_f64()
                    );
                }
                if size < best_size {
                    best_size = size;
                    best = Some(engine);
                }
            }
            if std::env::var_os("SMTRS_DEBUG").is_some() {
                eprintln!("; dual_encode: chose {best_size} sat vars");
            }
            self.engine = best;
        }
        // Extend the engine with everything not blasted yet: the assertions
        // added since the last check, plus — after a rebuild in guarded mode —
        // everything above the base level, which preprocessing deliberately
        // skipped. On the unguarded path `base_len` is the whole assertion set,
        // so after a rebuild this loop runs zero times.
        {
            let e = self.engine.as_mut().expect("engine exists");
            // Mirror the open push levels into activation-literal slots. Keyed
            // off the engine's own flag, so an engine built before guarding was
            // engaged keeps blasting plain units — with no slots every
            // assertion blasts exactly as it did before push levels were made
            // retractable.
            let levels: &[usize] = if e.guarded { &self.levels } else { &[] };
            while e.acts.len() < levels.len() {
                let start = levels[e.acts.len()];
                let vars_at_open = e.sat.num_vars();
                e.acts.push(Level {
                    start,
                    act: None,
                    vars_at_open,
                });
            }
            let start = e.blasted.len();
            let new: Vec<TermId> = self.assertions[start..].to_vec();
            let t_inc = std::time::Instant::now();
            let mut interrupted = false;
            for (off, &a) in new.iter().enumerate() {
                if e.hard_unsat {
                    break; // nothing left to learn; skip the encoding work
                }
                let s = apply_subst(pool, &e.subst, e.subst_rounds, a);
                let rw = e.rewriter.rewrite(pool, s);
                if e.rewriter.interrupted() {
                    interrupted = true;
                    break;
                }
                if rw == pool.true_term {
                    // Nothing to assert, so the level gets no activation
                    // literal on account of this one.
                    continue;
                }
                let guard = e.guard_for(start + off);
                if rw == pool.false_term {
                    match guard {
                        // The level contradicts itself, which is a fact about
                        // the level and must not outlive it.
                        Some(g) => e.sat.add_clause(&[!g]),
                        None => {
                            e.hard_unsat = true;
                            break;
                        }
                    }
                } else {
                    e.blaster.assert_true_guarded(pool, rw, &mut e.sat, guard);
                }
                if e.blaster.interrupted() {
                    interrupted = true;
                    break;
                }
            }
            e.blasted.extend_from_slice(&new);
            blast_secs += t_inc.elapsed().as_secs_f64();
            if interrupted {
                self.stats.phases.blast += blast_secs;
                return self.interrupted_answer();
            }
        }
        self.stats.phases.blast += blast_secs;

        let e = self.engine.as_mut().expect("engine exists");
        // `clone_from` reuses the destination's table across checks; a fresh
        // clone per check is a per-query allocation with no reader that needs
        // it (hygiene, not a measured win — see docs/REJECTED.md).
        self.stats.rewrites_applied.clone_from(&e.rewriter.stats);
        if std::env::var_os("SMTRS_DEBUG").is_some() {
            eprintln!(
                "; debug: terms={} blasted_assertions={} aig_gates={} sat_vars={}",
                pool.num_terms(),
                e.blasted.len(),
                e.blaster.aig.num_and_gates,
                e.sat.num_vars(),
            );
        }
        if e.hard_unsat {
            // An assertion rewrote to `false`. It cannot be a tracked one:
            // `act -> phi` never rewrites to `false` (setting `act` false
            // satisfies it), so the culprit is an untracked assertion and the
            // core is empty — the untracked set refutes itself.
            self.set_core(CoreState::Core(Vec::new()));
            return self.unsat_answer(pool);
        }

        // Assumptions become SAT-level assumption literals: nothing about the
        // engine changes across assumption-only checks (angr's usage pattern).
        // The open push levels' activation literals ride along at the front —
        // they are what makes the clauses of the current context active at all,
        // and they belong in `user_lits` below because they are in force for
        // the answer while naming no tracked assertion.
        let mut assumption_lits = e.live_acts();
        assumption_lits.reserve(assumptions.len());
        for &a in assumptions {
            let s = apply_subst(pool, &e.subst, e.subst_rounds, a);
            let rw = e.rewriter.rewrite(pool, s);
            if e.rewriter.interrupted() {
                return self.interrupted_answer();
            }
            if rw == pool.false_term {
                // Refuted by an assumption of this check alone; no tracked
                // assertion took part.
                self.set_core(CoreState::Core(Vec::new()));
                return self.unsat_answer(pool);
            }
            if rw == pool.true_term {
                continue;
            }
            let out = e.blaster.blast_bool(pool, rw);
            if e.blaster.interrupted() {
                return self.interrupted_answer();
            }
            let lit = e.blaster.aig.emit(&mut e.sat, out);
            assumption_lits.push(lit);
        }
        // How many of `assumption_lits` came from the caller. The activation
        // literals appended below are ours, and only they may name a core.
        let user_lits = assumption_lits.len();

        // Every live tracked assertion is switched on by assuming its
        // activation literal. On `unsat`, the failed subset of these is the
        // core.
        let mut acts: Vec<(SymbolId, ActLit)> = Vec::new();
        if self.produce_cores {
            let live: Vec<SymbolId> = self.tracked.iter().flatten().map(|&(s, _)| s).collect();
            for sym in live {
                let act = match e.act_lits.get(&sym) {
                    Some(&cached) => cached,
                    None => {
                        let var = pool.var(sym);
                        // The activation variable goes through the same
                        // substitute-rewrite-blast path as a user assumption,
                        // which is what makes preprocessing's verdict on it
                        // visible here instead of silently dropped.
                        let s = apply_subst(pool, &e.subst, e.subst_rounds, var);
                        let rw = e.rewriter.rewrite(pool, s);
                        if e.rewriter.interrupted() {
                            return self.interrupted_answer();
                        }
                        let act = if rw == pool.false_term {
                            ActLit::Refuted
                        } else if rw == pool.true_term {
                            ActLit::Forced
                        } else {
                            let out = e.blaster.blast_bool(pool, rw);
                            if e.blaster.interrupted() {
                                return self.interrupted_answer();
                            }
                            let lit = e.blaster.aig.emit(&mut e.sat, out);
                            // Pin it: CNF preprocessing may eliminate or merge
                            // away any other variable, and the core is read
                            // off the implication graph these literals live in.
                            e.sat.freeze_var(lit);
                            if rw == var {
                                ActLit::Lit(lit)
                            } else {
                                ActLit::Rewritten(lit)
                            }
                        };
                        e.act_lits.insert(sym, act);
                        act
                    }
                };
                if act == ActLit::Refuted {
                    // `phi` rewrote to `false` on its own (the rewriter is
                    // context-free, and only untracked assertions can supply
                    // the substitutions a later round rewrites under), so this
                    // one assertion is the whole core.
                    if std::env::var_os("SMTRS_DEBUG").is_some() {
                        eprintln!("; core: tracked assertion refuted by preprocessing");
                    }
                    self.set_core(CoreState::Core(vec![sym]));
                    return self.unsat_answer(pool);
                }
                if let ActLit::Lit(lit) | ActLit::Rewritten(lit) = act {
                    assumption_lits.push(lit);
                }
                acts.push((sym, act));
            }
        }

        if let Ok(path) = std::env::var("SMTRS_DUMP_CNF") {
            e.sat.dump_dimacs(&path);
            eprintln!("; dumped CNF to {path}");
        }
        // Hard restart: the search runs under a conflict budget, and an
        // instance that blows it — i.e. one heading for a timeout anyway — is
        // re-entered once. `solve` keeps the learned clauses and the activity
        // scores but starts the Luby sequence over, which is the whole effect.
        // A backend that cannot express a budget would never trip it, so the
        // re-entry below would wait for an event that cannot happen; take its
        // word for it and run the plain single solve instead.
        let restart_at = hard_restart_at().filter(|&b| e.sat.set_conflict_budget(b));
        let t_sat = std::time::Instant::now();
        let mut result = e.sat.solve(&assumption_lits);
        if restart_at.is_some() {
            let _ = e.sat.set_conflict_budget(u64::MAX);
        }
        let terminated = self
            .terminate
            .as_ref()
            .is_some_and(|f| f.load(std::sync::atomic::Ordering::Relaxed));
        if restart_at.is_some() && result == SatResult::Unknown && !terminated {
            result = e.sat.solve(&assumption_lits);
        }
        self.stats.phases.sat += t_sat.elapsed().as_secs_f64();
        self.stats.terms = pool.num_terms();
        self.stats.assertions_blasted = e.blasted.len();
        self.stats.sat_vars = e.sat.num_vars();
        self.stats.aig_gates = e.blaster.aig.num_and_gates;
        self.stats.aig_strash_hits = e.blaster.aig.strash_hits;
        self.stats.aig_folds = e.blaster.aig.folds;
        self.stats.sat_counters = e.sat.counters();

        match result {
            SatResult::Unsat => {
                if self.produce_cores {
                    self.extract_core(&assumption_lits[..user_lits], &acts);
                }
                return self.unsat_answer(pool);
            }
            SatResult::Unknown => return Answer::Unknown("sat solver gave up".to_string()),
            SatResult::Sat => {}
        }
        let t_model = std::time::Instant::now();
        let t_visits = pool.walk_counters();

        // Variables to give values to: everything appearing in the roots
        // (FP lowering introduces fresh IEEE-bit variables that models and
        // validation both need) plus the user-declared constants. The list
        // comes pre-collected from the caller's [`PrefixScan`], in the order
        // the walk that used to live here produced.
        //
        // The literal lookups stay *after* the verdict: they are work done for
        // the model — an `unsat` or `unknown` check has no model, so doing
        // them before the solve made every refutation pay for one. Nothing
        // here can affect the search: it only reads the blaster's
        // term-to-literal map, which the solve does not touch.
        let var_bits: Vec<(SymbolId, Option<VarBits>)> = model_syms
            .iter()
            .map(|&sym| {
                let var = pool.var(sym);
                let bits = match pool.symbol(sym).sort {
                    Sort::Bool => e.blaster.bool_lit(var).map(VarBits::Bool),
                    Sort::BitVec(_) => e.blaster.bv_bits(var).cloned().map(VarBits::Bv),
                    _ => None,
                };
                (sym, bits)
            })
            .collect();

        // Model reconstruction with completion: unconstrained -> 0/false.
        let mut model: FxHashMap<SymbolId, Value> = FxHashMap::default();
        let defined: rustc_hash::FxHashSet<SymbolId> = e.defs.iter().map(|(s, _)| *s).collect();
        for (sym, bits) in var_bits {
            if defined.contains(&sym) {
                continue; // reconstructed from defs below
            }
            let sort = pool.symbol(sym).sort;
            let value = match (bits, sort) {
                (Some(VarBits::Bool(l)), _) => {
                    Value::Bool(e.blaster.aig.value(&e.sat, l).unwrap_or(false))
                }
                (Some(VarBits::Bv(bits)), Sort::BitVec(w)) => {
                    Value::Bv(BvConst::from_bits(w, |i| {
                        e.blaster
                            .aig
                            .value(&e.sat, bits[i as usize])
                            .unwrap_or(false)
                    }))
                }
                (None, Sort::Bool) => Value::Bool(false),
                (None, Sort::BitVec(w)) => Value::Bv(BvConst::zero(w)),
                _ => continue,
            };
            model.insert(sym, value);
        }
        // Eliminated variables: evaluate defining terms in reverse
        // recording order (each RHS references only surviving vars or
        // later-recorded defs).
        //
        // One evaluator for the whole sequence, and for the validation pass
        // below. Preprocessing can eliminate thousands of variables whose
        // defining terms are chained (`t[i]` built from `t[i-1]`), so their
        // cones almost entirely coincide; a standalone `eval` per definition
        // re-walks that shared cone once per definition and allocates a fresh
        // value cache each time. Sound because the sequence only ever *extends*
        // `model` — a value once computed is never revised — which is exactly
        // the contract `Evaluator` states.
        let mut ev = smtrs_core::Evaluator::default();
        for (sym, rhs) in e.defs.iter().rev() {
            match ev.eval(pool, &[*rhs], &model) {
                Ok(vals) => {
                    model.insert(*sym, vals[0].clone());
                }
                Err(err) => panic!(
                    "def reconstruction failed for {}: {err}",
                    pool.symbol(*sym).name
                ),
            }
        }

        if self.validate_models {
            // With core tracking on, the assertions in `roots` are guards
            // `act -> phi`, which a false `act` satisfies without saying
            // anything about `phi`. Every activation literal was assumed true
            // for this solve, so every one of them must be true in the model —
            // check that first, or the validation below is vacuous exactly
            // where it matters most.
            for (sym, act) in acts.iter() {
                if !matches!(act, ActLit::Lit(_)) {
                    // A `Rewritten` activation literal is not the variable's
                    // own, so the model's value for the *symbol* says nothing.
                    continue;
                }
                if model.get(sym) != Some(&Value::Bool(true)) {
                    panic!(
                        "MODEL VALIDATION FAILED: activation literal {} is not true, \
                         so its tracked assertion was not enforced",
                        pool.symbol(*sym).name
                    );
                }
            }
            match ev.eval(pool, &roots, &model) {
                Ok(vals) => {
                    if let Some(i) = vals.iter().position(|v| v != &Value::Bool(true)) {
                        panic!(
                            "MODEL VALIDATION FAILED on assertion {}: {}",
                            i,
                            pool.display(roots[i])
                        );
                    }
                }
                Err(err) => panic!("model validation error: {err}"),
            }
        }

        self.model = Some(model);
        // Re-read: giving a value to a declared symbol that occurs in no
        // assertion mints its `Var` node, and that now happens here rather
        // than before the solve.
        self.stats.terms = pool.num_terms();
        let now = pool.walk_counters();
        self.stats.model_traversals += now.walks - t_visits.walks;
        self.stats.model_visits += now.visits - t_visits.visits;
        self.stats.phases.model += t_model.elapsed().as_secs_f64();
        Answer::Sat
    }

    /// Read the unsat core off the SAT engine's failed-assumption set.
    ///
    /// `user_lits` are the assumption literals of this check that came from
    /// the caller: they are in force for the core, but they are not tracked
    /// assertions and never name one.
    ///
    /// The core is then **verified** — re-solve under the caller's assumptions
    /// plus only the core's activation literals, and require `unsat` again.
    /// The extraction has its own tests, but this is the property the answer
    /// is judged on and it costs one incremental SAT call on a formula whose
    /// learnt clauses are already there. A verification that does not come
    /// back `unsat` (including one cut short by an interrupt) falls back to
    /// the whole tracked set, which is trivially a core: the check that just
    /// ran assumed all of it and was unsat.
    fn extract_core(&mut self, user_lits: &[smtrs_sat::Lit], acts: &[(SymbolId, ActLit)]) {
        let e = self.engine.as_mut().expect("engine exists");
        let Some(failed) = e.sat.failed_assumptions() else {
            self.core =
                CoreState::Refused("the selected SAT backend does not report failed assumptions");
            return;
        };
        if acts.iter().any(|(_, a)| matches!(a, ActLit::Rewritten(_))) {
            self.core = CoreState::Refused(
                "preprocessing replaced an activation literal, so the failed \
                 assumptions no longer name the tracked assertions",
            );
            return;
        }
        let failed: rustc_hash::FxHashSet<smtrs_sat::Lit> = failed.into_iter().collect();
        let mut syms: Vec<SymbolId> = Vec::new();
        let mut lits: Vec<smtrs_sat::Lit> = user_lits.to_vec();
        for &(sym, act) in acts {
            match act {
                ActLit::Lit(l) if failed.contains(&l) => {
                    syms.push(sym);
                    lits.push(l);
                }
                // Nothing can switch this assertion off, so nothing can show
                // it was unnecessary either. Keeping it is the larger core.
                ActLit::Forced => syms.push(sym),
                _ => {}
            }
        }
        let verified = e.sat.solve(&lits) == SatResult::Unsat;
        if std::env::var_os("SMTRS_DEBUG").is_some() {
            eprintln!(
                "; core: {} of {} tracked assertions, verification {}",
                syms.len(),
                acts.len(),
                if verified {
                    "unsat"
                } else {
                    "FAILED, widening"
                }
            );
        }
        self.set_core(if verified {
            CoreState::Core(syms)
        } else {
            CoreState::Core(acts.iter().map(|&(sym, _)| sym).collect())
        });
    }

    /// Literalize `terms` as SAT assumption literals in the current engine
    /// (substitution + rewrite + blast + emit). Returns Err(Unsat) if any
    /// rewrites to false; `true` terms are skipped.
    ///
    /// Every live activation literal is appended. Without them the tracked
    /// assertions are all switched *off* — `act -> phi` is satisfied by a
    /// false `act` — so a direct `sat.solve` for `minimize`/`eval_n` would run
    /// against a strictly weaker formula than the one `check_sat` answered on.
    /// The activation literals are read from the cache the preceding
    /// `check_sat` populated, which is why this may only be called after one.
    fn literalize(
        &mut self,
        pool: &mut TermPool,
        terms: &[TermId],
    ) -> Result<Vec<smtrs_sat::Lit>, Answer> {
        let acts: Vec<smtrs_sat::Lit> = if self.produce_cores {
            let e = self.engine.as_ref().expect("engine exists");
            self.tracked
                .iter()
                .flatten()
                .filter_map(|(sym, _)| match e.act_lits.get(sym) {
                    Some(&(ActLit::Lit(l) | ActLit::Rewritten(l))) => Some(l),
                    _ => None,
                })
                .collect()
        } else {
            Vec::new()
        };
        let e = self.engine.as_mut().expect("engine exists");
        let mut lits = acts;
        // The open push levels, for the same reason: their clauses are inert
        // without them, so a direct `sat.solve` would run on a formula missing
        // everything asserted inside the current scope.
        lits.extend(e.live_acts());
        lits.reserve(terms.len());
        for &a in terms {
            let s = apply_subst(pool, &e.subst, e.subst_rounds, a);
            let rw = e.rewriter.rewrite(pool, s);
            if rw == pool.false_term {
                return Err(Answer::Unsat);
            }
            if rw == pool.true_term {
                continue;
            }
            let out = e.blaster.blast_bool(pool, rw);
            lits.push(e.blaster.aig.emit(&mut e.sat, out));
        }
        Ok(lits)
    }

    /// Emitted SAT literals for the bits of a BV term (LSB first).
    fn term_bit_lits(&mut self, pool: &mut TermPool, term: TermId) -> Option<Vec<smtrs_sat::Lit>> {
        if self.unsupported_reason(pool, &[term]).is_some() {
            return None;
        }
        let e = self.engine.as_mut()?;
        let s = apply_subst(pool, &e.subst, e.subst_rounds, term);
        let rw = e.rewriter.rewrite(pool, s);
        if !pool.sort(rw).is_bv() {
            return None;
        }
        let bits = e.blaster.blast_bv(pool, rw);
        Some(
            bits.iter()
                .map(|&b| e.blaster.aig.emit(&mut e.sat, b))
                .collect(),
        )
    }

    /// Native minimum (unsigned) of a BV term under assumptions: MSB-first
    /// bit fixing over the persistent engine — width w SAT calls, all sharing
    /// learned state. This is what claripy emulates with ~64 solver
    /// round-trips; here it is one API call. Returns None if unsat/unknown.
    pub fn minimize(
        &mut self,
        pool: &mut TermPool,
        term: TermId,
        assumptions: &[TermId],
    ) -> Option<BvConst> {
        self.extremum(pool, term, assumptions, false)
    }

    /// Native maximum (unsigned) of a BV term under assumptions.
    pub fn maximize(
        &mut self,
        pool: &mut TermPool,
        term: TermId,
        assumptions: &[TermId],
    ) -> Option<BvConst> {
        self.extremum(pool, term, assumptions, true)
    }

    fn extremum(
        &mut self,
        pool: &mut TermPool,
        term: TermId,
        assumptions: &[TermId],
        maximize: bool,
    ) -> Option<BvConst> {
        if self.check_sat(pool, assumptions) != Answer::Sat {
            return None;
        }
        // The check may have theory-lowered the assumptions; literalize what
        // the engine actually solved, not what the caller wrote.
        let assumptions = self.lowered_assumptions.clone();
        let bit_lits = self.term_bit_lits(pool, term)?;
        let base = self.literalize(pool, &assumptions).ok()?;
        let e = self.engine.as_mut()?;
        let w = bit_lits.len();
        // MSB-first: greedily fix each bit to the preferred value if a model
        // still exists with it; otherwise the opposite value is forced.
        let mut fixed: Vec<smtrs_sat::Lit> = Vec::with_capacity(w);
        for i in (0..w).rev() {
            let prefer = if maximize { bit_lits[i] } else { !bit_lits[i] };
            let mut assums = base.clone();
            assums.extend_from_slice(&fixed);
            assums.push(prefer);
            match e.sat.solve(&assums) {
                SatResult::Sat => fixed.push(prefer),
                SatResult::Unsat => fixed.push(!prefer),
                SatResult::Unknown => return None,
            }
        }
        // fixed[k] corresponds to bit w-1-k.
        Some(BvConst::from_bits(w as u32, |i| {
            let l = fixed[w - 1 - i as usize];
            let bit_lit = bit_lits[i as usize];
            l == bit_lit // positive polarity chosen for this bit
        }))
    }

    /// Enumerate up to `n` distinct values of a BV term under assumptions.
    /// Blocking clauses are guarded by a fresh activation literal that is
    /// retired afterwards, so the engine is unchanged for future queries.
    pub fn eval_n(
        &mut self,
        pool: &mut TermPool,
        term: TermId,
        n: usize,
        assumptions: &[TermId],
    ) -> Vec<BvConst> {
        let mut out = Vec::new();
        if n == 0 || self.check_sat(pool, assumptions) != Answer::Sat {
            return out;
        }
        // As in `extremum`: the engine speaks post-lowering Bool/BV, so
        // re-literalize the lowered assumptions, never the raw ones.
        let assumptions = self.lowered_assumptions.clone();
        let Some(bit_lits) = self.term_bit_lits(pool, term) else {
            return out;
        };
        let Ok(base) = self.literalize(pool, &assumptions) else {
            return out;
        };
        let e = self.engine.as_mut().expect("engine exists");
        let act = e.sat.new_var();
        let w = bit_lits.len();
        loop {
            let mut assums = base.clone();
            assums.push(act);
            match e.sat.solve(&assums) {
                SatResult::Sat => {
                    let value = BvConst::from_bits(w as u32, |i| {
                        e.sat.value(bit_lits[i as usize]).unwrap_or(false)
                    });
                    // Block this value (under act): some bit must differ.
                    let mut clause: Vec<smtrs_sat::Lit> = vec![!act];
                    for (i, &bl) in bit_lits.iter().enumerate() {
                        clause.push(if value.bit(i as u32) { !bl } else { bl });
                    }
                    e.sat.add_clause(&clause);
                    out.push(value);
                    if out.len() >= n {
                        break;
                    }
                }
                _ => break,
            }
        }
        // Retire the activation literal and its blocking clauses.
        e.sat.add_clause(&[!act]);
        out
    }

    /// Evaluate arbitrary terms under the current model (for get-value).
    pub fn eval_terms(&self, pool: &TermPool, terms: &[TermId]) -> Result<Vec<Value>, String> {
        let model = self.model.as_ref().ok_or("no model available")?;
        eval(pool, terms, model).map_err(|e| e.to_string())
    }
}

enum VarBits {
    Bool(smtrs_aig::AigLit),
    Bv(Vec<smtrs_aig::AigLit>),
}

/// Render a model value as SMT-LIB.
pub fn value_smt2(v: &Value) -> String {
    match v {
        Value::Bool(b) => b.to_string(),
        Value::Bv(c) => c.to_binary_string(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use smtrs_parser::{parse_script, Command};

    fn run(input: &str) -> (Vec<Answer>, TermPool, Solver) {
        let mut pool = TermPool::new();
        let script = parse_script(input, &mut pool).expect("parse");
        let mut solver = Solver::new();
        solver.declared = script.declared.clone();
        let mut answers = Vec::new();
        for cmd in &script.commands {
            match cmd {
                Command::Assert(t, _) => solver.assert(*t),
                Command::CheckSat => answers.push(solver.check_sat(&mut pool, &[])),
                Command::CheckSatAssuming(ts) => answers.push(solver.check_sat(&mut pool, ts)),
                Command::Push(n) => solver.push(*n),
                Command::Pop(n) => solver.pop(*n),
                _ => {}
            }
        }
        (answers, pool, solver)
    }

    /// Assert-check-assert-check across the FP lowering: the second check
    /// must reason about the *same* `x` as the first. Before `fp_lowered`,
    /// the second lowering run minted a fresh bit-variable for `x`, so
    /// `(not (fp.eq x x))` and a later `(not (fp.isNaN x))` stopped sharing a
    /// variable and answered a wrong `sat`.
    #[test]
    fn fp_lowering_survives_incremental_assert() {
        let (answers, mut pool, mut solver) = run(
            "(declare-const x (_ FloatingPoint 11 53))\
             (assert (not (fp.eq x x)))\
             (check-sat)",
        );
        assert_eq!(answers, vec![Answer::Sat]);
        let script = parse_script(
            "(declare-const x (_ FloatingPoint 11 53))(assert (not (fp.isNaN x)))",
            &mut pool,
        )
        .expect("parse");
        // The parser scopes names per script, so rebind its `x` to the
        // solver's: both scripts name the same declared constant.
        let Command::Assert(t, _) = script.commands[0] else {
            panic!("expected an assert");
        };
        let old_x = pool.var(script.declared[0]);
        let new_x = pool.var(solver.declared[0]);
        let t = pool.substitute(t, &FxHashMap::from_iter([(old_x, new_x)])).expect("substitute");
        solver.assert(t);
        assert_eq!(solver.check_sat(&mut pool, &[]), Answer::Unsat);
    }

    /// The same identity property for assumptions: a string assumption after
    /// a string-lowered check must constrain the same variable the lowered
    /// assertions encode.
    #[test]
    fn string_assumptions_after_a_lowered_check_share_variables() {
        let (answers, mut pool, mut solver) = run(
            r#"(declare-const s String)(assert (= (str.len s) 3))(check-sat)"#,
        );
        assert_eq!(answers, vec![Answer::Sat]);
        // Assuming |s| = 5 now contradicts the asserted |s| = 3.
        let script = parse_script(
            r#"(declare-const s String)(assert (= (str.len s) 5))"#,
            &mut pool,
        )
        .expect("parse");
        let Command::Assert(t, _) = script.commands[0] else {
            panic!("expected an assert");
        };
        let old_s = pool.var(script.declared[0]);
        let new_s = pool.var(solver.declared[0]);
        let t = pool.substitute(t, &FxHashMap::from_iter([(old_s, new_s)])).expect("substitute");
        assert_eq!(solver.check_sat(&mut pool, &[t]), Answer::Unsat);
        // And the assertions alone are still satisfiable afterwards.
        assert_eq!(solver.check_sat(&mut pool, &[]), Answer::Sat);
    }

    /// `minimize`/`eval_n` under assumptions that need theory lowering: the
    /// engine speaks post-lowering Bool/BV, so literalizing the caller's raw
    /// `fp.*` terms was a blaster panic. The auxiliary-variable shape below is
    /// exactly how a client evaluates a float: bind its IEEE bits to a BV
    /// variable by an assumed equality, then enumerate that variable.
    #[test]
    fn native_ops_under_fp_assumptions() {
        let mut pool = TermPool::new();
        let x_sym = pool.fresh_symbol("x", Sort::Float(8, 24));
        let x = pool.var(x_sym);
        let aux_sym = pool.fresh_symbol("aux", Sort::BitVec(32));
        let aux = pool.var(aux_sym);
        let bits = pool.mk(Op::FpToIeeeBv, &[x]).unwrap();
        let link = pool.mk(Op::Eq, &[aux, bits]).unwrap();
        // x == 2.0f32 (bit pattern 0x40000000).
        let two_bits = pool.bv_u64(32, 0x4000_0000);
        let two = pool.mk(Op::FpFromIeeeBv { eb: 8, sb: 24 }, &[two_bits]).unwrap();
        let x_is_two = pool.mk(Op::FpEq, &[x, two]).unwrap();

        let mut solver = Solver::new();
        solver.declared = vec![x_sym, aux_sym];
        solver.assert(x_is_two);
        let values = solver.eval_n(&mut pool, aux, 4, &[link]);
        assert_eq!(values.len(), 1, "fp.eq pins the bit pattern");
        assert_eq!(values[0].as_u64(), Some(0x4000_0000));
        let min = solver.minimize(&mut pool, aux, &[link]).expect("sat");
        assert_eq!(min.as_u64(), Some(0x4000_0000));
    }

    /// The bit-vector bridge (`bv2nat` / `(_ int2bv w)` in `smtrs-str`), as a
    /// bit-vector client like clarirs emits it: lengths wrapped in the bridge
    /// and compared as 64-bit bit-vectors, substr positions passed through
    /// `bv2nat`.
    #[test]
    fn bv_bridge_end_to_end() {
        let mut pool = TermPool::new();
        let s_sym = pool.fresh_symbol("s", Sort::Str);
        let s = pool.var(s_sym);
        let head = |pool: &mut TermPool, name: &str| pool.fresh_symbol(name, Sort::Bool);
        let str_len = head(&mut pool, "str.len");
        let int2bv = head(&mut pool, "int2bv");
        let bv2nat = head(&mut pool, "bv2nat");
        let substr = head(&mut pool, "str.substr");
        let len = pool.other(str_len, 0, 0, &[s], Sort::Int);
        let bridged = pool.other(int2bv, 64, 0, &[len], Sort::BitVec(64));

        // (= ((_ int2bv 64) (str.len s)) 3) is sat, and the model's length
        // symbol really carries 3.
        let three = pool.bv_u64(64, 3);
        let eq3 = pool.mk(Op::Eq, &[bridged, three]).unwrap();
        let mut solver = Solver::new();
        solver.declared = vec![s_sym];
        solver.assert(eq3);
        assert_eq!(solver.check_sat(&mut pool, &[]), Answer::Sat);
        let model = solver.model().expect("model");
        let len_val = model.iter().find_map(|(sym, v)| {
            (pool.symbol(*sym).name == "s!len").then(|| v.as_bv().unwrap().as_u64().unwrap())
        });
        assert_eq!(len_val, Some(3));

        // Adding (bvult ((_ int2bv 64) (str.len s)) 3) contradicts it, and
        // the answer must be a real `unsat`, not `unknown`: the bridged
        // comparison is harvestable, so bound completeness holds.
        let ult3 = pool.mk(Op::BvUlt, &[bridged, three]).unwrap();
        let mut solver2 = Solver::new();
        solver2.declared = vec![s_sym];
        solver2.assert(eq3);
        solver2.assert(ult3);
        assert_eq!(solver2.check_sat(&mut pool, &[]), Answer::Unsat);

        // (= (str.substr s (bv2nat #x01/64) (bv2nat #x02/64)) "bc") with
        // (= s "abcd"): substr positions cross the bridge into the Int world.
        let lit_sym = pool.fresh_symbol("str!\"abcd\"", Sort::Str);
        let lit = pool.var(lit_sym);
        let bc_sym = pool.fresh_symbol("str!\"bc\"", Sort::Str);
        let bc = pool.var(bc_sym);
        let one64 = pool.bv_u64(64, 1);
        let two64 = pool.bv_u64(64, 2);
        let off = pool.other(bv2nat, 0, 0, &[one64], Sort::Int);
        let cnt = pool.other(bv2nat, 0, 0, &[two64], Sort::Int);
        let sub = pool.other(substr, 0, 0, &[s, off, cnt], Sort::Str);
        let s_is = pool.mk(Op::Eq, &[s, lit]).unwrap();
        let sub_is = pool.mk(Op::Eq, &[sub, bc]).unwrap();
        let mut solver3 = Solver::new();
        solver3.declared = vec![s_sym];
        solver3.assert(s_is);
        solver3.assert(sub_is);
        assert_eq!(solver3.check_sat(&mut pool, &[]), Answer::Sat);
        // And the wrong substring is a real unsat.
        let ab_sym = pool.fresh_symbol("str!\"ab\"", Sort::Str);
        let ab = pool.var(ab_sym);
        let sub_is_ab = pool.mk(Op::Eq, &[sub, ab]).unwrap();
        let mut solver4 = Solver::new();
        solver4.declared = vec![s_sym];
        solver4.assert(s_is);
        solver4.assert(sub_is_ab);
        assert_eq!(solver4.check_sat(&mut pool, &[]), Answer::Unsat);
    }

    /// Same script, both encodings forced. `dual = 0.0` builds only the
    /// guarded one; a large cap always builds the alternative as well and
    /// keeps whichever has fewer SAT variables.
    fn run_with_dual(input: &str, dual: f64) -> Vec<Answer> {
        let mut pool = TermPool::new();
        let script = parse_script(input, &mut pool).expect("parse");
        let mut solver = Solver::new();
        solver.dual_encode_max_secs = dual;
        solver.declared = script.declared.clone();
        let mut answers = Vec::new();
        for cmd in &script.commands {
            match cmd {
                Command::Assert(t, _) => solver.assert(*t),
                Command::CheckSat => answers.push(solver.check_sat(&mut pool, &[])),
                _ => {}
            }
        }
        answers
    }

    /// A chain of partial sums, each shared by the next link and by its own
    /// comparison, is exactly the shape the flattening sharing guard exists
    /// for — and exactly the shape the alternative encoding un-nests. The
    /// solver picks between the two by SAT-variable count, so what has to hold
    /// is that the choice cannot change the answer.
    #[test]
    fn shared_sum_chain_agrees_under_both_encodings() {
        let chain = "
            (declare-const a (_ BitVec 16))(declare-const b (_ BitVec 16))
            (declare-const c (_ BitVec 16))(declare-const d (_ BitVec 16))
            (assert (bvult (bvadd a b) #x0100))
            (assert (bvult (bvadd (bvadd a b) c) #x0200))
            (assert (bvult (bvadd (bvadd (bvadd a b) c) d) #x0300))
            (assert (= (bvadd (bvadd (bvadd a b) c) d) #x02ff))
            (check-sat)";
        assert_eq!(run_with_dual(chain, 0.0), vec![Answer::Sat]);
        assert_eq!(run_with_dual(chain, 60.0), vec![Answer::Sat]);

        // The same chain with a contradictory total: 2*(a+b) cannot be odd.
        let refuted = "
            (declare-const a (_ BitVec 16))(declare-const b (_ BitVec 16))
            (assert (= (bvadd (bvadd a b) (bvadd a b)) #x0001))
            (assert (bvult (bvadd a b) #x0100))
            (check-sat)";
        assert_eq!(run_with_dual(refuted, 0.0), vec![Answer::Unsat]);
        assert_eq!(run_with_dual(refuted, 60.0), vec![Answer::Unsat]);
    }

    #[test]
    fn trivial_sat_unsat() {
        let (a, _, _) = run("(declare-const x (_ BitVec 8))(assert (= x #x2a))(check-sat)");
        assert_eq!(a, vec![Answer::Sat]);
        let (a, _, _) =
            run("(declare-const x (_ BitVec 8))(assert (= x #x2a))(assert (= x #x2b))(check-sat)");
        assert_eq!(a, vec![Answer::Unsat]);
    }

    /// Model reconstruction shares one `Evaluator` across every eliminated
    /// variable's defining term. This is the shape that exercises it: a long
    /// chain of top-level equalities, which preprocessing substitutes out, so
    /// the model is rebuilt definition by definition in reverse over cones
    /// that almost entirely coincide. A memo that leaked a stale value between
    /// links would put one link out of step with its own equation, so the test
    /// re-derives the whole chain in Rust from the model's value for `b` and
    /// requires agreement at every link.
    #[test]
    fn long_definition_chain_reconstructs_every_eliminated_variable() {
        const N: usize = 40;
        let mut s = String::from("(declare-const b (_ BitVec 32))\n");
        for i in 0..N {
            s.push_str(&format!("(declare-const t{i} (_ BitVec 32))\n"));
        }
        s.push_str("(assert (= t0 (bvadd b #x00000007)))\n");
        for i in 1..N {
            s.push_str(&format!(
                "(assert (= t{i} (bvadd (bvxor t{p} #x{k:08x}) (bvmul t{p} #x00000003))))\n",
                p = i - 1,
                k = (i as u32).wrapping_mul(2_654_435_761)
            ));
        }
        s.push_str(&format!("(assert (bvult t{} #x80000000))\n", N - 1));
        s.push_str("(check-sat)");

        let (a, pool, solver) = run(&s);
        assert_eq!(a, vec![Answer::Sat]);
        let m = solver.model().unwrap();

        let by_name: FxHashMap<&str, u32> = solver
            .declared
            .iter()
            .map(|sym| {
                let v = m
                    .get(sym)
                    .unwrap_or_else(|| panic!("{} has no value", pool.symbol(*sym).name));
                let n = v.as_bv().expect("bv value").as_u64().expect("32 bits fit") as u32;
                (pool.symbol(*sym).name.as_str(), n)
            })
            .collect();
        assert_eq!(by_name.len(), N + 1, "every declared symbol has a value");

        let mut want = by_name["b"].wrapping_add(7);
        assert_eq!(by_name["t0"], want, "t0 disagrees with its definition");
        for i in 1..N {
            want =
                (want ^ (i as u32).wrapping_mul(2_654_435_761)).wrapping_add(want.wrapping_mul(3));
            assert_eq!(
                by_name[format!("t{i}").as_str()],
                want,
                "t{i} disagrees with its definition"
            );
        }
        assert!(want < 0x8000_0000, "the model must satisfy the bound");
    }

    /// The symbols a model covers are collected *after* the verdict, so this
    /// pins what that collection must still produce: a value for every
    /// declared symbol, including one that appears in no assertion at all and
    /// therefore has no bit-blasted representation to read a value off.
    #[test]
    fn model_covers_declared_symbols_that_appear_in_no_assertion() {
        let (a, pool, solver) = run("(declare-const x (_ BitVec 8))
             (declare-const untouched (_ BitVec 12))
             (declare-const flag Bool)
             (assert (= x #x2a))
             (check-sat)");
        assert_eq!(a, vec![Answer::Sat]);
        let m = solver.model().unwrap();
        for &sym in &solver.declared {
            assert!(
                m.contains_key(&sym),
                "{} missing from the model",
                pool.symbol(sym).name
            );
        }
        let untouched = solver.declared[1];
        assert_eq!(m[&untouched].as_bv().unwrap().as_u64(), Some(0));
        assert_eq!(m[&solver.declared[2]], Value::Bool(false));
    }

    /// An `unsat` answer leaves no model behind, and asking again on the same
    /// solver must not be disturbed by the fact that the refuted check never
    /// collected any model symbols.
    #[test]
    fn an_unsat_check_leaves_no_model_and_does_not_disturb_the_next_one() {
        let mut pool = TermPool::new();
        let script = parse_script(
            "(declare-const x (_ BitVec 8))
             (declare-const y (_ BitVec 8))
             (assert (bvult x #x10))
             (check-sat-assuming ((bvugt x #x20)))
             (check-sat)",
            &mut pool,
        )
        .expect("parse");
        let mut solver = Solver::new();
        solver.declared = script.declared.clone();
        let mut answers = Vec::new();
        for cmd in &script.commands {
            match cmd {
                Command::Assert(t, _) => solver.assert(*t),
                Command::CheckSat => {
                    answers.push(solver.check_sat(&mut pool, &[]));
                    assert!(solver.model().is_some(), "a sat check leaves a model");
                }
                Command::CheckSatAssuming(ts) => {
                    answers.push(solver.check_sat(&mut pool, ts));
                    assert!(solver.model().is_none(), "an unsat check leaves no model");
                }
                _ => {}
            }
        }
        assert_eq!(answers, vec![Answer::Unsat, Answer::Sat]);
        let m = solver.model().unwrap();
        for &sym in &solver.declared {
            assert!(m.contains_key(&sym));
        }
    }

    #[test]
    fn arithmetic_sat() {
        let (a, pool, solver) = run(
            "(declare-const x (_ BitVec 8))(declare-const y (_ BitVec 8))
             (assert (= (bvadd x y) #x0a))
             (assert (bvult x y))
             (assert (= (bvmul x y) #x10))
             (check-sat)",
        );
        assert_eq!(a, vec![Answer::Sat]);
        // Any model with x + y == 10 and x*y == 16 (mod 256) and x < y works
        // (e.g. 2/8 or 130/136); validity is what matters.
        let m = solver.model().unwrap();
        let vals: Vec<u64> = solver
            .declared
            .iter()
            .map(|s| m[s].as_bv().unwrap().as_u64().unwrap())
            .collect();
        let _ = pool;
        assert_eq!((vals[0] + vals[1]) % 256, 10);
        assert_eq!((vals[0] * vals[1]) % 256, 16);
        assert!(vals[0] < vals[1]);
    }

    #[test]
    fn division_by_zero_semantics() {
        // x / 0 == all-ones must be sat (it's the SMT-LIB definition).
        let (a, _, _) = run("(declare-const x (_ BitVec 4))
             (assert (= (bvudiv x #x0) #xf))
             (check-sat)");
        assert_eq!(a, vec![Answer::Sat]);
        let (a, _, _) = run("(declare-const x (_ BitVec 4))
             (assert (distinct (bvurem x #x0) x))
             (check-sat)");
        assert_eq!(a, vec![Answer::Unsat]);
    }

    #[test]
    fn signed_ops() {
        // -6 sdiv 4 == -1 (round toward zero).
        let (a, _, _) = run("(assert (= (bvsdiv #b1010 #b0100) #b1111))
             (check-sat)");
        assert_eq!(a, vec![Answer::Sat]);
        // Symbolic: forall-free check that sdiv matches its definition on a case.
        let (a, _, _) = run("(declare-const x (_ BitVec 6))
             (assert (bvslt x #b000000))
             (assert (= (bvsdiv x #b000010) (bvneg (bvudiv (bvneg x) #b000010))))
             (check-sat)");
        assert_eq!(a, vec![Answer::Sat]);
    }

    #[test]
    fn shifts_and_structure() {
        let (a, _, _) = run(
            "(declare-const x (_ BitVec 8))(declare-const s (_ BitVec 8))
             (assert (= (bvshl x s) #x80))
             (assert (bvuge s #x07))
             (check-sat)",
        );
        assert_eq!(a, vec![Answer::Sat]); // x odd, s = 7
        let (a, _, _) = run("(declare-const x (_ BitVec 8))
             (assert (= (concat ((_ extract 7 4) x) ((_ extract 3 0) x)) (bvnot x))
             )(check-sat)");
        assert_eq!(a, vec![Answer::Unsat]); // x == ~x impossible
    }

    #[test]
    fn push_pop() {
        let (a, _, _) = run("(declare-const x (_ BitVec 4))
             (assert (bvult x #x8))
             (check-sat)
             (push 1)
             (assert (bvugt x #x9))
             (check-sat)
             (pop 1)
             (check-sat)");
        assert_eq!(a, vec![Answer::Sat, Answer::Unsat, Answer::Sat]);
    }

    #[test]
    fn check_sat_assuming() {
        let (a, _, _) = run("(declare-const p Bool)(declare-const x (_ BitVec 4))
             (assert (= p (bvult x #x2)))
             (check-sat-assuming (p (bvugt x #x0)))
             (check-sat-assuming ((not p) (bvult x #x1)))");
        assert_eq!(a, vec![Answer::Sat, Answer::Unsat]);
    }

    #[test]
    fn native_min_max_and_eval_n() {
        let mut pool = TermPool::new();
        let script = parse_script(
            "(declare-const x (_ BitVec 8))
             (assert (bvult x #x10))
             (assert (bvugt x #x02))",
            &mut pool,
        )
        .unwrap();
        let mut solver = Solver::new();
        solver.declared = script.declared.clone();
        for cmd in &script.commands {
            if let Command::Assert(t, _) = cmd {
                solver.assert(*t);
            }
        }
        let x = pool.var(solver.declared[0]);
        assert_eq!(
            solver.minimize(&mut pool, x, &[]).unwrap().as_u64(),
            Some(3)
        );
        assert_eq!(
            solver.maximize(&mut pool, x, &[]).unwrap().as_u64(),
            Some(15)
        );
        // Under an extra assumption.
        let seven = pool.bv_u64(8, 7);
        let above7 = pool.mk(smtrs_core::Op::BvUgt, &[x, seven]).unwrap();
        assert_eq!(
            solver.minimize(&mut pool, x, &[above7]).unwrap().as_u64(),
            Some(8)
        );
        // Assumption must not leak into later queries.
        assert_eq!(
            solver.minimize(&mut pool, x, &[]).unwrap().as_u64(),
            Some(3)
        );
        // Enumerate all 12 values (3..=15), then confirm exhaustion.
        let vals = solver.eval_n(&mut pool, x, 20, &[]);
        let mut got: Vec<u64> = vals.iter().map(|v| v.as_u64().unwrap()).collect();
        got.sort_unstable();
        assert_eq!(got, (3..=15).collect::<Vec<u64>>());
        // Engine still healthy after enumeration (activation retired).
        assert_eq!(solver.check_sat(&mut pool, &[]), Answer::Sat);
        assert_eq!(
            solver.maximize(&mut pool, x, &[]).unwrap().as_u64(),
            Some(15)
        );
        // Bit fixing and enumeration solve the SAT instance directly, so an
        // open push level has to reach them through its activation literal or
        // its assertions are simply not there. `GUARD_AFTER_POPS` empty
        // push/pop pairs first, to get into guarded mode.
        for _ in 0..GUARD_AFTER_POPS {
            solver.push(1);
            solver.pop(1);
        }
        solver.push(1);
        let twelve = pool.bv_u64(8, 12);
        let below12 = pool.mk(smtrs_core::Op::BvUlt, &[x, twelve]).unwrap();
        solver.assert(below12);
        assert_eq!(solver.check_sat(&mut pool, &[]), Answer::Sat);
        assert_eq!(
            solver.maximize(&mut pool, x, &[]).unwrap().as_u64(),
            Some(11)
        );
        let vals = solver.eval_n(&mut pool, x, 20, &[]);
        let mut got: Vec<u64> = vals.iter().map(|v| v.as_u64().unwrap()).collect();
        got.sort_unstable();
        assert_eq!(got, (3..=11).collect::<Vec<u64>>());
        // And the level's constraint is gone again once it is retired.
        solver.pop(1);
        assert_eq!(
            solver.maximize(&mut pool, x, &[]).unwrap().as_u64(),
            Some(15)
        );
    }

    #[test]
    fn fork_preserves_state_and_diverges() {
        let mut pool = TermPool::new();
        let script = parse_script(
            "(declare-const a (_ BitVec 8))
             (assert (bvult a #x80))",
            &mut pool,
        )
        .unwrap();
        let mut s1 = Solver::new();
        s1.declared = script.declared.clone();
        for cmd in &script.commands {
            if let Command::Assert(t, _) = cmd {
                s1.assert(*t);
            }
        }
        assert_eq!(s1.check_sat(&mut pool, &[]), Answer::Sat);

        let a = pool.var(s1.declared[0]);
        let mut s2 = s1.fork();
        // Diverge: s2 constrains a == 5; s1 constrains a == 9.
        let five = pool.bv_u64(8, 5);
        let nine = pool.bv_u64(8, 9);
        let eq5 = pool.mk(smtrs_core::Op::Eq, &[a, five]).unwrap();
        let eq9 = pool.mk(smtrs_core::Op::Eq, &[a, nine]).unwrap();
        s2.assert(eq5);
        s1.assert(eq9);
        assert_eq!(s2.check_sat(&mut pool, &[]), Answer::Sat);
        assert_eq!(s1.check_sat(&mut pool, &[]), Answer::Sat);
        assert_eq!(
            s2.model().unwrap()[&s2.declared[0]]
                .as_bv()
                .unwrap()
                .as_u64(),
            Some(5)
        );
        assert_eq!(
            s1.model().unwrap()[&s1.declared[0]]
                .as_bv()
                .unwrap()
                .as_u64(),
            Some(9)
        );
        // Contradictory branches behave independently.
        let mut s3 = s1.fork();
        let eq5b = pool.mk(smtrs_core::Op::Eq, &[a, five]).unwrap();
        s3.assert(eq5b);
        assert_eq!(s3.check_sat(&mut pool, &[]), Answer::Unsat);
        assert_eq!(s1.check_sat(&mut pool, &[]), Answer::Sat);
    }

    #[test]
    fn floating_point_semantics() {
        // NaN is not equal to itself under fp.eq, but `=` is structural.
        let (a, _, _) = run("(declare-const f Float32)
             (assert (fp.isNaN f))
             (assert (not (fp.eq f f)))
             (check-sat)");
        assert_eq!(a, vec![Answer::Sat]);
        // 1.0 + 1.0 == 2.0 exactly.
        let (a, _, _) = run(
            "(assert (= (fp.to_ieee_bv (fp.add RNE ((_ to_fp 8 24) #x3f800000)
                                                   ((_ to_fp 8 24) #x3f800000)))
                        #x40000000))
             (check-sat)",
        );
        assert_eq!(a, vec![Answer::Sat]);
        // In float32, 0.1 + 0.2 *does* equal 0.3 — the famous inequality is a
        // double-precision fact, and rounding to 24 bits hides it.
        let (a, _, _) = run("(assert (fp.eq (fp.add RNE ((_ to_fp 8 24) #x3dcccccd)
                                        ((_ to_fp 8 24) #x3e4ccccd))
                            ((_ to_fp 8 24) #x3e99999a)))
             (check-sat)");
        assert_eq!(a, vec![Answer::Sat]);
        // At double precision it does not: 0.1 + 0.2 lands one ulp above 0.3.
        let (a, _, _) = run(
            "(assert (fp.eq (fp.add RNE ((_ to_fp 11 53) #x3fb999999999999a)
                                        ((_ to_fp 11 53) #x3fc999999999999a))
                            ((_ to_fp 11 53) #x3fd3333333333333)))
             (check-sat)",
        );
        assert_eq!(a, vec![Answer::Unsat]);
        // Division by zero yields infinity, not an error.
        let (a, _, _) = run("(declare-const x Float32)
             (assert (= x (fp.div RNE ((_ to_fp 8 24) #x3f800000) ((_ to_fp 8 24) #x00000000))))
             (assert (fp.isInfinite x))
             (assert (fp.isPositive x))
             (check-sat)");
        assert_eq!(a, vec![Answer::Sat]);
        // fp.fma rounds once over the exact product. 0x3fc00000 is 1.5, and
        // 1.5*1.5 + 1.5 = 3.75 = 0x40700000 exactly.
        let (a, _, _) = run(
            "(assert (= (fp.to_ieee_bv (fp.fma RNE ((_ to_fp 8 24) #x3fc00000)
                                                   ((_ to_fp 8 24) #x3fc00000)
                                                   ((_ to_fp 8 24) #x3fc00000)))
                        #x40700000))
             (check-sat)",
        );
        assert_eq!(a, vec![Answer::Sat]);
        // Single rounding is the whole point. Here the exact product of
        // -7.5 and 1.6963076410474366e34 lands exactly on a rounding tie;
        // adding 7.0 pushes it just below, so the fused result is one ulp
        // away from rounding the product and the sum separately. (Verified
        // against an exact rational computation — note that a double-precision
        // FMA cannot be used as an oracle here, because the addend falls off
        // the end of a 53-bit significand.)
        let (a, _, _) = run("(assert (distinct
                 (fp.to_ieee_bv (fp.fma RNE ((_ to_fp 8 24) #xc0f00000)
                                            ((_ to_fp 8 24) #x78511608)
                                            ((_ to_fp 8 24) #x40e00000)))
                 (fp.to_ieee_bv (fp.add RNE (fp.mul RNE ((_ to_fp 8 24) #xc0f00000)
                                                        ((_ to_fp 8 24) #x78511608))
                                            ((_ to_fp 8 24) #x40e00000)))))
             (check-sat)");
        assert_eq!(a, vec![Answer::Sat]);
    }

    #[test]
    fn floating_point_remainder() {
        // fp.rem is exact: `x - y*n` with n the *nearest* integer to x/y,
        // ties to even -- so the result can be negative for positive operands.
        // Constant operands are evaluated rather than encoded.
        let rem64 = |x: &str, y: &str, r: &str| {
            format!(
                "(declare-const x Float64) (declare-const y Float64)
                 (assert (= x ((_ to_fp 11 53) {x}))) (assert (= y ((_ to_fp 11 53) {y})))
                 (assert (= (fp.to_ieee_bv (fp.rem x y)) {r})) (check-sat)"
            )
        };
        // 5 rem 2 = 1 (quotient 2.5 ties to the even 2).
        let (a, _, _) = run(&rem64(
            "#x4014000000000000",
            "#x4000000000000000",
            "#x3ff0000000000000",
        ));
        assert_eq!(a, vec![Answer::Sat]);
        // 7 rem 2 = -1 (quotient 3.5 ties to the even 4).
        let (a, _, _) = run(&rem64(
            "#x401c000000000000",
            "#x4000000000000000",
            "#xbff0000000000000",
        ));
        assert_eq!(a, vec![Answer::Sat]);
        // ... and 7 rem 2 is emphatically not +1.
        let (a, _, _) = run(&rem64(
            "#x401c000000000000",
            "#x4000000000000000",
            "#x3ff0000000000000",
        ));
        assert_eq!(a, vec![Answer::Unsat]);
        // An exponent gap of 1000 -- far past what any staged circuit could
        // reach. 2^1000 = 4^500 = 1 (mod 3).
        let (a, _, _) = run(&rem64(
            "#x7e70000000000000",
            "#x4008000000000000",
            "#x3ff0000000000000",
        ));
        assert_eq!(a, vec![Answer::Sat]);
        // y infinite returns x; x infinite is NaN; y zero is NaN.
        let (a, _, _) = run(&rem64(
            "#x3ff0000000000000",
            "#x7ff0000000000000",
            "#x3ff0000000000000",
        ));
        assert_eq!(a, vec![Answer::Sat]);
        let (a, _, _) = run("(declare-const y Float64)
             (assert (= y ((_ to_fp 11 53) #x4000000000000000)))
             (assert (fp.isNaN (fp.rem (_ +oo 11 53) y)))
             (assert (fp.isNaN (fp.rem y (_ +zero 11 53))))
             (check-sat)");
        assert_eq!(a, vec![Answer::Sat]);

        // Symbolic operands go through the reduction circuit instead. Binding
        // through fp.to_ieee_bv keeps the values out of reach of the constant
        // folding, so this exercises the encoding.
        let sym32 = |x: &str, y: &str, r: &str| {
            format!(
                "(declare-const x Float32) (declare-const y Float32)
                 (assert (= (fp.to_ieee_bv x) {x})) (assert (= (fp.to_ieee_bv y) {y}))
                 (assert (= (fp.to_ieee_bv (fp.rem x y)) {r})) (check-sat)"
            )
        };
        let (a, _, _) = run(&sym32("#x40a00000", "#x40000000", "#x3f800000")); // 5 rem 2 = 1
        assert_eq!(a, vec![Answer::Sat]);
        let (a, _, _) = run(&sym32("#x40f00000", "#x40200000", "#x00000000")); // 7.5 rem 2.5 = +0
        assert_eq!(a, vec![Answer::Sat]);
        let (a, _, _) = run(&sym32("#xc1100000", "#x40800000", "#xbf800000")); // -9 rem 4 = -1
        assert_eq!(a, vec![Answer::Sat]);
        // A fully free Float32 remainder is still solvable.
        let (a, _, _) = run("(declare-const x Float32)
             (assert (fp.isZero (fp.rem x x)))
             (check-sat)");
        assert_eq!(a, vec![Answer::Sat]);
        // Float64 needs ~2100 reduction stages, which we decline to build:
        // unknown, never a wrong answer.
        let (a, _, _) = run("(declare-const x Float64) (declare-const y Float64)
             (assert (fp.isZero (fp.rem x y)))
             (check-sat)");
        assert!(matches!(a[0], Answer::Unknown(_)));
    }

    #[test]
    fn bounded_strings() {
        // Satisfiable string constraints are answered concretely.
        let (a, _, _) = run("(declare-const s String)
             (assert (= s (str.++ \"he\" \"llo\")))
             (assert (str.contains s \"ell\"))
             (assert (= (str.len s) 5))
             (check-sat)");
        assert_eq!(a, vec![Answer::Sat]);
        // Every string here is length-constrained below the bound, so the
        // encoding is complete and `unsat` is real.
        let (a, _, _) = run("(declare-const s String)
             (assert (= (str.len s) 3))
             (assert (= (str.len s) 4))
             (check-sat)");
        assert_eq!(a, vec![Answer::Unsat]);
        // With nothing bounding the string, unsatisfiable-within-the-bound must
        // NOT be reported as unsat. Here the two memberships force a length
        // that is a multiple of both 10 and 11, so the shortest model is 110
        // characters long — well outside the bound, and genuinely satisfiable.
        let (a, _, _) = run("(declare-const s String)
             (assert (str.in_re s (re.+ (str.to_re \"abcdefghij\"))))
             (assert (str.in_re s (re.+ (str.to_re \"abcdefghijk\"))))
             (check-sat)");
        assert!(matches!(a[0], Answer::Unknown(_)), "got {:?}", a[0]);
        // A free `Int` variable is encoded in 16 bits, and the comparisons are
        // signed, so `30000 < z < 40000` looks contradictory to the encoding.
        // The formula is satisfiable (z = 35000), so `unsat` must not escape.
        let (a, _, _) = run("(declare-fun z () Int)
             (assert (> z 30000))
             (assert (< z 40000))
             (assert (= (str.len \"ab\") 2))
             (check-sat)");
        assert!(matches!(a[0], Answer::Unknown(_)), "got {:?}", a[0]);
    }

    /// The Int comparisons are `:chainable`: `(< a b c)` means `a < b and
    /// b < c`. Encoding only the first pair dropped the rest of the chain and
    /// produced a *wrong answer* — this query is unsatisfiable (Z3 agrees) and
    /// used to come back `sat`.
    #[test]
    fn chained_int_comparisons_use_every_conjunct() {
        for rel in ["<", "<="] {
            let (a, _, _) = run(&format!(
                "(set-logic QF_SLIA)
                 (declare-const s String)
                 (declare-const t String)
                 (assert ({rel} (str.len s) (str.len t) 3))
                 (assert (> (str.len s) 5))
                 (check-sat)"
            ));
            assert!(
                !matches!(a[0], Answer::Sat),
                "chained {rel} reported sat on an unsatisfiable query: {:?}",
                a[0]
            );
        }
        // The reversed forms chain the same way.
        for rel in [">", ">="] {
            let (a, _, _) = run(&format!(
                "(set-logic QF_SLIA)
                 (declare-const s String)
                 (assert ({rel} 3 (str.len s) 8))
                 (check-sat)"
            ));
            assert!(
                !matches!(a[0], Answer::Sat),
                "chained {rel} reported sat on an unsatisfiable query: {:?}",
                a[0]
            );
        }
        // A satisfiable chain must still be satisfiable.
        let (a, _, _) = run("(set-logic QF_SLIA)
             (declare-const s String)
             (assert (< 1 (str.len s) 5))
             (check-sat)");
        assert_eq!(a, vec![Answer::Sat]);
    }

    /// `(= (op s t r) expected)` is satisfiable. With every operand a literal
    /// the result is fully determined, so this pins the concrete semantics:
    /// `sat` for the right answer and never `sat` for a wrong one. (A wrong
    /// answer comes back as `unknown` rather than `unsat` because the bounded
    /// encoding never reports a trustworthy `unsat`.)
    fn replace_is(op: &str, s: &str, t: &str, r: &str, expected: &str) {
        let query = |out: &str| {
            format!(
                "(set-logic QF_S)(assert (= ({op} \"{s}\" \"{t}\" \"{r}\") \"{out}\"))(check-sat)"
            )
        };
        let (a, _, _) = run(&query(expected));
        assert_eq!(
            a,
            vec![Answer::Sat],
            "({op} {s:?} {t:?} {r:?}) should be {expected:?}"
        );
        for wrong in [format!("{expected}z"), format!("z{expected}")] {
            let (a, _, _) = run(&query(&wrong));
            assert_ne!(
                a,
                vec![Answer::Sat],
                "({op} {s:?} {t:?} {r:?}) wrongly admits {wrong:?}"
            );
        }
    }

    #[test]
    fn str_replace_semantics() {
        // Only the first, leftmost occurrence.
        replace_is("str.replace", "abcabc", "bc", "X", "aXabc");
        replace_is("str.replace", "aaa", "a", "b", "baa");
        // Overlapping candidates: the leftmost wins and consumes both a's.
        replace_is("str.replace", "aaa", "aa", "b", "ba");
        // No occurrence leaves the string alone.
        replace_is("str.replace", "abc", "d", "X", "abc");
        replace_is("str.replace", "ab", "abc", "X", "ab");
        // Empty t prepends t' (note: the opposite of replace_all).
        replace_is("str.replace", "abc", "", "XY", "XYabc");
        replace_is("str.replace", "", "", "XY", "XY");
        // Empty s: only the empty pattern matches.
        replace_is("str.replace", "", "a", "X", "");
        // t' longer than t, so the result grows; and shorter, so it shrinks.
        replace_is("str.replace", "abc", "b", "XYZ", "aXYZc");
        replace_is("str.replace", "abc", "abc", "", "");
        replace_is("str.replace", "abcd", "bc", "", "ad");
    }

    #[test]
    fn str_replace_all_semantics() {
        // Every occurrence, not just the first.
        replace_is("str.replace_all", "abcabc", "bc", "X", "aXaX");
        replace_is("str.replace_all", "aaa", "a", "b", "bbb");
        // Non-overlapping, scanning left to right: "aa" in "aaa" fires once.
        replace_is("str.replace_all", "aaa", "aa", "b", "ba");
        replace_is("str.replace_all", "aaaa", "aa", "b", "bb");
        replace_is("str.replace_all", "aaaaa", "aa", "b", "bba");
        // No occurrence.
        replace_is("str.replace_all", "abc", "d", "X", "abc");
        // Empty t leaves s unchanged -- the opposite of str.replace.
        replace_is("str.replace_all", "abc", "", "XY", "abc");
        replace_is("str.replace_all", "", "", "XY", "");
        replace_is("str.replace_all", "", "a", "X", "");
        // Growing and shrinking replacements.
        replace_is("str.replace_all", "aba", "a", "XY", "XYbXY");
        replace_is("str.replace_all", "abab", "b", "", "aa");
    }

    #[test]
    fn str_replace_symbolic_operands() {
        // Symbolic pattern and replacement (their lengths are not statically
        // known, which is a different code path from the literal case).
        let (a, _, _) = run("(declare-const t String)(declare-const r String)
             (assert (= t \"bc\"))(assert (= r \"XY\"))
             (assert (= (str.replace \"abcabc\" t r) \"aXYabc\"))
             (assert (= (str.replace_all \"abcabc\" t r) \"aXYaXY\"))
             (check-sat)");
        assert_eq!(a, vec![Answer::Sat]);
        // The empty-pattern conventions still hold when t is symbolic.
        let (a, _, _) = run("(declare-const t String)
             (assert (= (str.len t) 0))
             (assert (= (str.replace \"ab\" t \"Z\") \"Zab\"))
             (assert (= (str.replace_all \"ab\" t \"Z\") \"ab\"))
             (check-sat)");
        assert_eq!(a, vec![Answer::Sat]);
        // Solving backwards for the subject string.
        let (a, _, solver) = run("(declare-const x String)
             (assert (= (str.replace_all x \"a\" \"bb\") \"bbcbb\"))
             (check-sat)");
        assert_eq!(a, vec![Answer::Sat]);
        assert!(solver.model().is_some());
        // ...and targets with no preimage at all: replace_all cannot leave an
        // "a" behind, and an empty pattern always prepends the replacement.
        let (a, _, _) = run("(declare-const x String)
             (assert (= (str.replace_all x \"a\" \"bb\") \"bab\"))
             (check-sat)");
        assert_ne!(a, vec![Answer::Sat]);
        let (a, _, _) = run("(declare-const x String)
             (assert (= (str.replace x \"\" \"ab\") \"b\"))
             (check-sat)");
        assert_ne!(a, vec![Answer::Sat]);
    }

    #[test]
    fn wide_bv() {
        let (a, _, solver) = run(
            "(declare-const x (_ BitVec 128))
             (assert (= (bvmul x #x00000000000000000000000000000003) #x00000000000000000000000000000009))
             (check-sat)",
        );
        assert_eq!(a, vec![Answer::Sat]);
        let m = solver.model().unwrap();
        let x = m[&solver.declared[0]].as_bv().unwrap();
        assert_eq!(x.as_u64(), Some(3));
    }

    /// A DAG that doubles at every level under an extract: the shape that
    /// made the rewriter's pushdown rules exponential. Levels are shared, so
    /// the term itself is linear — only a rewriter without a memo blows up.
    fn extract_pushdown_pathology(levels: usize) -> String {
        let mut s = String::from("(declare-const x (_ BitVec 32))\n(assert ");
        let mut cur = String::from("x");
        for i in 1..=levels {
            s.push_str(&format!(
                "(let ((v{i} (bvand (bvxor {cur} (_ bv{k} 32)) (bvadd {cur} (_ bv{k} 32)))))",
                k = 2 * i + 1
            ));
            cur = format!("v{i}");
        }
        s.push_str(&format!("(= ((_ extract 7 0) {cur}) (_ bv0 8))"));
        s.push_str(&")".repeat(levels));
        s.push_str(")\n(check-sat)");
        s
    }

    /// The rewriter must observe the terminate flag. Before it did, this was
    /// the shape that ran without bound: `--timeout-ms` was polled only by
    /// the SAT solver, so a process stuck in the rewriter never stopped.
    /// Answering `unknown` is the contract — never a guess, never a panic.
    #[test]
    fn terminate_flag_is_honoured_on_a_rewriter_heavy_input() {
        let input = extract_pushdown_pathology(64);
        let mut pool = TermPool::new();
        let script = parse_script(&input, &mut pool).expect("parse");
        let mut solver = Solver::new();
        solver.declared = script.declared.clone();
        solver.set_terminate(std::sync::Arc::new(std::sync::atomic::AtomicBool::new(
            true,
        )));
        for cmd in &script.commands {
            if let Command::Assert(t, _) = cmd {
                solver.assert(*t);
            }
        }
        let t0 = std::time::Instant::now();
        let answer = solver.check_sat(&mut pool, &[]);
        assert!(
            matches!(answer, Answer::Unknown(_)),
            "interrupted check must answer unknown, got {answer:?}"
        );
        assert!(t0.elapsed().as_secs_f64() < 10.0, "did not stop promptly");
    }

    /// The same input, uninterrupted, must actually finish: the memo in
    /// `rules::rewrite_node` is what bounds it. At 64 levels the unmemoized
    /// rewriter would need ~2^64 node rewrites, so a regression shows up as a
    /// hang — the armed flag turns that into a failed assertion instead.
    #[test]
    fn rewriter_heavy_input_finishes_within_its_budget() {
        let input = extract_pushdown_pathology(64);
        let mut pool = TermPool::new();
        let script = parse_script(&input, &mut pool).expect("parse");
        let mut solver = Solver::new();
        solver.declared = script.declared.clone();
        let flag = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
        solver.set_terminate(flag.clone());
        std::thread::spawn(move || {
            std::thread::sleep(std::time::Duration::from_secs(30));
            flag.store(true, std::sync::atomic::Ordering::Relaxed);
        });
        for cmd in &script.commands {
            if let Command::Assert(t, _) = cmd {
                solver.assert(*t);
            }
        }
        let answer = solver.check_sat(&mut pool, &[]);
        assert_eq!(answer, Answer::Sat, "expected a real answer inside 30 s");
    }

    /// A small linear system whose third equation defines `z`, so `z` is
    /// substituted away and its model value has to be reconstructed for a
    /// variable that never reached the bit-blaster. (This shape was the
    /// regression test for Gaussian elimination, which was removed in
    /// 2026-07-31 for costing time and gaining nothing; the answers and the
    /// reconstruction still have to be right without it.)
    #[test]
    fn linear_system_answers_and_reconstructs_models() {
        let (a, _, solver) = run("(declare-const x (_ BitVec 16))
             (declare-const y (_ BitVec 16))
             (declare-const z (_ BitVec 16))
             (assert (= (bvadd x y z) #x0064))
             (assert (= (bvadd x (bvmul #x0002 y)) #x004b))
             (assert (= z #x000a))
             (check-sat)");
        assert_eq!(a, vec![Answer::Sat]);
        let m = solver.model().unwrap();
        let v: Vec<u64> = solver
            .declared
            .iter()
            .map(|s| m[s].as_bv().unwrap().as_u64().unwrap())
            .collect();
        let (x, y, z) = (v[0], v[1], v[2]);
        assert_eq!((x + y + z) % 65536, 0x64);
        assert_eq!((x + 2 * y) % 65536, 0x4b);
        assert_eq!(z, 0x0a);
    }

    /// `2x = 3` is unsat and `2x + 2y = 6` has solutions with `x + y = 131` as
    /// well as `x + y = 3`: an even coefficient is a zero divisor in Z/2^w and
    /// no preprocessing step may divide by one.
    #[test]
    fn even_coefficients_are_never_divided_out() {
        let (a, _, solver) = run("(declare-const x (_ BitVec 8))
             (declare-const y (_ BitVec 8))
             (assert (= (bvadd (bvmul #x02 x) (bvmul #x02 y)) #x06))
             (assert (bvult y x))
             (check-sat)");
        assert_eq!(a, vec![Answer::Sat]);
        let m = solver.model().unwrap();
        let v: Vec<u64> = solver
            .declared
            .iter()
            .map(|s| m[s].as_bv().unwrap().as_u64().unwrap())
            .collect();
        assert_eq!((2 * v[0] + 2 * v[1]) % 256, 6);
        assert!(v[1] < v[0]);
        // 2x + 2y = 6 has solutions where x + y is 3 *or* 131; the point is
        // that the solver may not assume the former.
        let (a, _, _) = run("(declare-const x (_ BitVec 8))
             (assert (= (bvmul #x02 x) #x03))
             (check-sat)");
        assert_eq!(a, vec![Answer::Unsat]);
    }

    /// A word equation whose *lengths* alone are contradictory. Neither the
    /// bounded encoding (no length bound exists) nor the Boolean skeleton (one
    /// atom, satisfiable) can see it; the length abstraction reduces it to
    /// `2|t| = 1`, which no integer and no bit-vector residue satisfies.
    #[test]
    fn length_abstraction_refutes_a_word_equation() {
        let (a, _, _) = run(
            "(declare-fun x1 () String)(declare-fun x2 () String)(declare-fun t () String)
             (assert (= (str.++ x1 t t x2) (str.++ x2 \"b\" x1)))(check-sat)",
        );
        assert_eq!(a, vec![Answer::Unsat]);
    }

    /// Two memberships whose languages have disjoint word lengths. The regex
    /// on the left is infinite, so no bound on `x` exists either.
    #[test]
    fn length_abstraction_refutes_a_regex_length_conflict() {
        let (a, _, _) = run("(declare-fun x () String)
             (assert (str.in_re x (re.++ (str.to_re \"aa\") (re.* (str.to_re \"b\")))))
             (assert (str.in_re x (str.to_re \"z\")))(check-sat)");
        assert_eq!(a, vec![Answer::Unsat]);
    }

    /// The abstraction is blind to characters on purpose: a contradiction that
    /// lives in the contents and not the lengths must not be claimed here. (The
    /// bounded encoding settles this one on its own, and correctly.)
    #[test]
    fn length_abstraction_says_nothing_about_a_character_conflict() {
        let (a, _, _) = run("(declare-fun x () String)
             (assert (= x \"a\"))(assert (= x \"b\"))(check-sat)");
        assert_eq!(a, vec![Answer::Unsat]);
        // Same shape, but satisfiable: no over-approximation may refute it.
        let (a, _, _) = run("(declare-fun x () String)(declare-fun y () String)
             (assert (= (str.++ x y) (str.++ y x)))
             (assert (not (str.in_re x (re.* (str.to_re \"a\")))))(check-sat)");
        assert_eq!(a, vec![Answer::Sat]);
    }

    /// The one thing wrapping forbids. `|x| != |y|` is an integer disequality,
    /// and integers that differ can agree modulo `2^32`, so the abstraction may
    /// not emit it as a bit-vector disequality when the lengths are unbounded.
    /// Asserting it together with its negation is unsatisfiable — but only the
    /// *positive* half is available modularly, so the answer must be `unknown`
    /// from the length abstraction and `unsat` only if something else sees it.
    #[test]
    fn length_abstraction_never_reads_a_disequality_modularly() {
        let (a, _, _) = run("(declare-fun x () String)(declare-fun y () String)
             (assert (not (= (str.len x) (str.len y))))
             (assert (= (str.len x) (str.len y)))(check-sat)");
        // Propositionally contradictory, so the Boolean skeleton gets it; what
        // matters is that the answer is not reached by a wrong modular step.
        assert_eq!(a, vec![Answer::Unsat]);
        let (a, _, _) = run("(declare-fun x () String)(declare-fun y () String)
             (assert (not (= (str.len x) (str.len y))))
             (assert (str.prefixof \"aaa\" x))(check-sat)");
        assert!(!matches!(a[0], Answer::Unsat), "got {:?}", a[0]);
    }

    /// The trap the modular reading of the length system is built to avoid.
    /// `2^32` and `0` are different integers but the same 32-bit residue, so a
    /// disequality between them must never be emitted as a bit-vector one —
    /// both of these are satisfiable and the answer may not be `unsat`.
    #[test]
    fn length_abstraction_survives_lengths_that_wrap() {
        for src in [
            "(declare-fun x () String)(declare-fun y () String)
             (assert (= (str.len x) 4294967296))(assert (= (str.len y) 0))
             (assert (distinct (str.len x) (str.len y)))(check-sat)",
            "(declare-fun x () String)(declare-fun y () String)
             (assert (= (str.len x) 4294967296))
             (assert (not (= (str.len x) (str.len y))))
             (assert (= (str.len y) 0))(check-sat)",
            // 2^31 exceeds five, but reads negative as a signed 32-bit vector.
            "(declare-fun x () String)
             (assert (= (str.len x) 2147483648))(assert (> (str.len x) 5))
             (check-sat)",
        ] {
            let (a, _, _) = run(src);
            assert!(!matches!(a[0], Answer::Unsat), "{src} -> {:?}", a[0]);
        }
    }

    /// `bounds::analyze` does not merely set a trustworthiness flag: when it
    /// reports no blocker, `needed_len` *shrinks* the encoding and the result
    /// is then declared complete. So an integer bound that is quietly wrong
    /// does not degrade the answer, it inverts it. Each of these is
    /// satisfiable and each was answered `unsat`.
    #[test]
    fn a_wrapped_integer_bound_never_shrinks_the_encoding() {
        for src in [
            // `int_literal` yields a u64 and `as i64` reinterpreted it, so a
            // numeral just below 2^64 became a small negative bound. The
            // constraint is true of every string; the encoding got one slot.
            "(declare-const x String)
             (assert (not (>= (str.len x) 18446744073709551615)))
             (assert (= (str.len x) 3))(check-sat)",
            // Same defect reached with the positive orientation.
            "(declare-const x String)
             (assert (<= (str.len x) 18446744073709551615))
             (assert (= (str.len x) 3))(check-sat)",
            // The interval fold multiplied without checking: 32^13 = 2^65
            // wrapped to exactly (0, 0), which passes the 16-bit gate and so
            // certifies the encoding's arithmetic as exact. The real product
            // is far above 100.
            "(declare-const a String)
             (assert (<= (str.len a) 32))(assert (>= (str.len a) 32))
             (assert (> (* (str.len a) (str.len a) (str.len a) (str.len a)
                           (str.len a) (str.len a) (str.len a) (str.len a)
                           (str.len a) (str.len a) (str.len a) (str.len a)
                           (str.len a)) 100))(check-sat)",
        ] {
            let (a, _, _) = run(src);
            assert!(!matches!(a[0], Answer::Unsat), "{src} -> {:?}", a[0]);
        }
    }

    /// A `\u` run that is not well-formed hex is ordinary characters, so the
    /// literal is six characters long and cannot equal a three-character one.
    /// Both readers used `from_str_radix` as a validity test, and it accepts a
    /// leading sign, so the literal was read as the single character `A`.
    #[test]
    fn a_signed_unicode_escape_is_not_an_escape() {
        let (a, _, _) = run("(declare-const x String)
             (assert (= (str.len x) 6))(assert (= x \"\\u+041\"))(check-sat)");
        assert_eq!(a, vec![Answer::Sat]);
        let (a, _, _) = run("(declare-const x String)
             (assert (= (str.len x) 1))(assert (= x \"\\u+041\"))(check-sat)");
        assert_eq!(a, vec![Answer::Unsat]);
    }

    /// SMT-LIB corners the length rules have to get right, each satisfiable:
    /// a `str.substr` window past the end is empty rather than negative, a
    /// `str.indexof` whose pattern cannot fit is -1 rather than `|s| - |p|`,
    /// `str.replace_all` may grow its subject, and `(not (< a b c))` says only
    /// that *some* adjacent pair fails.
    #[test]
    fn length_abstraction_gets_the_smtlib_corners_right() {
        for src in [
            "(declare-fun s () String)(assert (<= (str.len s) 2))
             (assert (= (str.len (str.substr s 5 3)) 0))(check-sat)",
            "(declare-fun s () String)(assert (<= (str.len s) 1))
             (assert (= (str.indexof s \"abcd\" 0) (- 1)))(check-sat)",
            "(declare-fun s () String)(assert (= s \"aaa\"))
             (assert (= (str.len (str.replace_all s \"a\" \"bbbb\")) 12))(check-sat)",
            "(declare-fun a () Int)(declare-fun b () Int)(declare-fun c () Int)
             (assert (not (< a b c)))
             (assert (= a 0))(assert (= c 0))(assert (= b 5))(check-sat)",
            // A named atom must reach the intervals with its own polarity.
            "(declare-fun x () String)(declare-fun T () Bool)
             (assert (= T (not (> (str.len x) 10))))(assert (not T))
             (assert (>= (str.len x) 11))(check-sat)",
        ] {
            let (a, _, _) = run(src);
            assert!(!matches!(a[0], Answer::Unsat), "{src} -> {:?}", a[0]);
        }
    }

    /// A rebuild has to re-walk terms an *earlier* prefix already stamped.
    ///
    /// This is the one way [`PrefixScan`] can be wrong that a shrinking prefix
    /// does not already exercise. `clear` empties the stamp array, and `walk`
    /// refills it because the vector is then shorter than the pool. Keep the
    /// array instead — `resize` only ever grows it — and every term the old
    /// prefix touched still reads as folded in, so the rebuild skips it and
    /// loses the fact it carried. Below, the offending term is asserted,
    /// popped, and asserted again: on the way back in it is reached by a prefix
    /// walk that has already seen it once, and skipping it hands an `Int` or a
    /// float straight to the bit-blaster.
    #[test]
    fn prefix_scan_rebuild_rewalks_already_stamped_terms() {
        let (a, _, _) = run("(declare-const b (_ BitVec 8))(declare-const i Int)
             (assert (bvult b #x40))(push 1)(assert (= i 0))(check-sat)
             (pop 1)(check-sat)(assert (= i 0))(check-sat)");
        assert!(matches!(a[0], Answer::Unknown(_)), "{a:?}");
        assert_eq!(a[1], Answer::Sat, "{a:?}");
        assert!(matches!(a[2], Answer::Unknown(_)), "{a:?}");

        let (a, _, _) = run("(declare-const b (_ BitVec 8))(declare-const f Float32)
             (assert (bvult b #x40))(push 1)(assert (fp.isNaN f))(check-sat)
             (pop 1)(check-sat)
             (assert (fp.isNaN f))(assert (not (fp.isNaN f)))(check-sat)");
        assert_eq!(a, vec![Answer::Sat, Answer::Sat, Answer::Unsat], "{a:?}");
    }

    /// The cache must not let a *popped* assertion keep answering.
    ///
    /// Each fact is retracted by the pop that retires the term carrying it, so
    /// each is checked on its own: an `Int` (unsupported), a string (routes to
    /// the bounded lowering), a float (routes to word-blasting), and a variable
    /// that must stop appearing in models.
    #[test]
    fn prefix_scan_facts_do_not_survive_the_pop_that_retires_them() {
        // Unsupported sort: unknown inside the scope, decidable outside it.
        let (a, _, _) = run("(declare-const b (_ BitVec 8))(declare-const i Int)
             (assert (bvult b #x40))(push 1)(assert (> i 3))(check-sat)(pop 1)(check-sat)");
        assert!(matches!(a[0], Answer::Unknown(_)), "{a:?}");
        assert_eq!(a[1], Answer::Sat, "{a:?}");

        // A string assertion pushes the whole problem through the bounded
        // lowering, which replaces `assertions` wholesale. After the pop the
        // remaining BV problem must still be answered as a BV problem.
        let (a, _, _) = run("(declare-const b (_ BitVec 8))(declare-const s String)
             (assert (bvult b #x40))(push 1)(assert (= s \"ab\"))(check-sat)
             (pop 1)(check-sat)(assert (bvugt b #x40))(check-sat)");
        assert_eq!(a, vec![Answer::Sat, Answer::Sat, Answer::Unsat], "{a:?}");

        // Same for a float.
        let (a, _, _) = run("(declare-const b (_ BitVec 8))(declare-const f Float32)
             (assert (bvult b #x40))(push 1)(assert (fp.isNaN f))(check-sat)
             (pop 1)(check-sat)(assert (bvugt b #x40))(check-sat)");
        assert_eq!(a, vec![Answer::Sat, Answer::Sat, Answer::Unsat], "{a:?}");

        // A variable reachable only from a popped assertion is no longer part
        // of the problem; it may still be in `declared`, but a variable that
        // was never declared must not be carried by the cache.
        let (_, _, solver) = run("(declare-const b (_ BitVec 8))
             (assert (bvult b #x40))
             (push 1)(assert (= b (bvadd b #x01)))(check-sat)(pop 1)(check-sat)");
        let model = solver.model().expect("sat");
        assert_eq!(model.len(), 1, "only `b` is in scope: {model:?}");
    }

    /// A pop that is followed by *as many* new assertions as it retired leaves
    /// the assertion vector the same length it was, so the cache's length test
    /// says "still extends" and only the element-by-element comparison catches
    /// it. Found by mutation testing: deleting that comparison broke nothing
    /// else in the suite, including the incremental one.
    #[test]
    fn prefix_scan_notices_a_prefix_that_changed_without_changing_length() {
        // The retired assertion carries "unsupported sort"; its replacement
        // does not, so a stale cache answers `unknown` for a pure BV problem.
        let (a, _, _) = run("(declare-const b (_ BitVec 8))(declare-const i Int)
             (assert (bvult b #x40))
             (push 1)(assert (> i 3))(check-sat)(pop 1)
             (push 1)(assert (bvugt b #x10))(check-sat)");
        assert!(matches!(a[0], Answer::Unknown(_)), "{a:?}");
        assert_eq!(a[1], Answer::Sat, "{a:?}");

        // And the other direction: the replacement carries the fact and the
        // retired assertion did not, so a stale cache answers a problem it
        // cannot encode.
        let (a, _, _) = run("(declare-const b (_ BitVec 8))(declare-const i Int)
             (assert (bvult b #x40))
             (push 1)(assert (bvugt b #x10))(check-sat)(pop 1)
             (push 1)(assert (> i 3))(check-sat)");
        assert_eq!(a[0], Answer::Sat, "{a:?}");
        assert!(matches!(a[1], Answer::Unknown(_)), "{a:?}");
    }

    /// Each check's assumptions get their own stamp, and a term one check
    /// walked has to be walked again by the next.
    ///
    /// Also mutation-found: making every query share one mark leaves the second
    /// of two identical `check-sat-assuming`s seeing an empty DAG and answering
    /// from the assertions alone.
    #[test]
    fn prefix_scan_rewalks_assumptions_on_every_check() {
        let (a, _, _) = run("(declare-const b (_ BitVec 8))(declare-const i Int)
             (assert (bvult b #x40))
             (check-sat-assuming ((> i 3)))
             (check-sat-assuming ((> i 3)))");
        assert!(matches!(a[0], Answer::Unknown(_)), "{a:?}");
        assert!(
            matches!(a[1], Answer::Unknown(_)),
            "first check's stamps \
                                                     swallowed the second: {a:?}"
        );

        // A term an assumption stamped, later *asserted*: it comes into the
        // prefix carrying a fact, and the prefix walk must not skip it because
        // some earlier query already touched it.
        let (a, _, _) = run("(declare-const b (_ BitVec 8))(declare-const i Int)
             (assert (bvult b #x40))
             (check-sat-assuming ((> i 3)))
             (check-sat)
             (assert (> i 3))(check-sat)");
        assert!(matches!(a[0], Answer::Unknown(_)), "{a:?}");
        assert_eq!(a[1], Answer::Sat, "{a:?}");
        assert!(matches!(a[2], Answer::Unknown(_)), "{a:?}");
    }

    /// An assumption's facts belong to *that* check only. A float or a string
    /// assumed once must not make the next check take the lowering path, and
    /// the variables it drags in must not stay in the model set.
    #[test]
    fn prefix_scan_does_not_keep_an_assumption_from_the_previous_check() {
        let mut pool = TermPool::new();
        let script = parse_script(
            "(declare-const b (_ BitVec 8))(declare-const c (_ BitVec 8))
             (assert (bvult b #x40))",
            &mut pool,
        )
        .expect("parse");
        let mut solver = Solver::new();
        // Only `b` is declared, so `c` can reach the model set only through the
        // assumption that mentions it.
        solver.declared = vec![script.declared[0]];
        for cmd in &script.commands {
            if let Command::Assert(t, _) = cmd {
                solver.assert(*t);
            }
        }
        let c = pool.var(script.declared[1]);
        let k = pool.bv_u64(8, 3);
        let q = pool.mk(Op::BvUlt, &[c, k]).expect("well-sorted");

        assert_eq!(solver.check_sat(&mut pool, &[q]), Answer::Sat);
        assert!(
            solver
                .model()
                .expect("sat")
                .contains_key(&script.declared[1]),
            "the assumption's variable needs a value in that check's model"
        );
        assert_eq!(solver.check_sat(&mut pool, &[]), Answer::Sat);
        assert!(
            !solver
                .model()
                .expect("sat")
                .contains_key(&script.declared[1]),
            "a variable only the previous assumption reached is still in the model"
        );
    }
}
