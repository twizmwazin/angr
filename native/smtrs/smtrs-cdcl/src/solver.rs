//! The CDCL solver core.

mod prepro;

use prepro::{ElimEntry, PreproMode};
use std::io::Write as _;

// ---------- basic types ----------

#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug, PartialOrd, Ord)]
pub struct Var(pub u32);

/// Literal: `var << 1 | negated`.
#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug, PartialOrd, Ord)]
pub struct Lit(u32);

impl Lit {
    pub fn new(v: Var, positive: bool) -> Self {
        Lit(v.0 << 1 | (!positive) as u32)
    }

    #[inline]
    pub fn var(self) -> Var {
        Var(self.0 >> 1)
    }

    #[inline]
    pub fn is_positive(self) -> bool {
        self.0 & 1 == 0
    }

    #[inline]
    fn index(self) -> usize {
        self.0 as usize
    }

    /// DIMACS-style signed integer (1-based).
    pub fn to_dimacs(self) -> i32 {
        let v = (self.0 >> 1) as i32 + 1;
        if self.is_positive() {
            v
        } else {
            -v
        }
    }
}

impl std::ops::Not for Lit {
    type Output = Lit;
    #[inline]
    fn not(self) -> Lit {
        Lit(self.0 ^ 1)
    }
}

/// Three-valued assignment. `TRUE.0 ^ sign` gives literal values for free.
#[allow(non_camel_case_types)]
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct lbool(pub u8);

#[allow(non_upper_case_globals)]
impl lbool {
    pub const TRUE: lbool = lbool(0);
    pub const FALSE: lbool = lbool(1);
    pub const UNDEF: lbool = lbool(2);
}

// ---------- clause arena ----------

/// Clause layout in `db`: [len, flags, lit0, lit1, ...].
/// flags: bit0 = learnt, bit1 = deleted, bit2 = protected, bits 3.. = lbd.
type CRef = u32;

const CREF_NONE: CRef = u32::MAX;

fn chrono_threshold() -> u32 {
    // Debug bisection: SMTRS_CDCL_NO_CHRONO disables chronological backtracking.
    if std::env::var_os("SMTRS_CDCL_NO_CHRONO").is_some() {
        u32::MAX
    } else {
        100
    }
}

fn vivify_disabled() -> bool {
    std::env::var_os("SMTRS_CDCL_NO_VIVIFY").is_some()
}

fn trail_reuse_disabled() -> bool {
    std::env::var_os("SMTRS_CDCL_NO_TRAIL_REUSE").is_some()
}

/// Which branching heuristic picks the next decision variable.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum DecisionMode {
    /// Exponential VSIDS over the activity heap (the historical default; kept
    /// for bisection).
    Vsids,
    /// Variable move-to-front (Biere/Ryvchin): a timestamp-ordered queue,
    /// bumped by moving analyzed variables to the front. The default — worth
    /// +4 and +6 solved on two interleaved full-suite passes.
    Vmtf,
    /// Alternate the two on a doubling conflict schedule, the way CaDiCaL and
    /// Kissat alternate their stable/focused branchers.
    ///
    /// The two branchers do *not* see the same conflicts. `bump_var` returns
    /// early while `vmtf_active`, and `vmtf_bump_analyzed` runs only while
    /// `vmtf_active`, so each half updates only its own state and each
    /// brancher resumes from where *it* left off — after 10 000 conflicts of
    /// the other, and then 20 000, and so on. That is deliberate on the VSIDS
    /// side (see `bump_var`), but it applies symmetrically to the queue, and
    /// it is the most likely reason `Alt` measured +4 and then +1 where plain
    /// VMTF measured +6: half of `Alt`'s branching is done on evidence that is
    /// a full interval out of date. Whoever revisits this should try bumping
    /// both structures on every conflict and alternating only the *choice*.
    ///
    /// What the alternation must not break is the VMTF search cursor, which
    /// has to stay current through the VSIDS half or the queue resumes with a
    /// cursor sitting below unassigned variables. That is why `backtrack`
    /// keys its cursor repair off `decision_mode` rather than `vmtf_active`;
    /// `vmtf_next_decision` asserts the invariant.
    Alt,
    /// Conflict-history branching: the same heap, but scores are an
    /// exponential recency-weighted average of a `1/(conflict gap)` reward
    /// (Liang et al.'s CHB) instead of a fixed VSIDS increment.
    ///
    /// Textbook CHB also rewards every *assignment* between conflicts. That is
    /// unaffordable here: this solver runs ~2 000 propagations per conflict, so
    /// per-assignment heap sifting would dominate the whole search. Only the
    /// analyzed variables are rewarded, which keeps the cost identical to a
    /// VSIDS bump.
    Chb,
}

/// `SMTRS_CDCL_DECISION=vmtf|vsids|alt|chb` (default `vmtf`).
fn decision_mode_from_env() -> DecisionMode {
    match std::env::var("SMTRS_CDCL_DECISION").as_deref() {
        Ok("vsids") => DecisionMode::Vsids,
        Ok("alt") => DecisionMode::Alt,
        Ok("chb") => DecisionMode::Chb,
        _ => DecisionMode::Vmtf,
    }
}

/// CHB's step size: starts here and decays towards `CHB_ALPHA_MIN`.
const CHB_ALPHA_START: f64 = 0.4;
const CHB_ALPHA_MIN: f64 = 0.06;

/// Conflicts in the first phase of `DecisionMode::Alt` before the first
/// switch; the interval doubles after every full VSIDS+VMTF cycle.
const ALT_FIRST_INTERVAL: u64 = 10_000;

/// Sentinel for "not in the VMTF queue" / end of queue.
const VMTF_NIL: u32 = u32::MAX;

fn lucky_disabled() -> bool {
    std::env::var_os("SMTRS_CDCL_NO_LUCKY").is_some()
}

pub struct Solver {
    db: Vec<u32>,
    /// watches[l] = clauses in which ¬l is one of the two watched literals.
    watches: Vec<Vec<Watcher>>,
    assign: Vec<lbool>,
    level: Vec<u32>,
    reason: Vec<CRef>,
    trail: Vec<Lit>,
    trail_lim: Vec<u32>,
    qhead: usize,

    activity: Vec<f64>,
    var_inc: f64,
    heap: Vec<Var>,
    heap_pos: Vec<i32>,
    phase: Vec<bool>,

    // ---------- VMTF queue (see `DecisionMode`) ----------
    /// Doubly-linked list of decidable variables, `vmtf_first` = most recently
    /// bumped. `vmtf_prev` points at the higher-stamped neighbour.
    vmtf_prev: Vec<u32>,
    vmtf_next: Vec<u32>,
    /// Monotone timestamp; 0 means "not in the queue" (eliminated).
    vmtf_stamp: Vec<u64>,
    vmtf_first: u32,
    vmtf_last: u32,
    /// Search cursor. Invariant: every unassigned queued variable has a stamp
    /// no greater than the cursor's, so scanning forward from it finds the
    /// highest-stamped unassigned variable.
    vmtf_search: u32,
    vmtf_stamp_next: u64,
    /// Scratch for bumping analyzed variables in stamp order: `(stamp, var)`.
    vmtf_bump_buf: Vec<(u64, u32)>,
    decision_mode: DecisionMode,
    /// Is VMTF the brancher right now? (Always false/true outside `Alt`.)
    vmtf_active: bool,
    /// Conflict count at which `Alt` next switches brancher, and the current
    /// half-cycle length.
    alt_switch_at: u64,
    alt_interval: u64,
    /// CHB step size and per-variable last-rewarded conflict index.
    chb_alpha: f64,
    chb_last_conflict: Vec<u64>,

    /// `add_clause_inner` scratch: the sorted input and the normalized output.
    /// Owned by the solver because the bit-blaster adds one clause per CNF
    /// clause — millions per instance — and a pair of fresh `Vec`s per call
    /// was pure allocator traffic on the hottest handoff we have.
    add_sorted: Vec<Lit>,
    add_out: Vec<Lit>,

    learnts: Vec<CRef>,
    /// Analysis scratch.
    seen: Vec<u8>,
    analyze_toclear: Vec<Lit>,
    min_stack: Vec<Lit>,
    /// Learnt-clause buffer, handed to the caller of `analyze` and handed back.
    analyze_learnt: Vec<Lit>,
    /// Per-level generation stamps for counting an LBD in one pass.
    lbd_stamp: Vec<u64>,
    lbd_gen: u64,

    ok: bool,
    pub conflicts: u64,
    pub decisions: u64,
    pub propagations: u64,
    pub restarts: u64,
    reduce_conflicts_target: u64,
    next_vivify: u64,

    drat: Option<std::io::BufWriter<std::fs::File>>,
    /// Conflict budget for bounded solving (u64::MAX = off).
    conflict_budget: u64,
    chrono_threshold: u32,
    vivify_enabled: bool,
    trail_reuse: bool,
    /// Try the trivial full assignments before the first search (see
    /// `lucky_phases`); cleared once they have been tried.
    lucky_pending: bool,
    /// Which lucky pass answered, 1-based (0 = none). Read by the tests; in
    /// production the same fact shows as an answer with zero conflicts.
    pub lucky_hit: u32,
    // ---------- CNF preprocessing (see solver/prepro.rs) ----------
    prepro_mode: PreproMode,
    /// Conflict count at which preprocessing runs (deferred: see prepro.rs).
    prepro_at_conflicts: u64,
    /// Preprocessing has run at least once.
    preprocessed: bool,
    /// Number of preprocessing/inprocessing passes so far.
    prepro_rounds: u32,
    /// Total passes allowed (1 = preprocess once) and the conflict gap between
    /// them. See `prepro::inprocess_rounds`.
    inprocess_rounds: u32,
    inprocess_interval: u64,
    /// Eliminated variables in elimination order, with the clauses that were
    /// removed with them (for model reconstruction and for restoring).
    elim_stack: Vec<ElimEntry>,
    /// Position in `elim_stack` per variable, -1 when live.
    elim_index: Vec<i32>,
    /// Variables the caller pinned as never-eliminable.
    frozen_vars: Vec<Var>,
    /// True while `assign` holds reconstructed values for eliminated vars.
    model_extended: bool,
    pub prepro_vars_elim: u32,
    pub prepro_clauses_before: u32,
    pub prepro_clauses_after: u32,
    pub prepro_secs: f64,
    pub restored_vars: u64,
    /// Learnt binaries turned into problem clauses by inprocessing.
    pub promoted_binaries: u64,
    /// Variables merged away by equivalent-literal substitution (cumulative).
    pub prepro_vars_merged: u64,
    /// Cooperative termination: checked at every conflict and restart.
    terminate: Option<std::sync::Arc<std::sync::atomic::AtomicBool>>,
    /// Assumption literals that alone are inconsistent with the formula, set
    /// by [`Solver::analyze_final`] when the last `solve` reported FALSE
    /// because an assumption was falsified. Empty means the formula refuted
    /// itself, which is a real and different answer — see
    /// [`Solver::failed_assumptions`].
    failed: Vec<Lit>,
}

impl Clone for Solver {
    /// Fork the solver, preserving all learned state. The DRAT writer and
    /// terminate flag are not inherited.
    fn clone(&self) -> Self {
        Solver {
            db: self.db.clone(),
            watches: self.watches.clone(),
            assign: self.assign.clone(),
            level: self.level.clone(),
            reason: self.reason.clone(),
            trail: self.trail.clone(),
            trail_lim: self.trail_lim.clone(),
            qhead: self.qhead,
            activity: self.activity.clone(),
            var_inc: self.var_inc,
            heap: self.heap.clone(),
            heap_pos: self.heap_pos.clone(),
            phase: self.phase.clone(),
            vmtf_prev: self.vmtf_prev.clone(),
            vmtf_next: self.vmtf_next.clone(),
            vmtf_stamp: self.vmtf_stamp.clone(),
            vmtf_first: self.vmtf_first,
            vmtf_last: self.vmtf_last,
            vmtf_search: self.vmtf_search,
            vmtf_stamp_next: self.vmtf_stamp_next,
            vmtf_bump_buf: Vec::new(),
            decision_mode: self.decision_mode,
            vmtf_active: self.vmtf_active,
            alt_switch_at: self.alt_switch_at,
            alt_interval: self.alt_interval,
            chb_alpha: self.chb_alpha,
            chb_last_conflict: self.chb_last_conflict.clone(),
            add_sorted: Vec::new(),
            add_out: Vec::new(),
            learnts: self.learnts.clone(),
            seen: self.seen.clone(),
            analyze_toclear: self.analyze_toclear.clone(),
            min_stack: self.min_stack.clone(),
            analyze_learnt: Vec::new(),
            lbd_stamp: self.lbd_stamp.clone(),
            lbd_gen: self.lbd_gen,
            ok: self.ok,
            conflicts: self.conflicts,
            decisions: self.decisions,
            propagations: self.propagations,
            restarts: self.restarts,
            reduce_conflicts_target: self.reduce_conflicts_target,
            next_vivify: self.next_vivify,
            drat: None,
            conflict_budget: self.conflict_budget,
            chrono_threshold: self.chrono_threshold,
            vivify_enabled: self.vivify_enabled,
            trail_reuse: self.trail_reuse,
            lucky_pending: self.lucky_pending,
            lucky_hit: self.lucky_hit,
            prepro_mode: self.prepro_mode,
            prepro_at_conflicts: self.prepro_at_conflicts,
            preprocessed: self.preprocessed,
            prepro_rounds: self.prepro_rounds,
            inprocess_rounds: self.inprocess_rounds,
            inprocess_interval: self.inprocess_interval,
            elim_stack: self.elim_stack.clone(),
            elim_index: self.elim_index.clone(),
            frozen_vars: self.frozen_vars.clone(),
            model_extended: self.model_extended,
            prepro_vars_elim: self.prepro_vars_elim,
            prepro_clauses_before: self.prepro_clauses_before,
            prepro_clauses_after: self.prepro_clauses_after,
            prepro_secs: self.prepro_secs,
            restored_vars: self.restored_vars,
            promoted_binaries: self.promoted_binaries,
            prepro_vars_merged: self.prepro_vars_merged,
            terminate: None,
            failed: self.failed.clone(),
        }
    }
}

#[derive(Clone, Copy)]
struct Watcher {
    cref: CRef,
    blocker: Lit,
}

impl Default for Solver {
    fn default() -> Self {
        Self::new()
    }
}

impl Solver {
    pub fn new() -> Self {
        let mode = decision_mode_from_env();
        Solver {
            db: Vec::new(),
            watches: Vec::new(),
            assign: Vec::new(),
            level: Vec::new(),
            reason: Vec::new(),
            trail: Vec::new(),
            trail_lim: Vec::new(),
            qhead: 0,
            activity: Vec::new(),
            var_inc: 1.0,
            heap: Vec::new(),
            heap_pos: Vec::new(),
            phase: Vec::new(),
            vmtf_prev: Vec::new(),
            vmtf_next: Vec::new(),
            vmtf_stamp: Vec::new(),
            vmtf_first: VMTF_NIL,
            vmtf_last: VMTF_NIL,
            vmtf_search: VMTF_NIL,
            vmtf_stamp_next: 0,
            vmtf_bump_buf: Vec::new(),
            decision_mode: mode,
            vmtf_active: mode == DecisionMode::Vmtf,
            alt_switch_at: ALT_FIRST_INTERVAL,
            alt_interval: ALT_FIRST_INTERVAL,
            chb_alpha: CHB_ALPHA_START,
            chb_last_conflict: Vec::new(),
            add_sorted: Vec::new(),
            add_out: Vec::new(),
            learnts: Vec::new(),
            seen: Vec::new(),
            analyze_toclear: Vec::new(),
            min_stack: Vec::new(),
            analyze_learnt: Vec::new(),
            lbd_stamp: vec![0],
            lbd_gen: 0,
            ok: true,
            conflicts: 0,
            decisions: 0,
            propagations: 0,
            restarts: 0,
            reduce_conflicts_target: 2000,
            next_vivify: 30_000,
            drat: None,
            conflict_budget: u64::MAX,
            chrono_threshold: chrono_threshold(),
            vivify_enabled: !vivify_disabled(),
            trail_reuse: !trail_reuse_disabled(),
            lucky_pending: !lucky_disabled(),
            lucky_hit: 0,
            prepro_mode: prepro::prepro_mode_from_env(),
            prepro_at_conflicts: prepro::prepro_at_conflicts(),
            preprocessed: false,
            prepro_rounds: 0,
            inprocess_rounds: prepro::inprocess_rounds(),
            inprocess_interval: prepro::INPROCESS_INTERVAL,
            elim_stack: Vec::new(),
            elim_index: Vec::new(),
            frozen_vars: Vec::new(),
            model_extended: false,
            prepro_vars_elim: 0,
            prepro_clauses_before: 0,
            prepro_clauses_after: 0,
            prepro_secs: 0.0,
            restored_vars: 0,
            promoted_binaries: 0,
            prepro_vars_merged: 0,
            terminate: None,
            failed: Vec::new(),
        }
    }

    /// Pin `v` as never-eliminable (call before the first `solve`). Variables
    /// that are not pinned are still safe to use later: a clause or assumption
    /// mentioning an eliminated variable restores it on demand.
    pub fn freeze(&mut self, v: Var) {
        self.frozen_vars.push(v);
        self.restore_var(v);
    }

    /// Install a cooperative termination flag; when set, `solve` returns
    /// UNDEF at the next conflict boundary. Callable from other threads /
    /// signal handlers via the shared Arc.
    pub fn set_terminate_flag(&mut self, flag: std::sync::Arc<std::sync::atomic::AtomicBool>) {
        self.terminate = Some(flag);
    }

    /// Enable DRAT proof emission to `path` (call before solving).
    pub fn enable_drat(&mut self, path: &str) {
        self.drat = Some(std::io::BufWriter::new(
            std::fs::File::create(path).expect("create DRAT file"),
        ));
    }

    /// Flush any pending DRAT output.
    pub fn flush_drat(&mut self) {
        if let Some(w) = &mut self.drat {
            let _ = w.flush();
        }
    }

    pub fn new_var(&mut self) -> Var {
        let v = Var(self.assign.len() as u32);
        self.assign.push(lbool::UNDEF);
        self.level.push(0);
        self.reason.push(CREF_NONE);
        self.activity.push(0.0);
        self.heap_pos.push(-1);
        self.phase.push(false);
        self.seen.push(0);
        self.elim_index.push(-1);
        self.watches.push(Vec::new());
        self.watches.push(Vec::new());
        self.vmtf_prev.push(VMTF_NIL);
        self.vmtf_next.push(VMTF_NIL);
        self.vmtf_stamp.push(0);
        self.chb_last_conflict.push(0);
        // Decision levels are bounded by the variable count; `lbd_stamp` starts
        // with one slot so that level `num_vars` is still in range.
        self.lbd_stamp.push(0);
        self.heap_insert(v);
        self.vmtf_enqueue(v);
        v
    }

    pub fn num_vars(&self) -> usize {
        self.assign.len()
    }

    #[inline]
    fn value_var(&self, v: Var) -> lbool {
        self.assign[v.0 as usize]
    }

    #[inline]
    pub fn value_lit(&self, l: Lit) -> lbool {
        let a = self.assign[(l.0 >> 1) as usize];
        if a == lbool::UNDEF {
            lbool::UNDEF
        } else {
            lbool(a.0 ^ (l.0 & 1) as u8)
        }
    }

    fn decision_level(&self) -> u32 {
        self.trail_lim.len() as u32
    }

    // ---------- clause db ----------

    fn clause_len(&self, c: CRef) -> usize {
        self.db[c as usize] as usize
    }

    fn clause_lits(&self, c: CRef) -> &[u32] {
        let len = self.db[c as usize] as usize;
        &self.db[c as usize + 2..c as usize + 2 + len]
    }

    #[inline]
    fn lit_at(&self, c: CRef, i: usize) -> Lit {
        Lit(self.db[c as usize + 2 + i])
    }

    fn is_learnt(&self, c: CRef) -> bool {
        self.db[c as usize + 1] & 1 != 0
    }

    fn is_deleted(&self, c: CRef) -> bool {
        self.db[c as usize + 1] & 2 != 0
    }

    fn set_deleted(&mut self, c: CRef) {
        self.db[c as usize + 1] |= 2;
    }

    fn protected(&self, c: CRef) -> bool {
        self.db[c as usize + 1] & 4 != 0
    }

    fn set_protected(&mut self, c: CRef, p: bool) {
        if p {
            self.db[c as usize + 1] |= 4;
        } else {
            self.db[c as usize + 1] &= !4;
        }
    }

    fn lbd(&self, c: CRef) -> u32 {
        self.db[c as usize + 1] >> 3
    }

    fn alloc_clause(&mut self, lits: &[Lit], learnt: bool, lbd: u32) -> CRef {
        let c = self.db.len() as CRef;
        self.db.push(lits.len() as u32);
        self.db.push(lbd << 3 | learnt as u32);
        for &l in lits {
            self.db.push(l.0);
        }
        c
    }

    fn watch_clause(&mut self, c: CRef) {
        let l0 = self.lit_at(c, 0);
        let l1 = self.lit_at(c, 1);
        self.watches[(!l0).index()].push(Watcher {
            cref: c,
            blocker: l1,
        });
        self.watches[(!l1).index()].push(Watcher {
            cref: c,
            blocker: l0,
        });
    }

    fn unwatch_clause(&mut self, c: CRef) {
        for i in 0..2 {
            let l = self.lit_at(c, i);
            let ws = &mut self.watches[(!l).index()];
            if let Some(pos) = ws.iter().position(|w| w.cref == c) {
                ws.swap_remove(pos);
            }
        }
    }

    fn drat_add(&mut self, lits: &[Lit]) {
        if let Some(w) = &mut self.drat {
            for &l in lits {
                write!(w, "{} ", l.to_dimacs()).unwrap();
            }
            writeln!(w, "0").unwrap();
        }
    }

    fn drat_comment(&mut self, msg: &str) {
        if let Some(w) = &mut self.drat {
            writeln!(w, "c {msg}").unwrap();
        }
    }

    fn drat_delete(&mut self, c: CRef) {
        if let Some(w) = &mut self.drat {
            write!(w, "d ").unwrap();
            let len = self.db[c as usize] as usize;
            for i in 0..len {
                let l = Lit(self.db[c as usize + 2 + i]);
                write!(w, "{} ", l.to_dimacs()).unwrap();
            }
            writeln!(w, "0").unwrap();
        }
    }

    /// Add a problem clause (any time; the previous model's trail is
    /// discarded first — assignments above level 0 are search state, not
    /// facts).
    pub fn add_clause(&mut self, lits: &[Lit]) {
        self.clear_extended_model();
        // A clause over an eliminated variable would be unsound: the clauses
        // that constrained it are gone. Put them back first.
        self.restore_lits(lits);
        self.add_clause_inner(lits);
    }

    fn add_clause_inner(&mut self, lits: &[Lit]) {
        // Normalization below reads level-0 values; a reconstructed model must
        // never be mistaken for one (see prepro::clear_extended_model).
        debug_assert!(!self.model_extended);
        self.backtrack(0);
        if !self.ok {
            return;
        }
        // Normalize: dedup, drop false lits, detect tautology/satisfied.
        //
        // The two buffers are solver-owned and reused. Taking them out and
        // putting them back is safe under re-entry (nothing reachable from
        // here calls back in, but a re-entrant call would simply find an empty
        // buffer and allocate its own), and `clear` before use is what makes
        // that true rather than merely likely.
        let mut sorted = std::mem::take(&mut self.add_sorted);
        let mut cl = std::mem::take(&mut self.add_out);
        sorted.clear();
        sorted.extend_from_slice(lits);
        sorted.sort_unstable();
        sorted.dedup();
        cl.clear();
        // Satisfied at level 0, or a tautology: either way the clause is
        // dropped. Recorded rather than returned early so the buffers go back.
        let mut dropped = false;
        for &l in &sorted {
            match self.value_lit(l) {
                lbool::TRUE => {
                    dropped = true; // satisfied at level 0
                    break;
                }
                lbool::FALSE => continue,
                _ => {}
            }
            // Dropping tautologies is **load-bearing, not an optimization**:
            // `propagate` hoists `watches[p]` into a local and argues nothing
            // in its inner loop can write that same list, because `¬lk == p`
            // would put `lk` at clause index 1 — an argument that holds only
            // while no clause reaching the watch lists carries both `l` and
            // `!l`. A false negative here is silent corruption, not a
            // redundant clause. So this search must stay exact.
            //
            // It is exact: `sorted` was just sorted and deduplicated with the
            // same `Ord` (`Lit` is a newtype over the packed `u32`), which is
            // what lets the binary search replace the linear scan this used to
            // do. AND-tree collapsing emits clauses of up to 65 literals, where
            // the scan was quadratic. `clause_normalization_vs_brute_force` in
            // smtrs-sat covers the sortedness dependence specifically — the
            // older random-CNF differential does not catch losing the sort.
            // (A single adjacency walk doing dedup and this test together was
            // also written and measured: 1 % on the handoff microbenchmark,
            // inside its noise, and not worth the subtler argument.)
            if sorted.binary_search(&!l).is_ok() {
                dropped = true; // tautology
                break;
            }
            cl.push(l);
        }
        if !dropped {
            match cl.len() {
                0 => {
                    self.ok = false;
                }
                1 => {
                    self.enqueue(cl[0], CREF_NONE);
                    if self.propagate().is_some() {
                        self.ok = false;
                    }
                }
                _ => {
                    let c = self.alloc_clause(&cl, false, 0);
                    self.watch_clause(c);
                }
            }
        }
        self.add_sorted = sorted;
        self.add_out = cl;
    }

    // ---------- VSIDS heap ----------

    fn heap_insert(&mut self, v: Var) {
        if self.heap_pos[v.0 as usize] >= 0 {
            return;
        }
        self.heap.push(v);
        self.heap_pos[v.0 as usize] = (self.heap.len() - 1) as i32;
        self.heap_up(self.heap.len() - 1);
    }

    fn heap_up(&mut self, mut i: usize) {
        while i > 0 {
            let parent = (i - 1) / 2;
            if self.activity[self.heap[i].0 as usize] > self.activity[self.heap[parent].0 as usize]
            {
                self.heap_swap(i, parent);
                i = parent;
            } else {
                break;
            }
        }
    }

    fn heap_down(&mut self, mut i: usize) {
        loop {
            let (l, r) = (2 * i + 1, 2 * i + 2);
            let mut best = i;
            if l < self.heap.len()
                && self.activity[self.heap[l].0 as usize]
                    > self.activity[self.heap[best].0 as usize]
            {
                best = l;
            }
            if r < self.heap.len()
                && self.activity[self.heap[r].0 as usize]
                    > self.activity[self.heap[best].0 as usize]
            {
                best = r;
            }
            if best == i {
                break;
            }
            self.heap_swap(i, best);
            i = best;
        }
    }

    fn heap_swap(&mut self, i: usize, j: usize) {
        self.heap.swap(i, j);
        self.heap_pos[self.heap[i].0 as usize] = i as i32;
        self.heap_pos[self.heap[j].0 as usize] = j as i32;
    }

    /// Remove `v` from the decision heap (used for eliminated variables).
    fn heap_remove(&mut self, v: Var) {
        let pos = self.heap_pos[v.0 as usize];
        if pos < 0 {
            return;
        }
        let i = pos as usize;
        self.heap_pos[v.0 as usize] = -1;
        let last = self.heap.pop().unwrap();
        if i < self.heap.len() {
            self.heap[i] = last;
            self.heap_pos[last.0 as usize] = i as i32;
            self.heap_down(i);
            self.heap_up(i);
        }
    }

    fn heap_pop(&mut self) -> Option<Var> {
        if self.heap.is_empty() {
            return None;
        }
        let top = self.heap[0];
        self.heap_pos[top.0 as usize] = -1;
        let last = self.heap.pop().unwrap();
        if !self.heap.is_empty() {
            self.heap[0] = last;
            self.heap_pos[last.0 as usize] = 0;
            self.heap_down(0);
        }
        Some(top)
    }

    fn bump_var(&mut self, v: Var) {
        // While VMTF is branching, VSIDS state is frozen entirely: activities
        // are not bumped and `var_inc` is not decayed, so the heap keeps the
        // order it had when VMTF took over (and `var_inc` cannot run away to
        // infinity over a long unbumped stretch).
        if self.vmtf_active {
            return;
        }
        if self.decision_mode == DecisionMode::Chb {
            self.bump_var_chb(v);
            return;
        }
        let a = &mut self.activity[v.0 as usize];
        *a += self.var_inc;
        if *a > 1e100 {
            for act in self.activity.iter_mut() {
                *act *= 1e-100;
            }
            self.var_inc *= 1e-100;
        }
        let pos = self.heap_pos[v.0 as usize];
        if pos >= 0 {
            self.heap_up(pos as usize);
        }
    }

    /// CHB reward: recent conflict participation is worth more. Scores live in
    /// [0,1), so unlike VSIDS this never needs rescaling.
    fn bump_var_chb(&mut self, v: Var) {
        let i = v.0 as usize;
        let gap = (self.conflicts - self.chb_last_conflict[i] + 1) as f64;
        self.chb_last_conflict[i] = self.conflicts;
        let a = &mut self.activity[i];
        let new = (1.0 - self.chb_alpha) * *a + self.chb_alpha / gap;
        let dropped = new < *a;
        *a = new;
        let pos = self.heap_pos[i];
        if pos >= 0 {
            // A reward can lower the score, so sift both ways.
            if dropped {
                self.heap_down(pos as usize);
            } else {
                self.heap_up(pos as usize);
            }
        }
    }

    fn decay_var_activity(&mut self) {
        if self.vmtf_active {
            return;
        }
        if self.decision_mode == DecisionMode::Chb {
            self.chb_alpha = (self.chb_alpha - 1e-6).max(CHB_ALPHA_MIN);
            return;
        }
        self.var_inc /= 0.95;
    }

    // ---------- VMTF queue ----------

    /// Link `v` at the front of the queue with a fresh (maximal) stamp.
    /// Unassigned variables become the search cursor, which must never sit
    /// below an unassigned variable.
    fn vmtf_enqueue(&mut self, v: Var) {
        let i = v.0 as usize;
        self.vmtf_stamp_next += 1;
        self.vmtf_stamp[i] = self.vmtf_stamp_next;
        self.vmtf_prev[i] = VMTF_NIL;
        self.vmtf_next[i] = self.vmtf_first;
        if self.vmtf_first != VMTF_NIL {
            self.vmtf_prev[self.vmtf_first as usize] = v.0;
        } else {
            self.vmtf_last = v.0;
        }
        self.vmtf_first = v.0;
        if self.assign[i] == lbool::UNDEF {
            self.vmtf_search = v.0;
        }
    }

    /// Unlink `v` (it has been eliminated, and must never be decided on).
    fn vmtf_dequeue(&mut self, v: Var) {
        let i = v.0 as usize;
        if self.vmtf_stamp[i] == 0 {
            return;
        }
        let (p, n) = (self.vmtf_prev[i], self.vmtf_next[i]);
        if p == VMTF_NIL {
            self.vmtf_first = n;
        } else {
            self.vmtf_next[p as usize] = n;
        }
        if n == VMTF_NIL {
            self.vmtf_last = p;
        } else {
            self.vmtf_prev[n as usize] = p;
        }
        if self.vmtf_search == v.0 {
            // Lower stamps only: anything above the cursor is assigned or gone.
            self.vmtf_search = n;
        }
        self.vmtf_prev[i] = VMTF_NIL;
        self.vmtf_next[i] = VMTF_NIL;
        self.vmtf_stamp[i] = 0;
    }

    /// Move `v` to the front (VMTF's equivalent of a VSIDS bump).
    fn vmtf_move_to_front(&mut self, v: Var) {
        if self.vmtf_stamp[v.0 as usize] == 0 || self.vmtf_first == v.0 {
            return;
        }
        self.vmtf_dequeue(v);
        self.vmtf_enqueue(v);
    }

    /// Bump every variable seen during conflict analysis, oldest stamp first,
    /// so the queue front ends up ordered by recency within the conflict.
    ///
    /// The stamp is materialised into the sort key rather than read through
    /// `sort_unstable_by_key`: that form re-reads `vmtf_stamp[v]` on *every
    /// comparison*, which is a random load into an array the size of the
    /// variable count, and this sort is per conflict. Sorting `(stamp, var)`
    /// pairs makes the comparisons local and leaves the resulting queue order
    /// identical — stamps are unique among queued variables, and the only ties
    /// are at stamp 0, where `vmtf_move_to_front` is a no-op.
    fn vmtf_bump_analyzed(&mut self) {
        let mut buf = std::mem::take(&mut self.vmtf_bump_buf);
        buf.clear();
        buf.extend(self.analyze_toclear.iter().map(|l| {
            let v = l.var();
            (self.vmtf_stamp[v.0 as usize], v.0)
        }));
        buf.sort_unstable();
        for &(_, v) in buf.iter() {
            self.vmtf_move_to_front(Var(v));
        }
        self.vmtf_bump_buf = buf;
    }

    /// Highest-stamped unassigned variable, advancing the search cursor.
    fn vmtf_next_decision(&mut self) -> Option<Var> {
        let mut v = self.vmtf_search;
        while v != VMTF_NIL {
            if self.assign[v as usize] == lbool::UNDEF {
                self.vmtf_search = v;
                return Some(Var(v));
            }
            v = self.vmtf_next[v as usize];
        }
        // `None` is the one answer that is not self-correcting: `solve` reads
        // it as "every variable is assigned" and returns a *model*. If the
        // cursor had drifted below an unassigned variable this scan would miss
        // it and we would report `sat` on a partial assignment — silently, and
        // only on the instances where the drift happened. So the cursor
        // invariant is checked here rather than trusted. It costs one sweep
        // per model (and per restart with nothing left to decide), which is
        // why it can afford to be exhaustive.
        //
        // The invariant is not maintained by this module alone: `backtrack` is
        // what restores the cursor after the trail shrinks, and it does so
        // whenever `decision_mode` is not `Vsids` — not merely when VMTF is
        // the current brancher — so that `Alt`'s VSIDS half and a `lucky_pass`
        // walk in any mode both keep it current. That coupling is invisible
        // from either side; this is where it gets tested.
        #[cfg(debug_assertions)]
        {
            let cursor_stamp = if self.vmtf_search == VMTF_NIL {
                0
            } else {
                self.vmtf_stamp[self.vmtf_search as usize]
            };
            for i in 0..self.num_vars() {
                // stamp 0 = not queued (eliminated); those are never decided
                // and `extend_model` gives them values.
                assert!(
                    !(self.vmtf_stamp[i] != 0
                        && self.assign[i] == lbool::UNDEF
                        && self.vmtf_stamp[i] > cursor_stamp),
                    "VMTF cursor (var {}, stamp {cursor_stamp}) sits below \
                     unassigned var {i} (stamp {}): a partial assignment is \
                     about to be reported as a model",
                    self.vmtf_search,
                    self.vmtf_stamp[i],
                );
            }
        }
        None
    }

    // ---------- trail ----------

    #[inline]
    fn enqueue(&mut self, l: Lit, reason: CRef) {
        debug_assert_eq!(self.value_lit(l), lbool::UNDEF);
        let v = (l.0 >> 1) as usize;
        self.assign[v] = lbool((l.0 & 1) as u8); // TRUE ^ sign
        self.level[v] = self.decision_level();
        self.reason[v] = reason;
        self.phase[v] = l.is_positive();
        self.trail.push(l);
    }

    /// Backtrack to `target` level. Level-aware: with chronological
    /// backtracking, trail entries can carry levels lower than their trail
    /// position; those are preserved (in order).
    fn backtrack(&mut self, target: u32) {
        if self.decision_level() <= target {
            return;
        }
        let cut = self.trail_lim[target as usize] as usize;
        let mut kept: Vec<Lit> = Vec::new();
        for i in cut..self.trail.len() {
            let l = self.trail[i];
            let v = (l.0 >> 1) as usize;
            if self.level[v] <= target {
                kept.push(l);
            } else {
                self.assign[v] = lbool::UNDEF;
                self.reason[v] = CREF_NONE;
                self.heap_insert(Var(v as u32));
                // VMTF cursor must not sit below any unassigned variable.
                if self.decision_mode != DecisionMode::Vsids {
                    let stamp = self.vmtf_stamp[v];
                    if stamp != 0
                        && (self.vmtf_search == VMTF_NIL
                            || stamp > self.vmtf_stamp[self.vmtf_search as usize])
                    {
                        self.vmtf_search = v as u32;
                    }
                }
            }
        }
        self.trail.truncate(cut);
        self.trail.extend_from_slice(&kept);
        self.trail_lim.truncate(target as usize);
        self.qhead = cut.min(self.qhead).min(self.trail.len());
    }

    // ---------- propagation ----------

    fn propagate(&mut self) -> Option<CRef> {
        while self.qhead < self.trail.len() {
            let p = self.trail[self.qhead];
            self.qhead += 1;
            self.propagations += 1;

            // Move the watch list of `p` into a local: the inner loop reads it
            // once per watcher and re-resolving `self.watches[p.index()]`
            // through two pointers plus a bounds check each time was 7 % of
            // total runtime on a search-bound instance. Nothing in the loop can
            // reach this list — the only list written is `(!lk)` for a literal
            // at clause index >= 2, and `¬lk == p` would mean `lk` is the
            // literal already at index 1, which `add_clause_inner`'s
            // deduplication rules out. It is put back before every exit.
            let mut ws = std::mem::take(&mut self.watches[p.index()]);
            let mut conflict: Option<CRef> = None;

            let mut i = 0;
            'watchers: while i < ws.len() {
                let w = ws[i];
                if self.value_lit(w.blocker) == lbool::TRUE {
                    i += 1;
                    continue;
                }
                let c = w.cref;
                if self.is_deleted(c) {
                    ws.swap_remove(i);
                    continue;
                }
                // Ensure the false literal (¬p) is at position 1.
                let not_p = !p;
                let base = c as usize + 2;
                if self.lit_at(c, 0) == not_p {
                    self.db.swap(base, base + 1);
                }
                debug_assert_eq!(self.lit_at(c, 1), not_p);
                let first = self.lit_at(c, 0);
                if first != w.blocker && self.value_lit(first) == lbool::TRUE {
                    ws[i].blocker = first;
                    i += 1;
                    continue;
                }
                // Look for a new watch.
                let len = self.clause_len(c);
                for k in 2..len {
                    let lk = self.lit_at(c, k);
                    if self.value_lit(lk) != lbool::FALSE {
                        debug_assert_ne!((!lk).index(), p.index());
                        self.db.swap(base + 1, base + k);
                        self.watches[(!lk).index()].push(Watcher {
                            cref: c,
                            blocker: first,
                        });
                        ws.swap_remove(i);
                        continue 'watchers;
                    }
                }
                // No new watch: unit or conflict on `first`.
                if self.value_lit(first) == lbool::FALSE {
                    self.qhead = self.trail.len();
                    conflict = Some(c);
                    break;
                }
                self.enqueue(first, c);
                i += 1;
            }

            self.watches[p.index()] = ws;
            if conflict.is_some() {
                return conflict;
            }
        }
        None
    }

    // ---------- conflict analysis ----------

    /// Max assignment level among a conflict clause's literals.
    fn conflict_level(&self, confl: CRef) -> u32 {
        self.clause_lits(confl)
            .iter()
            .map(|&raw| self.level[(raw >> 1) as usize])
            .max()
            .unwrap_or(0)
    }

    /// First-UIP learning. Returns (learnt clause with asserting literal
    /// first, backjump level, lbd).
    fn analyze(&mut self, confl: CRef) -> (Vec<Lit>, u32, u32) {
        let dl = self.decision_level();
        // Reuse the previous conflict's buffer: a fresh `vec![Lit(0)]` per
        // conflict re-enters the allocator and then grows one literal at a
        // time. The caller hands it back (`self.analyze_learnt = learnt`).
        let mut learnt = std::mem::take(&mut self.analyze_learnt);
        learnt.clear();
        learnt.push(Lit(0)); // placeholder for UIP
        let mut counter = 0u32;
        let mut p: Option<Lit> = None;
        let mut idx = self.trail.len();
        let mut cur = confl;

        loop {
            debug_assert_ne!(cur, CREF_NONE);
            // Bump learnt clause LBD-improvement protection.
            if self.is_learnt(cur) {
                self.set_protected(cur, true);
            }
            let len = self.clause_len(cur);
            let start = if p.is_some() { 1 } else { 0 };
            for k in start..len {
                let q = self.lit_at(cur, k);
                let v = (q.0 >> 1) as usize;
                if self.seen[v] == 0 && self.level[v] > 0 {
                    self.seen[v] = 1;
                    self.analyze_toclear.push(q);
                    self.bump_var(Var(v as u32));
                    if self.level[v] >= dl {
                        counter += 1;
                    } else {
                        learnt.push(q);
                    }
                }
            }
            // Next literal to resolve on: most recent seen trail literal at
            // the conflict level. With chronological backtracking, preserved
            // out-of-order entries mean seen literals *below* dl can sit
            // above the last decision — those belong to the learnt clause
            // and must NOT be resolved on (their seen flags stay set).
            loop {
                idx -= 1;
                let v = (self.trail[idx].0 >> 1) as usize;
                if self.seen[v] != 0 && self.level[v] >= dl {
                    break;
                }
            }
            let pl = self.trail[idx];
            let v = (pl.0 >> 1) as usize;
            cur = self.reason[v];
            self.seen[v] = 0;
            counter -= 1;
            p = Some(pl);
            if counter == 0 {
                break;
            }
        }
        learnt[0] = !p.unwrap();

        // Recursive minimization: drop literals implied by the rest.
        let abstract_levels: u64 = learnt[1..].iter().fold(0, |acc, &l| {
            acc | 1 << (self.level[(l.0 >> 1) as usize] & 63)
        });
        let mut j = 1;
        for i in 1..learnt.len() {
            let l = learnt[i];
            if self.reason[(l.0 >> 1) as usize] == CREF_NONE
                || !self.lit_redundant(l, abstract_levels)
            {
                learnt[j] = l;
                j += 1;
            }
        }
        learnt.truncate(j);

        // Backjump level: max level among non-asserting literals.
        let mut bj = 0u32;
        let mut max_i = 1;
        for (i, &l) in learnt.iter().enumerate().skip(1) {
            let lv = self.level[(l.0 >> 1) as usize];
            if lv > bj {
                bj = lv;
                max_i = i;
            }
        }
        if learnt.len() > 1 {
            learnt.swap(1, max_i); // watched pair = asserting + highest level
        }

        // LBD = number of distinct levels. Counted with a generation-stamped
        // array rather than collect/sort/dedup, which allocated and sorted once
        // per conflict for a number that is a linear scan.
        //
        // `lbd_stamp` grows with `new_var` on the theory that levels are
        // bounded by the variable count — but that is false under assumptions:
        // `solve` opens one level per assumption *index*, including an empty
        // pseudo-level when the assumption is already satisfied, so a caller
        // stacking many (possibly repeated or forced) assumption literals can
        // push the decision level past the variable count. The bit-fixing
        // minimize/eval_n loops in smtrs-solver do exactly that. Learnt-clause
        // levels are bounded by the current decision level, so covering it is
        // always enough.
        if self.lbd_stamp.len() <= self.decision_level() as usize {
            self.lbd_stamp.resize(self.decision_level() as usize + 1, 0);
        }
        self.lbd_gen += 1;
        let gen = self.lbd_gen;
        let mut lbd = 0u32;
        for &l in learnt.iter() {
            let lv = self.level[(l.0 >> 1) as usize] as usize;
            if self.lbd_stamp[lv] != gen {
                self.lbd_stamp[lv] = gen;
                lbd += 1;
            }
        }

        // VMTF's bump: every analyzed variable moves to the front of the
        // queue, oldest first. (VSIDS bumped them in the resolution loop.)
        if self.vmtf_active {
            self.vmtf_bump_analyzed();
        }

        for &l in &self.analyze_toclear {
            self.seen[(l.0 >> 1) as usize] = 0;
        }
        self.analyze_toclear.clear();

        (learnt, bj, lbd)
    }

    /// Assumption literals whose conjunction with the clause database is
    /// unsatisfiable, after the last `solve` returned FALSE.
    ///
    /// **Empty is not "no information".** It means the clause database refuted
    /// itself without help from any assumption, so the answer is unsat for
    /// every assumption set — including the empty one. A caller that reads an
    /// empty result as "the extraction failed" and falls back to *all*
    /// assumptions is merely imprecise; one that reads a non-empty result as
    /// approximate is wrong, because the set is exact in the sense that
    /// matters: `clauses ∧ ⋀ failed` is unsatisfiable.
    ///
    /// Only meaningful immediately after `solve` reported FALSE.
    pub fn failed_assumptions(&self) -> &[Lit] {
        &self.failed
    }

    /// Standard `analyze_final`: record which assumptions forced `¬a`, given
    /// that assumption `a` is already false under the current trail.
    ///
    /// The implication graph is walked backwards from `¬a`, replacing each
    /// implied literal by the literals of its reason clause, until only
    /// decisions remain. `solve` decides the whole assumption prefix before it
    /// branches and detects the failure at re-decision time, so every decision
    /// on the trail at this moment *is* an assumption — which is what makes
    /// the collected decisions exactly the responsible assumptions.
    ///
    /// Soundness of the result: the collected set S satisfies `clauses ∧ ⋀ S ⊨
    /// ¬a` by construction (it is a resolution derivation read off the trail),
    /// and `a ∈ S`, so `clauses ∧ ⋀ S` is unsatisfiable. Literals assigned at
    /// level 0 are skipped because they hold unconditionally; that is what
    /// keeps assumption-independent implications out of the set rather than
    /// silently attributing them to whichever assumption came first.
    fn analyze_final(&mut self, a: Lit) {
        self.failed.clear();
        self.failed.push(a);
        let av = (a.0 >> 1) as usize;
        // `¬a` holds at level 0: nothing but the formula is responsible.
        if self.decision_level() == 0 || self.level[av] == 0 {
            return;
        }
        self.seen[av] = 1;
        let start = self.trail_lim[0] as usize;
        for i in (start..self.trail.len()).rev() {
            let l = self.trail[i];
            let v = (l.0 >> 1) as usize;
            if self.seen[v] == 0 {
                continue;
            }
            self.seen[v] = 0;
            if self.level[v] == 0 {
                continue;
            }
            let r = self.reason[v];
            if r == CREF_NONE {
                // A decision, i.e. an assumption: it is in the failed set as
                // itself (the trail holds the literal that was assumed).
                self.failed.push(l);
            } else {
                // `lit_at(r, 0)` is the implied literal; the rest is the
                // antecedent, exactly as in `analyze`/`lit_redundant`.
                for k in 1..self.clause_len(r) {
                    let q = self.lit_at(r, k);
                    let qv = (q.0 >> 1) as usize;
                    if self.level[qv] > 0 {
                        self.seen[qv] = 1;
                    }
                }
            }
        }
        // The walk stops at `trail_lim[0]`, so marks left on literals below it
        // survive the loop. Only variables reachable through reason clauses
        // are ever marked, and every such clause is an antecedent of something
        // the walk visits, so clearing along the way plus the seed covers all
        // of them — except the seed itself, which may sit below the cut.
        self.seen[av] = 0;
        debug_assert!(
            self.seen.iter().all(|&s| s == 0),
            "analyze_final left `seen` marks behind"
        );
    }

    /// Is `l` redundant in the learnt clause (implied by seen literals)?
    fn lit_redundant(&mut self, l: Lit, abstract_levels: u64) -> bool {
        self.min_stack.clear();
        self.min_stack.push(l);
        let top = self.analyze_toclear.len();
        while let Some(q) = self.min_stack.pop() {
            let v = (q.0 >> 1) as usize;
            let r = self.reason[v];
            debug_assert_ne!(r, CREF_NONE);
            let len = self.clause_len(r);
            for k in 1..len {
                let p = self.lit_at(r, k);
                let pv = (p.0 >> 1) as usize;
                if self.seen[pv] != 0 || self.level[pv] == 0 {
                    continue;
                }
                if self.reason[pv] == CREF_NONE
                    || (1u64 << (self.level[pv] & 63)) & abstract_levels == 0
                {
                    // Not removable: undo marks made during this check.
                    for &x in &self.analyze_toclear[top..] {
                        self.seen[(x.0 >> 1) as usize] = 0;
                    }
                    self.analyze_toclear.truncate(top);
                    return false;
                }
                self.seen[pv] = 1;
                self.analyze_toclear.push(p);
                self.min_stack.push(p);
            }
        }
        true
    }

    // ---------- learnt DB reduction ----------

    fn reduce_db(&mut self) {
        // Sort learnts: worst first (high lbd, then longer).
        let mut cands: Vec<CRef> = Vec::with_capacity(self.learnts.len());
        for &c in &self.learnts {
            if self.is_deleted(c) {
                continue;
            }
            cands.push(c);
        }
        cands.sort_by_key(|&c| {
            (
                std::cmp::Reverse(self.lbd(c)),
                std::cmp::Reverse(self.clause_len(c)),
            )
        });
        let target = cands.len() / 2;
        let mut removed = 0;
        let mut kept: Vec<CRef> = Vec::with_capacity(cands.len());
        for &c in &cands {
            let locked = {
                let l0 = self.lit_at(c, 0);
                self.value_lit(l0) == lbool::TRUE && self.reason[(l0.0 >> 1) as usize] == c
            };
            if removed < target && !locked && self.lbd(c) > 2 && !self.protected(c) {
                self.drat_delete(c);
                self.set_deleted(c);
                self.unwatch_clause(c);
                removed += 1;
            } else {
                self.set_protected(c, false);
                kept.push(c);
            }
        }
        self.learnts = kept;
    }

    // ---------- vivification (light inprocessing) ----------

    /// Try to shorten kept learnt clauses by propagating their negations.
    /// Runs at level 0 between restarts, bounded.
    fn vivify(&mut self) {
        debug_assert_eq!(self.decision_level(), 0);
        let mut budget: u64 = 200_000; // propagation budget
        let cands: Vec<CRef> = self
            .learnts
            .iter()
            .copied()
            .filter(|&c| !self.is_deleted(c) && self.lbd(c) <= 6 && self.clause_len(c) <= 16)
            .take(500)
            .collect();
        for c in cands {
            if budget == 0 {
                break;
            }
            if self.is_deleted(c) {
                continue;
            }
            let lits: Vec<Lit> = self.clause_lits(c).iter().map(|&r| Lit(r)).collect();
            // A clause used as a reason cannot be rewritten safely.
            let locked = {
                let l0 = lits[0];
                self.value_lit(l0) == lbool::TRUE && self.reason[(l0.0 >> 1) as usize] == c
            };
            if locked {
                continue;
            }
            let mut new_lits: Vec<Lit> = Vec::with_capacity(lits.len());
            let mut satisfied = false;
            let mut shortened = false;
            for &l in &lits {
                match self.value_lit(l) {
                    lbool::TRUE => {
                        // Rest of the clause is subsumed by the implication.
                        satisfied = true;
                        break;
                    }
                    lbool::FALSE => {
                        shortened = true; // literal implied false: drop it
                        continue;
                    }
                    _ => {}
                }
                new_lits.push(l);
                self.trail_lim.push(self.trail.len() as u32);
                self.enqueue(!l, CREF_NONE);
                let confl = self.propagate();
                budget = budget.saturating_sub(64);
                if confl.is_some() {
                    // ¬l1..¬lk conflict: clause shortens to l1..lk.
                    shortened = true;
                    break;
                }
            }
            // Undo all vivification levels.
            self.backtrack(0);
            if satisfied {
                continue;
            }
            if shortened && new_lits.len() < lits.len() {
                self.drat_add(&new_lits);
                self.drat_delete(c);
                self.set_deleted(c);
                self.unwatch_clause(c);
                if let Some(pos) = self.learnts.iter().position(|&x| x == c) {
                    self.learnts.swap_remove(pos);
                }
                match new_lits.len() {
                    0 => {
                        self.ok = false;
                        return;
                    }
                    1 => {
                        if self.value_lit(new_lits[0]) == lbool::UNDEF {
                            self.enqueue(new_lits[0], CREF_NONE);
                            if self.propagate().is_some() {
                                self.ok = false;
                                return;
                            }
                        } else if self.value_lit(new_lits[0]) == lbool::FALSE {
                            self.ok = false;
                            return;
                        }
                    }
                    _ => {
                        let lbd = new_lits.len() as u32;
                        let nc = self.alloc_clause(&new_lits, true, lbd);
                        self.watch_clause(nc);
                        self.learnts.push(nc);
                    }
                }
            }
        }
    }

    // ---------- restarts ----------

    /// Level to restart to, keeping the prefix of the trail the new decision
    /// order would have rebuilt anyway (van der Tak/Ramos/Heule trail reuse).
    ///
    /// The cost of a restart here is re-descent, not the loss of the trail: a
    /// previous experiment cut conflicts 28.6 % and still lost benchmarks
    /// because propagations per conflict rose. Walk the current decisions from
    /// the bottom and keep every one that VSIDS still ranks above the best
    /// unassigned variable — those decisions would be re-made verbatim, so
    /// redoing their propagation is pure waste.
    ///
    /// `min_level` pins the assumption prefix, whose levels are not VSIDS
    /// decisions at all (and may be empty pseudo-levels).
    fn restart_level(&mut self, min_level: u32) -> u32 {
        if !self.trail_reuse {
            return 0; // exact pre-trail-reuse behaviour, for A/B measurement
        }
        let dl = self.decision_level();
        if dl <= min_level {
            return min_level;
        }
        if self.vmtf_active {
            // Same rule, ranked by VMTF stamp instead of activity.
            let best_stamp = match self.vmtf_next_decision() {
                None => return min_level,
                Some(v) => self.vmtf_stamp[v.0 as usize],
            };
            let mut lvl = min_level;
            while lvl < dl {
                let d = self.trail[self.trail_lim[lvl as usize] as usize];
                if self.vmtf_stamp[(d.0 >> 1) as usize] < best_stamp {
                    break;
                }
                lvl += 1;
            }
            return lvl;
        }
        // Best unassigned activity. Assigned variables at the top of the heap
        // are stale entries; popping them is what the decision loop does too.
        let best_act = loop {
            match self.heap.first().copied() {
                None => return min_level, // nothing left to decide
                Some(v) => {
                    if self.value_var(v) == lbool::UNDEF {
                        break self.activity[v.0 as usize];
                    }
                    self.heap_pop();
                }
            }
        };
        let mut lvl = min_level;
        while lvl < dl {
            // trail_lim[i] is the position of the decision that opened level
            // i+1; chronological backtracking never moves entries below the
            // cut, so this stays valid.
            let d = self.trail[self.trail_lim[lvl as usize] as usize];
            if self.activity[(d.0 >> 1) as usize] < best_act {
                break;
            }
            lvl += 1;
        }
        lvl
    }

    // ---------- search ----------

    fn luby(mut x: u64) -> u64 {
        // Luby sequence: 1 1 2 1 1 2 4 ...
        let mut size = 1u64;
        let mut seq = 0u32;
        while size < x + 1 {
            seq += 1;
            size = 2 * size + 1;
        }
        while size - 1 != x {
            size = (size - 1) / 2;
            seq -= 1;
            x %= size;
        }
        1u64 << seq
    }

    /// Solve under assumptions. Returns TRUE/FALSE/UNDEF (budget exhausted).
    pub fn solve(&mut self, assumptions: &[Lit]) -> lbool {
        self.backtrack(0);
        self.clear_extended_model();
        // Every FALSE below other than the assumption-failure path is a
        // refutation of the clause database itself, for which the empty set is
        // the correct (and exact) answer; clearing here is what makes that so
        // rather than leaving the previous call's set to be misread.
        self.failed.clear();
        if !self.ok {
            return lbool::FALSE;
        }
        // An eliminated variable cannot be assumed: restore it first.
        self.restore_lits(assumptions);
        if !self.ok {
            return lbool::FALSE;
        }
        if self.propagate().is_some() {
            self.ok = false;
            return lbool::FALSE;
        }
        // Lucky phases come first: they are four propagation sweeps and they
        // answer before any other machinery has run. Assumptions are not
        // handled (a lucky assignment need not respect them), so an
        // incremental call under assumptions simply skips them.
        if self.lucky_pending && assumptions.is_empty() {
            match self.lucky_phases() {
                Some(true) => {
                    self.extend_model();
                    return lbool::TRUE;
                }
                Some(false) => return lbool::FALSE,
                None => {}
            }
        }
        // Preprocessing is deferred until the search has proved nontrivial (see
        // solver/prepro.rs); an earlier `solve` may already have crossed the
        // threshold without reaching the hook.
        if self.prepro_pending() {
            self.preprocess(assumptions);
            if !self.ok {
                return lbool::FALSE;
            }
        }

        let mut restart_num = 0u64;
        let mut conflicts_until_restart = 128 * Self::luby(restart_num);
        let mut conflicts_this_solve: u64 = 0;
        let trace_every: u64 = std::env::var("SMTRS_TRACE_SEARCH")
            .ok()
            .and_then(|v| v.parse().ok())
            .unwrap_or(20_000);
        let trace_search = std::env::var_os("SMTRS_TRACE_SEARCH").is_some();
        let mut max_trail = 0usize;
        let mut sum_learnt = 0u64;
        let mut sum_lbd = 0u64;

        loop {
            if let Some(confl) = self.propagate() {
                self.conflicts += 1;
                conflicts_this_solve += 1;
                if trace_search {
                    max_trail = max_trail.max(self.trail.len());
                    if conflicts_this_solve.is_multiple_of(trace_every) {
                        eprintln!(
                            "; trace confl={} dl={} trail={} maxtrail={} nvars={} \
                             avg_learnt={:.1} avg_lbd={:.1} learnts={} restarts={}",
                            conflicts_this_solve,
                            self.decision_level(),
                            self.trail.len(),
                            max_trail,
                            self.num_vars(),
                            sum_learnt as f64 / conflicts_this_solve as f64,
                            sum_lbd as f64 / conflicts_this_solve as f64,
                            self.learnts.len(),
                            self.restarts,
                        );
                        max_trail = 0;
                    }
                }

                // With chronological backtracking the conflict may involve
                // only lower levels; realign first.
                let clevel = self.conflict_level(confl);
                if clevel < self.decision_level() {
                    self.backtrack(clevel);
                }
                if self.decision_level() == 0 {
                    self.ok = false;
                    return lbool::FALSE;
                }
                // A conflict inside the assumption prefix means unsat under
                // assumptions (analyze below still learns a valid clause; we
                // detect the assumption failure at re-decision time).
                let (learnt, bj, lbd) = self.analyze(confl);
                if trace_search {
                    sum_learnt += learnt.len() as u64;
                    sum_lbd += lbd as u64;
                }
                self.decay_var_activity();
                self.drat_add(&learnt);

                // Chronological backtracking: for far backjumps, step back
                // one level instead (the learnt clause is still asserting).
                let target = if self.decision_level() - bj > self.chrono_threshold {
                    self.decision_level() - 1
                } else {
                    bj
                };
                self.backtrack(target);

                let asserting = learnt[0];
                match learnt.len() {
                    1 => {
                        // Unit learnt: it holds at level 0.
                        self.backtrack(0);
                        match self.value_lit(asserting) {
                            lbool::FALSE => {
                                self.ok = false;
                                return lbool::FALSE;
                            }
                            lbool::UNDEF => self.enqueue(asserting, CREF_NONE),
                            _ => {}
                        }
                    }
                    _ => {
                        let c = self.alloc_clause(&learnt, true, lbd);
                        self.watch_clause(c);
                        self.learnts.push(c);
                        if self.value_lit(asserting) == lbool::UNDEF {
                            self.enqueue(asserting, c);
                            // Assignment level of the asserting literal is
                            // the backjump level even under chrono-bt.
                            self.level[(asserting.0 >> 1) as usize] = bj;
                        }
                    }
                }
                // Return the buffer with its capacity for the next conflict.
                self.analyze_learnt = learnt;

                if conflicts_this_solve >= self.conflict_budget {
                    self.backtrack(0);
                    return lbool::UNDEF;
                }
                if conflicts_this_solve.is_multiple_of(64) {
                    if let Some(f) = &self.terminate {
                        if f.load(std::sync::atomic::Ordering::Relaxed) {
                            self.backtrack(0);
                            return lbool::UNDEF;
                        }
                    }
                }
                if self.prepro_pending() {
                    // The search is real work: now CNF preprocessing is worth
                    // its cost. Level 0 with propagation complete is required.
                    self.backtrack(0);
                    if self.propagate().is_some() {
                        self.ok = false;
                        return lbool::FALSE;
                    }
                    self.preprocess(assumptions);
                    if !self.ok {
                        return lbool::FALSE;
                    }
                    continue;
                }
                if self.conflicts >= self.next_vivify && self.vivify_enabled {
                    self.next_vivify = self.conflicts + 30_000;
                    self.backtrack(0);
                    self.vivify();
                    if !self.ok {
                        return lbool::FALSE;
                    }
                }
                if self.decision_mode == DecisionMode::Alt && self.conflicts >= self.alt_switch_at {
                    self.vmtf_active = !self.vmtf_active;
                    if !self.vmtf_active {
                        // A full VSIDS+VMTF cycle has elapsed; widen it.
                        self.alt_interval *= 2;
                    }
                    self.alt_switch_at = self.conflicts + self.alt_interval;
                }
                conflicts_until_restart = conflicts_until_restart.saturating_sub(1);
                if conflicts_until_restart == 0 {
                    restart_num += 1;
                    self.restarts += 1;
                    conflicts_until_restart = 128 * Self::luby(restart_num);
                    let target = self.restart_level(assumptions.len() as u32);
                    self.backtrack(target);
                }
                if self.learnts.len() as u64 > self.reduce_conflicts_target {
                    self.reduce_conflicts_target += 300;
                    self.reduce_db();
                }
            } else {
                // Decide: assumptions first, then VSIDS.
                let dl = self.decision_level() as usize;
                if dl < assumptions.len() {
                    let a = assumptions[dl];
                    match self.value_lit(a) {
                        lbool::TRUE => {
                            // Already satisfied: open an empty pseudo-level.
                            self.trail_lim.push(self.trail.len() as u32);
                            continue;
                        }
                        lbool::FALSE => {
                            // Assumption conflicts with current forced state.
                            // Read the responsible assumptions off the trail
                            // *before* backtracking discards it.
                            self.analyze_final(a);
                            self.backtrack(0);
                            return lbool::FALSE;
                        }
                        _ => {
                            self.decisions += 1;
                            self.trail_lim.push(self.trail.len() as u32);
                            self.enqueue(a, CREF_NONE);
                            continue;
                        }
                    }
                }
                // Branching heuristic decision.
                let next: Option<Var> = if self.vmtf_active {
                    self.vmtf_next_decision()
                } else {
                    let mut next = None;
                    while let Some(v) = self.heap_pop() {
                        if self.value_var(v) == lbool::UNDEF {
                            next = Some(v);
                            break;
                        }
                    }
                    next
                };
                match next {
                    None => {
                        // Full model over the live variables; give the
                        // eliminated ones consistent values.
                        self.extend_model();
                        return lbool::TRUE;
                    }
                    Some(v) => {
                        self.decisions += 1;
                        self.trail_lim.push(self.trail.len() as u32);
                        let l = Lit::new(v, self.phase[v.0 as usize]);
                        self.enqueue(l, CREF_NONE);
                    }
                }
            }
        }
    }

    /// Choose the branching heuristic (tests, bisection). Call before the
    /// first `solve`: the VMTF search cursor is only kept current while a
    /// non-VSIDS mode is selected.
    pub fn set_decision_mode(&mut self, mode: DecisionMode) {
        self.decision_mode = mode;
        self.vmtf_active = mode == DecisionMode::Vmtf;
    }

    // ---------- lucky phases ----------

    /// Decide `l` and propagate; on conflict, take CaDiCaL's one-step
    /// discrepancy repair rather than abandoning the pass.
    ///
    /// * Above level 1 the single decision is undone and the *opposite*
    ///   polarity tried once; a second conflict ends the pass.
    /// * At level 1 the conflict proves `¬l` outright — the decision is the
    ///   only assumption — so `¬l` is asserted as a root unit (a RUP
    ///   inference, which is what the emitted DRAT line records) and the walk
    ///   retries the same variable, now forced.
    ///
    /// Returns `Ok(())` to continue the pass, `Err(ok)` to end it, where `ok`
    /// is false only when the root propagation proved the formula unsat.
    fn lucky_decide(&mut self, l: Lit) -> Result<(), bool> {
        self.trail_lim.push(self.trail.len() as u32);
        self.enqueue(l, CREF_NONE);
        if self.propagate().is_none() {
            return Ok(());
        }
        if self.decision_level() > 1 {
            self.backtrack(self.decision_level() - 1);
            self.trail_lim.push(self.trail.len() as u32);
            self.enqueue(!l, CREF_NONE);
            if self.propagate().is_none() {
                return Ok(());
            }
            return Err(true);
        }
        // Level-1 conflict: ¬l is implied by the formula.
        self.backtrack(0);
        self.drat_add(&[!l]);
        if self.value_lit(!l) == lbool::FALSE {
            self.ok = false;
            return Err(false);
        }
        if self.value_lit(!l) == lbool::UNDEF {
            self.enqueue(!l, CREF_NONE);
        }
        if self.propagate().is_some() {
            self.ok = false;
            return Err(false);
        }
        Ok(())
    }

    /// One "lucky" attempt: walk the live variables in index order (reversed
    /// when `backward`), giving every still-unassigned one the fixed polarity
    /// `positive` as a decision and propagating after each. If the walk
    /// finishes, every live variable is assigned and propagation is complete,
    /// so no clause is falsified — the formula is satisfied.
    ///
    /// Cost is bounded by construction: each variable is decided at most twice
    /// and every literal enters the trail at most once between backtracks, so
    /// a pass is a constant number of propagation sweeps whether it succeeds
    /// or fails.
    fn lucky_pass(&mut self, backward: bool, positive: bool) -> Result<bool, ()> {
        debug_assert_eq!(self.decision_level(), 0);
        let n = self.num_vars();
        for k in 0..n {
            let idx = if backward { n - 1 - k } else { k };
            let v = Var(idx as u32);
            loop {
                // Eliminated variables have had their clauses removed;
                // deciding them would prove nothing, and `extend_model` gives
                // them consistent values anyway.
                if self.elim_index[idx] >= 0 || self.value_var(v) != lbool::UNDEF {
                    break;
                }
                match self.lucky_decide(Lit::new(v, positive)) {
                    Ok(()) => {
                        if self.value_var(v) != lbool::UNDEF {
                            break;
                        }
                    }
                    Err(true) => {
                        self.backtrack(0);
                        return Ok(false);
                    }
                    Err(false) => return Err(()),
                }
            }
        }
        Ok(true)
    }

    /// CaDiCaL's lucky phases, run once before the first search. Bit-blasted
    /// circuits often have a satisfying assignment that unit propagation finds
    /// from a single uniform polarity, and four propagation sweeps is the
    /// whole cost of asking. Returns `Some(true)` on a model, `Some(false)` if
    /// a root-level implication turned out to be inconsistent.
    ///
    /// Saved phases are restored when nothing is found. The root units the
    /// discrepancy repair asserted are *kept* — they are implied by the
    /// formula, so they are free information for the search that follows.
    ///
    /// Undoing them instead was implemented and measured against this in the
    /// same full-suite pass: **+21 against +22**, PAR-2 slightly worse
    /// (`keep/lucky-rollback`). It is also harder than it looks and buys less
    /// than it promises. Restoring the trail is not enough — `analyze` tests
    /// `level(v) > 0` to decide which literals are root-level, so `level` has
    /// to come back too, and the measured variant did not do that. And even a
    /// complete version is not inert: two-watched-literal propagation permutes
    /// the watch lists and swaps literals inside clauses, and snapshotting
    /// those would cost more memory than the solver. A fruitless run nudges
    /// propagation order whichever way the trail is handled; the rollback only
    /// makes it *look* inert.
    fn lucky_phases(&mut self) -> Option<bool> {
        self.lucky_pending = false;
        let saved = self.phase.clone();
        let order = [(false, false), (false, true), (true, false), (true, true)];
        for (i, &(backward, positive)) in order.iter().enumerate() {
            match self.lucky_pass(backward, positive) {
                Ok(true) => {
                    self.lucky_hit = i as u32 + 1;
                    return Some(true);
                }
                Ok(false) => {}
                Err(()) => return Some(false),
            }
        }
        self.phase = saved;
        None
    }

    /// Set (or clear with u64::MAX) a per-solve conflict budget.
    pub fn set_conflict_budget(&mut self, budget: u64) {
        self.conflict_budget = budget;
    }

    /// Is a CNF preprocessing pass due? The first one waits for the deferral
    /// threshold; later ones (inprocessing) are on a widening conflict
    /// schedule set by the previous pass.
    fn prepro_pending(&self) -> bool {
        if self.prepro_mode == PreproMode::Off || self.conflicts < self.prepro_at_conflicts {
            return false;
        }
        !self.preprocessed || self.inprocess_rounds > self.prepro_rounds
    }

    /// Total preprocessing passes and the conflict gap between them (tests;
    /// production takes these from `SMTRS_CDCL_INPROCESS`).
    pub fn set_inprocess(&mut self, rounds: u32, interval: u64) {
        self.inprocess_rounds = rounds.max(1);
        self.inprocess_interval = interval.max(1);
    }

    /// Turn CNF preprocessing off (tests, bisection).
    pub fn disable_prepro(&mut self) {
        self.prepro_mode = PreproMode::Off;
    }

    /// Skip the pre-search lucky phases (tests, bisection).
    pub fn disable_lucky(&mut self) {
        self.lucky_pending = false;
    }

    /// Conflict count at which CNF preprocessing runs; 0 runs it before the
    /// first search. Tests use 0 to exercise elimination on small inputs.
    pub fn set_prepro_at(&mut self, conflicts: u64) {
        self.prepro_at_conflicts = conflicts;
    }

    /// Preprocessing/inprocessing passes run so far.
    pub fn prepro_passes(&self) -> u32 {
        self.prepro_rounds
    }
}
