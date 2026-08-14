//! smtrs-sat: the SAT backend abstraction.
//!
//! Pure-Rust policy (user decision): no C/C++ in the solving stack. The
//! default backend is the in-house `smtrs-cdcl` engine; `SMTRS_SAT=batsat`
//! switches to batsat (MiniSat-class), which is kept as a differential-testing
//! oracle rather than as the shipping default. The trait keeps the solver
//! pipeline independent of the backend.

use batsat::SolverInterface as _;

/// A propositional literal. `Lit::from_var(v, true)` is the positive literal.
#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug)]
pub struct Lit(i32);

impl Lit {
    pub fn from_index(var_index: u32, positive: bool) -> Self {
        let v = var_index as i32 + 1;
        Lit(if positive { v } else { -v })
    }

    pub fn var_index(self) -> u32 {
        self.0.unsigned_abs() - 1
    }

    pub fn is_positive(self) -> bool {
        self.0 > 0
    }

    pub fn negate(self) -> Self {
        Lit(-self.0)
    }
}

impl std::ops::Not for Lit {
    type Output = Lit;
    fn not(self) -> Lit {
        self.negate()
    }
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum SatResult {
    Sat,
    Unsat,
    /// Resource limit / interrupt.
    Unknown,
}

/// Deterministic search/preprocessing counters, for A/B measurement.
#[derive(Default, Clone, Copy)]
pub struct SatCounters {
    pub conflicts: u64,
    pub decisions: u64,
    pub propagations: u64,
    pub restarts: u64,
    /// CNF preprocessing (cdcl backend): variables eliminated, clauses before
    /// and after, seconds spent, variables restored by later clauses.
    pub prepro_vars_elim: u32,
    pub prepro_clauses_before: u32,
    pub prepro_clauses_after: u32,
    pub prepro_secs: f64,
    pub restored_vars: u64,
    /// Incremental trail reuse (cdcl backend): solves answered outright from
    /// the model the previous `solve` left on the trail, and decision levels
    /// carried into a solve instead of being re-decided and re-propagated.
    pub reused_models: u64,
    pub reused_levels: u64,
}

/// Minimal incremental SAT interface the bit-blaster needs.
pub trait SatBackend {
    /// Allocate a fresh variable, returning its positive literal.
    fn new_var(&mut self) -> Lit;
    fn add_clause(&mut self, clause: &[Lit]);
    /// Solve under the given assumptions.
    fn solve(&mut self, assumptions: &[Lit]) -> SatResult;
    /// Value of a literal in the current model (after Sat).
    fn value(&self, lit: Lit) -> Option<bool>;
    /// Number of variables allocated.
    fn num_vars(&self) -> u32;
    /// Install a cooperative termination flag. Every backend supports this —
    /// `--timeout-ms` depends on it, and a backend that ignored it would run
    /// past the deadline rather than answer `unknown`.
    fn set_terminate(&mut self, flag: std::sync::Arc<std::sync::atomic::AtomicBool>);
    /// Stop the next `solve` after this many conflicts and report `Unknown`
    /// (`u64::MAX` disables the budget). Learned state survives, so a
    /// subsequent unbudgeted `solve` resumes rather than restarts.
    ///
    /// Returns whether the budget was installed. Not every backend can express
    /// one, and a caller that plans around a bounded phase — re-entering the
    /// search after the budget trips, say — needs to know that the phase will
    /// never fire rather than silently waiting forever for it.
    #[must_use]
    fn set_conflict_budget(&mut self, _budget: u64) -> bool {
        false
    }
    /// Search counters, or `None` from a backend that does not keep them.
    ///
    /// Deliberately not "zeros if unsupported": `conflicts: 0` is a perfectly
    /// ordinary result (an instance solved by propagation alone), so a caller
    /// cannot tell a real zero from a missing one. `--stats-json` reported
    /// exactly that fiction for batsat until this became an `Option`.
    fn counters(&self) -> Option<SatCounters> {
        None
    }

    /// Pin a variable as never-eliminable by CNF preprocessing. A no-op on
    /// backends without variable elimination, and never required for
    /// correctness — an eliminated variable used as an assumption is restored
    /// on demand — but unsat-core extraction reads the implication graph of
    /// the *current* clause database, and pinning the activation literals
    /// keeps that graph the one the core is supposed to be read from.
    fn freeze_var(&mut self, _lit: Lit) {}

    /// Assumption literals that alone contradict the formula, after `solve`
    /// returned [`SatResult::Unsat`]. `None` from a backend that cannot report
    /// them, which is a refusal, not an empty core: an empty slice is the
    /// meaningful answer "the formula is unsat with no assumption's help".
    ///
    /// The returned set S is exact in the only sense that matters to a caller
    /// building an unsat core: `formula ∧ ⋀ S` is unsatisfiable. It is not
    /// promised to be minimal.
    fn failed_assumptions(&self) -> Option<Vec<Lit>> {
        None
    }
}

/// batsat-backed implementation.
pub struct BatsatBackend {
    solver: batsat::BasicSolver,
    vars: Vec<batsat::Var>,
    /// Reusable clause buffer; see `CdclBackend::scratch`.
    scratch: Vec<batsat::Lit>,
    /// Debug: mirror of all added clauses for DIMACS dumping.
    dump: Option<Vec<Vec<i32>>>,
}

impl Default for BatsatBackend {
    fn default() -> Self {
        Self::new()
    }
}

impl BatsatBackend {
    pub fn new() -> Self {
        BatsatBackend {
            solver: batsat::BasicSolver::default(),
            vars: Vec::new(),
            scratch: Vec::new(),
            dump: std::env::var_os("SMTRS_DUMP_CNF").map(|_| Vec::new()),
        }
    }

    /// Write accumulated clauses as DIMACS (when SMTRS_DUMP_CNF is set).
    pub fn dump_dimacs(&self, path: &str) {
        write_dimacs(self.vars.len(), self.dump.as_deref(), path);
    }

    fn to_batsat(&self, lit: Lit) -> batsat::Lit {
        batsat::Lit::new(self.vars[lit.var_index() as usize], lit.is_positive())
    }
}

impl SatBackend for BatsatBackend {
    fn new_var(&mut self) -> Lit {
        let v = self.solver.new_var_default();
        let idx = self.vars.len() as u32;
        self.vars.push(v);
        Lit::from_index(idx, true)
    }

    fn add_clause(&mut self, clause: &[Lit]) {
        if let Some(dump) = &mut self.dump {
            dump.push(clause.iter().map(|&l| l.0).collect());
        }
        let mut cl = std::mem::take(&mut self.scratch);
        cl.clear();
        cl.extend(clause.iter().map(|&l| self.to_batsat(l)));
        self.solver.add_clause_reuse(&mut cl);
        self.scratch = cl;
    }

    fn solve(&mut self, assumptions: &[Lit]) -> SatResult {
        let assumps: Vec<batsat::Lit> = assumptions.iter().map(|&l| self.to_batsat(l)).collect();
        let r = self.solver.solve_limited(&assumps);
        if r == batsat::lbool::TRUE {
            SatResult::Sat
        } else if r == batsat::lbool::FALSE {
            SatResult::Unsat
        } else {
            SatResult::Unknown
        }
    }

    fn value(&self, lit: Lit) -> Option<bool> {
        let l = self.to_batsat(lit);
        let v = self.solver.value_lit(l);
        if v == batsat::lbool::TRUE {
            Some(true)
        } else if v == batsat::lbool::FALSE {
            Some(false)
        } else {
            // Variable eliminated/unassigned in the model: caller completes.
            None
        }
    }

    fn num_vars(&self) -> u32 {
        self.vars.len() as u32
    }

    fn set_terminate(&mut self, flag: std::sync::Arc<std::sync::atomic::AtomicBool>) {
        self.solver
            .cb_mut()
            .set_stop(move || flag.load(std::sync::atomic::Ordering::Relaxed));
    }

    /// batsat keeps `conflict_budget` private with no setter, so the bounded
    /// phase cannot be expressed here. Saying so lets the caller skip it.
    fn set_conflict_budget(&mut self, _budget: u64) -> bool {
        false
    }

    /// batsat exposes no failed-assumption set through `SolverInterface`.
    /// `None` refuses the query rather than guessing; the differential oracle
    /// backend is not the one unsat cores are produced from.
    fn failed_assumptions(&self) -> Option<Vec<Lit>> {
        None
    }

    fn counters(&self) -> Option<SatCounters> {
        Some(SatCounters {
            conflicts: self.solver.num_conflicts(),
            decisions: self.solver.num_decisions(),
            propagations: self.solver.num_propagations(),
            restarts: self.solver.num_restarts(),
            // batsat's own simplification is not our CNF preprocessing pass,
            // so these stay zero rather than reporting something unrelated.
            ..SatCounters::default()
        })
    }
}

/// In-house CDCL implementation (smtrs-cdcl).
#[derive(Clone)]
pub struct CdclBackend {
    solver: smtrs_cdcl::Solver,
    /// Number of variables handed out so far.
    ///
    /// There is deliberately no `Vec<smtrs_cdcl::Var>` mapping table here.
    /// `Solver::new_var` hands out dense indices from zero and this backend is
    /// its only caller, so the map was the identity — and looking it up cost a
    /// random read into a several-megabyte array on *every literal of every
    /// clause*, which is the hottest path in the encoder. `new_var` asserts the
    /// identity rather than assuming it; see there.
    num_vars: u32,
    /// Reusable clause buffer. `add_clause` is called once per CNF clause —
    /// millions of times on a large instance — and allocating a fresh `Vec` to
    /// hold three literals each time was the single largest cost of the
    /// handoff.
    scratch: Vec<smtrs_cdcl::Lit>,
    /// Debug: mirror of all added clauses for DIMACS dumping. Needed to check
    /// emitted DRAT proofs against the original CNF.
    dump: Option<Vec<Vec<i32>>>,
}

impl Default for CdclBackend {
    fn default() -> Self {
        Self::new()
    }
}

impl CdclBackend {
    pub fn new() -> Self {
        let mut solver = smtrs_cdcl::Solver::new();
        if let Ok(path) = std::env::var("SMTRS_DRAT") {
            solver.enable_drat(&path);
        }
        CdclBackend {
            solver,
            num_vars: 0,
            scratch: Vec::new(),
            dump: std::env::var_os("SMTRS_DUMP_CNF").map(|_| Vec::new()),
        }
    }

    #[inline]
    fn to_cdcl(&self, lit: Lit) -> smtrs_cdcl::Lit {
        debug_assert!(lit.var_index() < self.num_vars, "literal over unknown var");
        smtrs_cdcl::Lit::new(smtrs_cdcl::Var(lit.var_index()), lit.is_positive())
    }

    /// Conflict count at which CNF preprocessing runs (0 = before the first
    /// search). Tests use 0 so elimination is exercised on small inputs.
    pub fn set_prepro_at(&mut self, conflicts: u64) {
        self.solver.set_prepro_at(conflicts);
    }

    /// Write accumulated clauses as DIMACS (when SMTRS_DUMP_CNF is set). The
    /// variable numbering matches the one used by DRAT output.
    pub fn dump_dimacs(&self, path: &str) {
        write_dimacs(self.num_vars as usize, self.dump.as_deref(), path);
    }
}

/// DIMACS writer shared by both backends' `dump_dimacs`: neither the clause
/// mirror nor the variable count is backend-specific, so neither is this.
fn write_dimacs(num_vars: usize, clauses: Option<&[Vec<i32>]>, path: &str) {
    use std::io::Write;
    let Some(clauses) = clauses else { return };
    let mut f = std::io::BufWriter::new(std::fs::File::create(path).unwrap());
    writeln!(f, "p cnf {} {}", num_vars, clauses.len()).unwrap();
    for c in clauses {
        for l in c {
            write!(f, "{l} ").unwrap();
        }
        writeln!(f, "0").unwrap();
    }
}

impl SatBackend for CdclBackend {
    fn new_var(&mut self) -> Lit {
        let v = self.solver.new_var();
        // `to_cdcl` maps our index straight onto the engine's without a table.
        // That is only correct while the engine numbers variables densely from
        // zero, which it does — but it is an invariant of another crate, so it
        // is checked here (once per variable, against fifteen vector pushes
        // inside `new_var` itself) rather than assumed.
        assert_eq!(
            v.0, self.num_vars,
            "smtrs-cdcl handed out a non-dense variable index"
        );
        self.num_vars += 1;
        Lit::from_index(v.0, true)
    }

    fn add_clause(&mut self, clause: &[Lit]) {
        if let Some(dump) = &mut self.dump {
            dump.push(clause.iter().map(|&l| l.0).collect());
        }
        let mut cl = std::mem::take(&mut self.scratch);
        cl.clear();
        cl.extend(clause.iter().map(|&l| self.to_cdcl(l)));
        self.solver.add_clause(&cl);
        self.scratch = cl;
    }

    fn solve(&mut self, assumptions: &[Lit]) -> SatResult {
        let assumps: Vec<smtrs_cdcl::Lit> = assumptions.iter().map(|&l| self.to_cdcl(l)).collect();
        let r = self.solver.solve(&assumps);
        if r == smtrs_cdcl::lbool::TRUE {
            SatResult::Sat
        } else if r == smtrs_cdcl::lbool::FALSE {
            SatResult::Unsat
        } else {
            SatResult::Unknown
        }
    }

    fn value(&self, lit: Lit) -> Option<bool> {
        let v = self.solver.value_lit(self.to_cdcl(lit));
        if v == smtrs_cdcl::lbool::TRUE {
            Some(true)
        } else if v == smtrs_cdcl::lbool::FALSE {
            Some(false)
        } else {
            None
        }
    }

    fn num_vars(&self) -> u32 {
        self.num_vars
    }

    fn set_terminate(&mut self, flag: std::sync::Arc<std::sync::atomic::AtomicBool>) {
        self.solver.set_terminate_flag(flag);
    }

    fn set_conflict_budget(&mut self, budget: u64) -> bool {
        self.solver.set_conflict_budget(budget);
        true
    }

    fn freeze_var(&mut self, lit: Lit) {
        self.solver.freeze(self.to_cdcl(lit).var());
    }

    /// Backend index and cdcl variable index coincide, so a failed assumption
    /// carries straight across. That identity is not assumed here: `new_var`
    /// asserts it for every variable as it is handed out, which is a strictly
    /// stronger check than re-deriving it at each read — and it costs one
    /// comparison per variable instead of a random probe into a
    /// several-megabyte table per literal.
    ///
    /// What density does *not* cover is a variable the engine minted for itself
    /// and never handed back through `new_var`. That would be out of range
    /// rather than misnumbered, so the range is what is checked. It should be
    /// unreachable — failed assumptions are a subset of the assumptions we
    /// passed in — but the failure mode is a silently misnamed unsat core, and
    /// a wrong core is worse than no core.
    fn failed_assumptions(&self) -> Option<Vec<Lit>> {
        Some(
            self.solver
                .failed_assumptions()
                .iter()
                .map(|&l| {
                    let v = l.var();
                    assert!(
                        v.0 < self.num_vars,
                        "cdcl returned a failed assumption over a variable \
                         this backend never handed out"
                    );
                    Lit::from_index(v.0, l.is_positive())
                })
                .collect(),
        )
    }

    fn counters(&self) -> Option<SatCounters> {
        let s = &self.solver;
        Some(SatCounters {
            conflicts: s.conflicts,
            decisions: s.decisions,
            propagations: s.propagations,
            restarts: s.restarts,
            prepro_vars_elim: s.prepro_vars_elim,
            prepro_clauses_before: s.prepro_clauses_before,
            prepro_clauses_after: s.prepro_clauses_after,
            prepro_secs: s.prepro_secs,
            restored_vars: s.restored_vars,
            reused_models: s.reused_models,
            reused_levels: s.reused_levels,
        })
    }
}

/// Runtime-selected backend: `SMTRS_SAT=batsat|cdcl` (default: cdcl).
// Not boxed despite the variant spread — `BatsatBackend` is 1 088 bytes and
// `CdclBackend` 960, so the enum is 1 088 and the unused variant wastes 128 of
// them. Exactly one `Backend` exists per solve (it is a field of `Solver`), so
// that is paid once, while boxing would add a pointer chase to every
// `SatBackend` dispatch — `add_clause` and `value` are among the hottest calls
// we make. (Those two numbers were quoted here as 1104/688 and had drifted; the
// dispatch cost is separately measured at under 1 % by `examples/handoff.rs`
// under `SMTRS_HANDOFF_DIRECT=1`, which is the claim that actually matters.)
#[allow(clippy::large_enum_variant)]
pub enum Backend {
    Batsat(BatsatBackend),
    Cdcl(CdclBackend),
}

impl Default for Backend {
    fn default() -> Self {
        Self::from_env()
    }
}

impl Backend {
    pub fn from_env() -> Self {
        match std::env::var("SMTRS_SAT").as_deref() {
            Ok("batsat") => {
                // DRAT emission lives in smtrs-cdcl. Under batsat the proof
                // would simply never be written, and a proof that silently
                // does not exist is worse than a refused run: the user is
                // waiting for a file to check.
                if std::env::var_os("SMTRS_DRAT").is_some() {
                    eprintln!(
                        "error: SMTRS_DRAT needs SMTRS_SAT=cdcl; \
                         the batsat backend cannot emit proofs"
                    );
                    std::process::exit(1);
                }
                Backend::Batsat(BatsatBackend::new())
            }
            _ => Backend::Cdcl(CdclBackend::new()),
        }
    }

    /// DIMACS dump (debug).
    pub fn dump_dimacs(&self, path: &str) {
        match self {
            Backend::Batsat(b) => b.dump_dimacs(path),
            Backend::Cdcl(b) => b.dump_dimacs(path),
        }
    }

    /// Fork with learned state preserved. Only the cdcl backend supports
    /// this; callers fall back to rebuilding when None is returned.
    pub fn try_clone(&self) -> Option<Backend> {
        match self {
            Backend::Cdcl(b) => Some(Backend::Cdcl(b.clone())),
            Backend::Batsat(_) => None,
        }
    }
}

impl SatBackend for Backend {
    fn new_var(&mut self) -> Lit {
        match self {
            Backend::Batsat(b) => b.new_var(),
            Backend::Cdcl(b) => b.new_var(),
        }
    }

    fn add_clause(&mut self, clause: &[Lit]) {
        match self {
            Backend::Batsat(b) => b.add_clause(clause),
            Backend::Cdcl(b) => b.add_clause(clause),
        }
    }

    fn solve(&mut self, assumptions: &[Lit]) -> SatResult {
        match self {
            Backend::Batsat(b) => b.solve(assumptions),
            Backend::Cdcl(b) => b.solve(assumptions),
        }
    }

    fn value(&self, lit: Lit) -> Option<bool> {
        match self {
            Backend::Batsat(b) => b.value(lit),
            Backend::Cdcl(b) => b.value(lit),
        }
    }

    fn num_vars(&self) -> u32 {
        match self {
            Backend::Batsat(b) => b.num_vars(),
            Backend::Cdcl(b) => b.num_vars(),
        }
    }

    fn set_terminate(&mut self, flag: std::sync::Arc<std::sync::atomic::AtomicBool>) {
        match self {
            Backend::Batsat(b) => b.set_terminate(flag),
            Backend::Cdcl(b) => b.set_terminate(flag),
        }
    }

    fn set_conflict_budget(&mut self, budget: u64) -> bool {
        match self {
            Backend::Batsat(b) => b.set_conflict_budget(budget),
            Backend::Cdcl(b) => b.set_conflict_budget(budget),
        }
    }

    fn counters(&self) -> Option<SatCounters> {
        match self {
            Backend::Batsat(b) => b.counters(),
            Backend::Cdcl(b) => b.counters(),
        }
    }

    fn freeze_var(&mut self, lit: Lit) {
        match self {
            Backend::Batsat(b) => b.freeze_var(lit),
            Backend::Cdcl(b) => b.freeze_var(lit),
        }
    }

    fn failed_assumptions(&self) -> Option<Vec<Lit>> {
        match self {
            Backend::Batsat(b) => b.failed_assumptions(),
            Backend::Cdcl(b) => b.failed_assumptions(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Deterministic xorshift for reproducible random CNFs.
    struct Rng(u64);
    impl Rng {
        fn next(&mut self) -> u64 {
            self.0 ^= self.0 << 13;
            self.0 ^= self.0 >> 7;
            self.0 ^= self.0 << 17;
            self.0
        }
    }

    /// Differential: cdcl vs batsat on random CNFs (varied density), with
    /// assumption queries, model checks, and incremental clause addition.
    #[test]
    fn differential_cdcl_vs_batsat() {
        let mut rng = Rng(0xdeadbeef);
        let mut disagreements = 0;
        for round in 0..1500 {
            let nv = 5 + (rng.next() % 40) as usize;
            let density = 2.0 + (rng.next() % 40) as f64 / 10.0; // 2.0..6.0
            let nc = (nv as f64 * density) as usize;
            let mut b1 = CdclBackend::new();
            b1.set_prepro_at(0); // exercise BVE + model reconstruction here
            let mut b2 = BatsatBackend::new();
            let v1: Vec<Lit> = (0..nv).map(|_| b1.new_var()).collect();
            let v2: Vec<Lit> = (0..nv).map(|_| b2.new_var()).collect();
            let mut clauses: Vec<Vec<usize>> = Vec::new(); // (var, sign) packed
            for _ in 0..nc {
                let len = 1 + (rng.next() % 4) as usize;
                let mut cl: Vec<usize> = Vec::new();
                for _ in 0..len {
                    let v = (rng.next() % nv as u64) as usize;
                    let sign = (rng.next() % 2) as usize;
                    if !cl.contains(&(v * 2 + sign)) {
                        cl.push(v * 2 + sign);
                    }
                }
                clauses.push(cl);
            }
            let lits = |cl: &[usize], vs: &[Lit]| -> Vec<Lit> {
                cl.iter()
                    .map(|&x| if x % 2 == 0 { vs[x / 2] } else { !vs[x / 2] })
                    .collect()
            };
            // Split into two batches for incrementality.
            let split = clauses.len() / 2;
            for cl in &clauses[..split] {
                b1.add_clause(&lits(cl, &v1));
                b2.add_clause(&lits(cl, &v2));
            }
            // Query 1: with random assumptions.
            let mut assumps: Vec<usize> = Vec::new();
            for _ in 0..(rng.next() % 4) {
                let v = (rng.next() % nv as u64) as usize;
                let sign = (rng.next() % 2) as usize;
                if !assumps.contains(&(v * 2 + sign)) && !assumps.contains(&(v * 2 + 1 - sign)) {
                    assumps.push(v * 2 + sign);
                }
            }
            let r1 = b1.solve(&lits(&assumps, &v1));
            let r2 = b2.solve(&lits(&assumps, &v2));
            if r1 != r2 {
                disagreements += 1;
                eprintln!("round {round} q1: cdcl={r1:?} batsat={r2:?}");
            }
            if r1 == SatResult::Sat {
                for cl in &clauses[..split] {
                    let ls = lits(cl, &v1);
                    assert!(
                        ls.iter().any(|&l| b1.value(l) == Some(true)),
                        "cdcl model violates clause, round {round}"
                    );
                }
                // Assumptions honored.
                for &a in &lits(&assumps, &v1) {
                    assert_eq!(b1.value(a), Some(true), "assumption violated {round}");
                }
            }
            // Add the rest incrementally, query again without assumptions.
            for cl in &clauses[split..] {
                b1.add_clause(&lits(cl, &v1));
                b2.add_clause(&lits(cl, &v2));
            }
            let r1 = b1.solve(&[]);
            let r2 = b2.solve(&[]);
            if r1 != r2 {
                disagreements += 1;
                eprintln!("round {round} q2: cdcl={r1:?} batsat={r2:?}");
            }
            if r1 == SatResult::Sat {
                for cl in &clauses {
                    let ls = lits(cl, &v1);
                    assert!(
                        ls.iter().any(|&l| b1.value(l) == Some(true)),
                        "cdcl model violates clause (q2), round {round}"
                    );
                }
            }
        }
        assert_eq!(disagreements, 0);
    }

    /// The clause-normalization path against exhaustive truth-table checking.
    ///
    /// `add_clause_inner` normalizes through two solver-owned buffers that are
    /// reused across every call, and detects tautologies with a binary search
    /// over the sorted literals. Neither is exercised hard by the random CNFs
    /// above: those clauses are at most four literals long and never repeat a
    /// literal. This one deliberately emits duplicates, complementary pairs and
    /// clauses far longer than the widest the emitter produces, adds them in
    /// batches with solves in between (so the buffers are reused across a
    /// `solve`), enables BVE so the `restore_var` re-entry into the same
    /// normalizer fires, and checks every answer against brute force over the
    /// *original* clause list rather than against another solver.
    #[test]
    fn clause_normalization_vs_brute_force() {
        let mut rng = Rng(0x5eed_1234_9abc_def0);
        for round in 0..400 {
            let nv = 3 + (rng.next() % 8) as usize; // <= 10 vars: 1024 rows
            let nc = 1 + (rng.next() % 14) as usize;
            // Packed literals: var * 2 + sign, sign 1 = negated.
            let mut clauses: Vec<Vec<usize>> = Vec::new();
            for _ in 0..nc {
                // Mostly short, occasionally far wider than any clause the
                // AND-tree collapsing emitter produces (65 literals).
                let len = if rng.next().is_multiple_of(8) {
                    40 + (rng.next() % 50) as usize
                } else {
                    1 + (rng.next() % 5) as usize
                };
                // No dedup and no complement filter: duplicates and tautologies
                // are the point.
                let cl: Vec<usize> = (0..len)
                    .map(|_| (rng.next() % (nv as u64 * 2)) as usize)
                    .collect();
                clauses.push(cl);
            }

            let mut b = CdclBackend::new();
            b.set_prepro_at(0); // BVE, and with it the restore path
            let vs: Vec<Lit> = (0..nv).map(|_| b.new_var()).collect();
            let lits = |cl: &[usize]| -> Vec<Lit> {
                cl.iter()
                    .map(|&x| if x % 2 == 0 { vs[x / 2] } else { !vs[x / 2] })
                    .collect()
            };

            // Brute force over the original clauses, tautologies and all.
            let satisfies = |asg: u32, upto: usize| -> bool {
                clauses[..upto].iter().all(|cl| {
                    cl.iter()
                        .any(|&x| (asg >> (x / 2)) & 1 == (1 - (x % 2)) as u32)
                })
            };

            // Three batches with a solve between them, so the reused buffers
            // survive search, backtracking and preprocessing.
            let bounds = [clauses.len() / 3, 2 * clauses.len() / 3, clauses.len()];
            let mut added = 0;
            for &upto in &bounds {
                for cl in &clauses[added..upto] {
                    b.add_clause(&lits(cl));
                }
                added = upto;
                let expect_sat = (0..(1u32 << nv)).any(|asg| satisfies(asg, upto));
                let got = b.solve(&[]);
                assert_eq!(
                    got == SatResult::Sat,
                    expect_sat,
                    "round {round}, {upto} clauses: got {got:?}, brute force sat={expect_sat}"
                );
                if got == SatResult::Sat {
                    // The model must satisfy every clause as originally given.
                    let asg: u32 = (0..nv)
                        .map(|i| u32::from(b.value(vs[i]) == Some(true)) << i)
                        .sum();
                    assert!(
                        satisfies(asg, upto),
                        "round {round}: model violates an original clause"
                    );
                }
            }

            // Forking after the fact must not share or corrupt the buffers.
            let mut forked = b.clone();
            assert_eq!(forked.num_vars(), b.num_vars());
            let extra = forked.new_var();
            forked.add_clause(&[extra]);
            forked.add_clause(&[extra, !extra]); // tautology, dropped
            assert_eq!(forked.solve(&[]), b.solve(&[]));
        }
    }

    #[test]
    fn basic_sat_unsat() {
        let mut s = BatsatBackend::new();
        let a = s.new_var();
        let b = s.new_var();
        s.add_clause(&[a, b]);
        s.add_clause(&[!a, b]);
        assert_eq!(s.solve(&[]), SatResult::Sat);
        assert_eq!(s.value(b), Some(true));

        // Assumption-based unsat without poisoning the solver.
        assert_eq!(s.solve(&[!b]), SatResult::Unsat);
        assert_eq!(s.solve(&[]), SatResult::Sat);

        s.add_clause(&[!b]);
        assert_eq!(s.solve(&[]), SatResult::Unsat);
    }

    #[test]
    fn incremental_assumptions() {
        let mut s = BatsatBackend::new();
        let x = s.new_var();
        let y = s.new_var();
        let z = s.new_var();
        // x -> y, y -> z
        s.add_clause(&[!x, y]);
        s.add_clause(&[!y, z]);
        assert_eq!(s.solve(&[x, !z]), SatResult::Unsat);
        assert_eq!(s.solve(&[x]), SatResult::Sat);
        assert_eq!(s.value(z), Some(true));
    }
}
