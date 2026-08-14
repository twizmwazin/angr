//! SatELite-style CNF preprocessing: subsumption, self-subsuming resolution,
//! bounded variable elimination (BVE) and equivalent-literal substitution.
//!
//! *Deferred*, not run up front: the first pass happens after
//! `PREPRO_AT_CONFLICTS_DEFAULT` conflicts, for the reason argued at
//! `prepro_at_conflicts` below — running it before the first decision loses
//! money. It can also run again mid-search as inprocessing, though the
//! default `INPROCESS_ROUNDS_DEFAULT` of 1 means only the one pass runs
//! unless `SMTRS_CDCL_INPROCESS` raises it. Bit-blasting
//! emits a great many Tseitin auxiliary variables that occur in a handful of
//! clauses each; BVE resolves those away whenever doing so does not increase
//! the clause count.
//!
//! ## Incrementality
//!
//! Elimination is not satisfiability-preserving in the model direction, and it
//! is outright unsound if a later clause mentions an eliminated variable. Both
//! are handled explicitly:
//!
//! * **Model reconstruction.** Every clause removed by an elimination is pushed
//!   onto `elim_stack` in elimination order. A variable's recorded clauses can
//!   only mention variables that are still live *or* eliminated later, so a
//!   reverse walk of the stack assigns each eliminated variable a value that
//!   satisfies all of its recorded clauses (`extend_model`).
//! * **Restore on demand.** If a clause or assumption arrives that mentions an
//!   eliminated variable, the stack is popped down to that variable's entry and
//!   every recorded clause is re-added (`restore_var`). Correctness does not
//!   depend on guessing the future.
//!
//! DRAT: resolvents and strengthened clauses are RUP (they are resolvents of
//! live clauses), and clause deletion is unrestricted, so the forward direction
//! is checkable. `restore_var` re-adds clauses that were deleted, which is
//! *not* generally RUP; that path marks the proof incomplete with a comment
//! rather than silently emitting garbage.

use super::{lbool, CRef, Lit, Solver, Var, CREF_NONE};

/// One eliminated variable and every clause that mentioned it at that point.
#[derive(Clone)]
pub(super) struct ElimEntry {
    pub(super) var: Var,
    pub(super) clauses: Vec<Vec<Lit>>,
}

/// Preprocessing mode, from `SMTRS_CDCL_PREPRO`.
#[derive(Clone, Copy, PartialEq, Eq)]
pub(super) enum PreproMode {
    Off,
    /// Level-0 clause cleanup only (drop satisfied clauses, drop falsified
    /// literals). Useful as a measurement baseline: on bit-blasted CNF this
    /// alone removes most of the clause database.
    Clean,
    /// Cleanup + subsumption + self-subsuming resolution (no elimination).
    Subsume,
    /// Cleanup + subsumption + BVE.
    Full,
}

pub(super) fn prepro_mode_from_env() -> PreproMode {
    match std::env::var("SMTRS_CDCL_PREPRO").as_deref() {
        Ok("off") | Ok("0") => PreproMode::Off,
        Ok("clean") => PreproMode::Clean,
        Ok("sub") | Ok("subsume") => PreproMode::Subsume,
        _ => PreproMode::Full,
    }
}

// ---------- bounds ----------

/// Per-literal occurrence cap for elimination candidates.
const OCC_LIMIT: usize = 24;
/// Cap on resolvent length (longer resolvents hurt propagation more than the
/// eliminated variable helps).
const RESOLVENT_LEN_LIMIT: usize = 40;
/// Clauses longer than this are never used as a subsuming clause.
const SUBSUME_LEN_LIMIT: usize = 32;
/// Coarse work budget shared by subsumption and elimination. A "step" is
/// roughly a literal comparison (~40ns), so this bounds preprocessing at a few
/// hundred milliseconds even on million-clause inputs. Override in millions of
/// steps with `SMTRS_CDCL_PREPRO_BUDGET`.
const STEP_BUDGET_DEFAULT: u64 = 10_000_000;

fn step_budget() -> u64 {
    match std::env::var("SMTRS_CDCL_PREPRO_BUDGET") {
        Ok(v) => v.parse::<u64>().unwrap_or(10) * 1_000_000,
        Err(_) => STEP_BUDGET_DEFAULT,
    }
}
/// Elimination rounds (each round re-visits variables touched by the previous).
const BVE_ROUNDS: u32 = 4;

/// Preprocessing is deferred until the search has burned this many conflicts.
///
/// Running it before the first decision looks natural but loses money: on
/// bit-blasted QF_BV a large share of instances are *encode*-bound and are
/// solved in a few dozen conflicts, and an incremental script that pushes and
/// pops rebuilds the engine (and would re-preprocess) hundreds of times. Both
/// pay the full cost for nothing. Waiting for a few thousand conflicts costs
/// the search almost nothing on the instances where elimination pays off --
/// those run for 10^5 conflicts -- and costs nothing at all on the rest.
/// Override with `SMTRS_CDCL_PREPRO_AT` (0 = before the first search).
const PREPRO_AT_CONFLICTS_DEFAULT: u64 = 2_000;

/// Equivalent-literal substitution is on unless `SMTRS_CDCL_NO_ELS` is set
/// (A/B measurement and bisection).
fn els_enabled() -> bool {
    std::env::var_os("SMTRS_CDCL_NO_ELS").is_none()
}

/// Total number of preprocessing passes allowed, i.e. 1 + inprocessing rounds.
///
/// Preprocessing runs on the initial CNF and the clause database then changes
/// enormously during a long solve, so re-running it is the standard modern
/// design. It is *not* free, though: each pass rebuilds every watch list and
/// re-allocates every clause it rewrites into an arena that never shrinks, so
/// the rounds are capped and put on a widening schedule rather than run
/// whenever they might pay. `SMTRS_CDCL_INPROCESS` sets the cap (1 = the
/// original preprocess-once behaviour).
pub(super) fn inprocess_rounds() -> u32 {
    match std::env::var("SMTRS_CDCL_INPROCESS") {
        Ok(v) => v.parse::<u32>().unwrap_or(1).max(1),
        Err(_) => INPROCESS_ROUNDS_DEFAULT,
    }
}

const INPROCESS_ROUNDS_DEFAULT: u32 = 1;
/// Conflicts between one pass and the next.
pub(super) const INPROCESS_INTERVAL: u64 = 30_000;

pub(super) fn prepro_at_conflicts() -> u64 {
    match std::env::var("SMTRS_CDCL_PREPRO_AT") {
        Ok(v) => v.parse::<u64>().unwrap_or(PREPRO_AT_CONFLICTS_DEFAULT),
        Err(_) => PREPRO_AT_CONFLICTS_DEFAULT,
    }
}

// ---------- in-memory clause set ----------

struct Pc {
    lits: Vec<Lit>,
    sig: u64,
    /// Arena reference of the clause this came from, `CREF_NONE` if created
    /// during preprocessing.
    cref: CRef,
    dead: bool,
    /// `lits` differs from what the arena holds (strengthened).
    changed: bool,
}

fn signature(lits: &[Lit]) -> u64 {
    let mut s = 0u64;
    for l in lits {
        s |= 1u64 << (l.var().0 & 63);
    }
    s
}

/// Subsumption test on sorted literal vectors.
///
/// `Some(None)`: `ci` subsumes `cj`. `Some(Some(l))`: `ci` subsumes `cj` after
/// flipping `l` (so `!l` can be removed from `cj`). `None`: no relation.
fn subsumes(ci: &[Lit], cj: &[Lit]) -> Option<Option<Lit>> {
    if ci.len() > cj.len() {
        return None;
    }
    let mut flipped: Option<Lit> = None;
    let (mut i, mut j) = (0usize, 0usize);
    while i < ci.len() {
        if j == cj.len() {
            return None;
        }
        let (a, b) = (ci[i], cj[j]);
        if a.var() == b.var() {
            if a != b {
                if flipped.is_some() {
                    return None;
                }
                flipped = Some(a);
            }
            i += 1;
            j += 1;
        } else if a.var() > b.var() {
            j += 1;
        } else {
            return None;
        }
    }
    Some(flipped)
}

/// Resolvent of `a` and `b` on `v`, or `None` if it is a tautology.
/// Both inputs must be sorted; the result is sorted.
fn resolve(a: &[Lit], b: &[Lit], v: Var) -> Option<Vec<Lit>> {
    let mut out: Vec<Lit> = Vec::with_capacity(a.len() + b.len() - 2);
    for &l in a.iter().chain(b.iter()) {
        if l.var() != v {
            out.push(l);
        }
    }
    out.sort_unstable();
    out.dedup();
    for w in out.windows(2) {
        if w[0].var() == w[1].var() {
            return None; // l and !l: tautology
        }
    }
    Some(out)
}

struct Prepro {
    cl: Vec<Pc>,
    /// Clause ids per literal index; may hold stale (dead) ids.
    occ: Vec<Vec<u32>>,
    frozen: Vec<bool>,
    eliminated: Vec<bool>,
    /// Level-0 fixed vars: never candidates.
    fixed: Vec<bool>,
    /// Every new clause version in creation order (DRAT), empty if no proof.
    adds: Vec<Vec<Lit>>,
    keep_adds: bool,
    steps: u64,
    budget: u64,
    n_subsumed: u32,
    n_strengthened: u32,
    n_resolvents: u32,
    /// Equivalent-literal substitution: merged variables and unit clauses it
    /// derived (asserted after the commit, see `preprocess`).
    n_merged: u32,
    units: Vec<Lit>,
    unsat: bool,
    /// Eliminated variables with their clause sets, in elimination order.
    elims: Vec<ElimEntry>,
}

impl Prepro {
    fn push_clause(&mut self, lits: Vec<Lit>, cref: CRef) -> u32 {
        let id = self.cl.len() as u32;
        let sig = signature(&lits);
        for &l in &lits {
            self.occ[l.0 as usize].push(id);
        }
        self.cl.push(Pc {
            lits,
            sig,
            cref,
            dead: false,
            changed: false,
        });
        id
    }

    /// Register a clause created during preprocessing (records it for DRAT).
    fn new_clause(&mut self, lits: Vec<Lit>) -> u32 {
        if self.keep_adds {
            self.adds.push(lits.clone());
        }
        self.push_clause(lits, CREF_NONE)
    }

    fn kill(&mut self, id: u32) {
        if self.cl[id as usize].dead {
            return;
        }
        self.cl[id as usize].dead = true;
        let lits = std::mem::take(&mut self.cl[id as usize].lits);
        for &l in &lits {
            let occ = &mut self.occ[l.0 as usize];
            self.steps += occ.len() as u64 / 8 + 1;
            if let Some(pos) = occ.iter().position(|&x| x == id) {
                occ.swap_remove(pos);
            }
        }
        self.cl[id as usize].lits = lits;
    }

    /// Remove `l` from clause `id` (self-subsuming resolution). Caller must
    /// ensure the result still has at least two literals.
    fn strengthen(&mut self, id: u32, l: Lit) {
        {
            let c = &mut self.cl[id as usize];
            c.lits.retain(|&x| x != l);
            c.sig = signature(&c.lits);
            c.changed = true;
        }
        let occ = &mut self.occ[l.0 as usize];
        if let Some(pos) = occ.iter().position(|&x| x == id) {
            occ.swap_remove(pos);
        }
        self.n_strengthened += 1;
        if self.keep_adds {
            let lits = self.cl[id as usize].lits.clone();
            self.adds.push(lits);
        }
    }

    /// Literal of `lits` whose variable has the fewest occurrences.
    fn best_lit(&self, lits: &[Lit]) -> Lit {
        let mut best = lits[0];
        let mut best_n = usize::MAX;
        for &l in lits {
            let n = self.occ[l.0 as usize].len() + self.occ[(!l).0 as usize].len();
            if n < best_n {
                best_n = n;
                best = l;
            }
        }
        best
    }

    /// Is `lits` subsumed by some live clause? Read-only in the clause set, so
    /// occurrence lists are indexed directly.
    fn is_subsumed(&mut self, lits: &[Lit], sig: u64) -> bool {
        let best = self.best_lit(lits);
        for &pol in &[best, !best] {
            for k in 0..self.occ[pol.0 as usize].len() {
                let cj = self.occ[pol.0 as usize][k] as usize;
                if self.cl[cj].dead
                    || self.cl[cj].lits.len() > lits.len()
                    || self.cl[cj].sig & !sig != 0
                {
                    continue;
                }
                self.steps += self.cl[cj].lits.len() as u64;
                if subsumes(&self.cl[cj].lits, lits) == Some(None) {
                    return true;
                }
            }
        }
        false
    }

    /// Backward subsumption and self-subsuming resolution driven by clause
    /// `id`: every clause it subsumes is deleted, every clause it can
    /// strengthen loses a literal. Iterates over a snapshot of the occurrence
    /// list, which is sound because `kill`/`strengthen` only *remove* entries.
    fn subsume_with(&mut self, id: u32) {
        if self.cl[id as usize].dead || self.cl[id as usize].lits.len() > SUBSUME_LEN_LIMIT {
            return;
        }
        let lits = self.cl[id as usize].lits.clone();
        let sig = self.cl[id as usize].sig;
        let best = self.best_lit(&lits);
        for &pol in &[best, !best] {
            let cands: Vec<u32> = self.occ[pol.0 as usize].clone();
            for cj in cands {
                if cj == id || self.cl[cj as usize].dead || self.steps > self.budget {
                    continue;
                }
                let other = &self.cl[cj as usize];
                if other.lits.len() < lits.len() || sig & !other.sig != 0 {
                    continue;
                }
                self.steps += other.lits.len() as u64;
                match subsumes(&lits, &other.lits) {
                    Some(None) => {
                        self.kill(cj);
                        self.n_subsumed += 1;
                    }
                    Some(Some(l)) => {
                        // `other` contains !l and everything else of `lits`.
                        if self.cl[cj as usize].lits.len() <= 2 {
                            continue; // would produce a unit: skip (see module doc)
                        }
                        self.strengthen(cj, !l);
                    }
                    None => {}
                }
            }
        }
    }

    fn subsume_pass(&mut self) {
        let mut order: Vec<u32> = (0..self.cl.len() as u32)
            .filter(|&i| !self.cl[i as usize].dead)
            .collect();
        order.sort_by_key(|&i| self.cl[i as usize].lits.len());
        for id in order {
            if self.steps > self.budget {
                break;
            }
            self.subsume_with(id);
        }
    }

    /// Live clause ids containing `l`, compacting stale entries.
    fn live_occ(&mut self, l: Lit) -> Vec<u32> {
        let mut occ = std::mem::take(&mut self.occ[l.0 as usize]);
        occ.retain(|&id| !self.cl[id as usize].dead);
        self.occ[l.0 as usize] = occ.clone();
        occ
    }

    /// Try to eliminate `v`. Returns true on success.
    fn try_eliminate(&mut self, v: Var) -> bool {
        if self.frozen[v.0 as usize] || self.eliminated[v.0 as usize] || self.fixed[v.0 as usize] {
            return false;
        }
        let pl = Lit::new(v, true);
        let nl = Lit::new(v, false);
        // Cheap reject before compacting: stale entries only inflate the
        // occurrence lists, so a list far over the limit is hopeless.
        let (raw_pos, raw_neg) = (self.occ[pl.0 as usize].len(), self.occ[nl.0 as usize].len());
        if raw_pos + raw_neg == 0 || raw_pos > 4 * OCC_LIMIT || raw_neg > 4 * OCC_LIMIT {
            return false;
        }
        let pos = self.live_occ(pl);
        let neg = self.live_occ(nl);
        if pos.is_empty() && neg.is_empty() {
            return false;
        }
        if pos.len() > OCC_LIMIT || neg.len() > OCC_LIMIT {
            return false;
        }
        // Pure literal: no resolvents at all, elimination is free.
        let bound = pos.len() + neg.len();
        self.steps += (pos.len() * neg.len() * 4) as u64;

        let mut resolvents: Vec<Vec<Lit>> = Vec::new();
        for &a in &pos {
            for &b in &neg {
                let ra = &self.cl[a as usize].lits;
                let rb = &self.cl[b as usize].lits;
                let Some(r) = resolve(ra, rb, v) else {
                    continue;
                };
                if r.len() < 2 || r.len() > RESOLVENT_LEN_LIMIT {
                    // Units/empty clauses would change level-0 state mid-pass;
                    // over-long resolvents are not worth the variable.
                    return false;
                }
                if resolvents.len() >= bound {
                    return false; // growth bound exceeded
                }
                resolvents.push(r);
            }
        }
        // Drop resolvents already subsumed by a live clause: they need not be
        // added (the subsumer implies them, in the model direction too). No
        // clause containing `v` can subsume a resolvent, so doing this before
        // the originals are killed is fine.
        let mut kept: Vec<Vec<Lit>> = Vec::with_capacity(resolvents.len());
        for r in resolvents {
            let sig = signature(&r);
            if !self.is_subsumed(&r, sig) {
                kept.push(r);
            }
        }
        let resolvents = kept;

        // Commit: record the clause set for model reconstruction, then swap the
        // originals out for the resolvents.
        let mut recorded: Vec<Vec<Lit>> = Vec::with_capacity(bound);
        for &id in pos.iter().chain(neg.iter()) {
            recorded.push(self.cl[id as usize].lits.clone());
            self.kill(id);
        }
        for r in resolvents {
            self.n_resolvents += 1;
            self.new_clause(r);
        }
        self.eliminated[v.0 as usize] = true;
        self.elims.push(ElimEntry {
            var: v,
            clauses: recorded,
        });
        true
    }

    // ---------- equivalent-literal substitution ----------

    /// Strongly connected components of the binary implication graph.
    ///
    /// Node `i` is the literal with raw code `i`. A binary clause `(a ∨ b)`
    /// contributes `¬a → b` and `¬b → a`; every literal in a component is
    /// forced equal to every other. Iterative Tarjan — the graph has one node
    /// per literal and bit-blasted CNF reaches millions, so recursion would
    /// overflow the stack.
    fn binary_sccs(&mut self, nvars: usize) -> Vec<u32> {
        let n = 2 * nvars;
        // CSR adjacency, built with a counting pass so there is one allocation.
        let mut deg = vec![0u32; n + 1];
        for c in &self.cl {
            if !c.dead && c.lits.len() == 2 {
                deg[(!c.lits[0]).0 as usize] += 1;
                deg[(!c.lits[1]).0 as usize] += 1;
            }
        }
        let mut start = vec![0u32; n + 1];
        let mut acc = 0u32;
        for i in 0..=n {
            start[i] = acc;
            acc += deg[i];
        }
        drop(deg);
        let mut adj = vec![0u32; acc as usize];
        {
            // `deg` is dead now; reuse a fill cursor and drop it before the
            // Tarjan arrays are allocated. These arrays are 2 words per literal
            // and instances here reach millions of variables.
            let mut fill = start.clone();
            for c in &self.cl {
                if !c.dead && c.lits.len() == 2 {
                    let (a, b) = (c.lits[0], c.lits[1]);
                    adj[fill[(!a).0 as usize] as usize] = b.0;
                    fill[(!a).0 as usize] += 1;
                    adj[fill[(!b).0 as usize] as usize] = a.0;
                    fill[(!b).0 as usize] += 1;
                }
            }
        }
        self.steps += acc as u64 + n as u64;
        if acc == 0 {
            return vec![0; 0]; // no binary clauses: every literal is its own SCC
        }

        const UNVISITED: u32 = u32::MAX;
        let mut index = vec![UNVISITED; n];
        let mut low = vec![0u32; n];
        let mut on_stack = vec![false; n];
        let mut comp = vec![UNVISITED; n];
        let mut scc_stack: Vec<u32> = Vec::new();
        // (node, next adjacency slot to explore)
        let mut call: Vec<(u32, u32)> = Vec::new();
        let mut next_index = 0u32;
        let mut next_comp = 0u32;

        for root in 0..n as u32 {
            if index[root as usize] != UNVISITED {
                continue;
            }
            index[root as usize] = next_index;
            low[root as usize] = next_index;
            next_index += 1;
            scc_stack.push(root);
            on_stack[root as usize] = true;
            call.push((root, start[root as usize]));

            while let Some(&mut (v, ref mut e)) = call.last_mut() {
                if *e < start[v as usize + 1] {
                    let w = adj[*e as usize];
                    *e += 1;
                    if index[w as usize] == UNVISITED {
                        index[w as usize] = next_index;
                        low[w as usize] = next_index;
                        next_index += 1;
                        scc_stack.push(w);
                        on_stack[w as usize] = true;
                        call.push((w, start[w as usize]));
                    } else if on_stack[w as usize] {
                        low[v as usize] = low[v as usize].min(index[w as usize]);
                    }
                } else {
                    call.pop();
                    if low[v as usize] == index[v as usize] {
                        loop {
                            let w = scc_stack.pop().unwrap();
                            on_stack[w as usize] = false;
                            comp[w as usize] = next_comp;
                            if w == v {
                                break;
                            }
                        }
                        next_comp += 1;
                    }
                    if let Some(&mut (p, _)) = call.last_mut() {
                        low[p as usize] = low[p as usize].min(low[v as usize]);
                    }
                }
            }
        }
        self.steps += next_index as u64;
        comp
    }

    /// Merge literals forced equal by the binary implication graph.
    ///
    /// Returns the substitution's effect through `self`: `elims` gains one
    /// entry per merged variable (recording the two binary clauses that define
    /// the equivalence, which is exactly what `extend_model` and `restore_var`
    /// need), `units` gains any unit derived by the rewrite, and `unsat` is set
    /// if some component contains a literal and its negation.
    fn els(&mut self, nvars: usize) {
        let n = 2 * nvars;
        let comp = self.binary_sccs(nvars);
        if comp.is_empty() {
            return; // no binary clauses, so no equivalences
        }

        // A component holding both l and ¬l asserts l ↔ ¬l.
        for v in 0..nvars {
            let p = Lit::new(Var(v as u32), true);
            if comp[p.0 as usize] == comp[(!p).0 as usize] {
                self.unsat = true;
                return;
            }
        }

        // Representative per component. First literal encountered wins, and
        // the complementary component takes the negation so that `rep` stays
        // consistent under negation. A frozen variable is preferred: it must
        // survive as a decision literal, so it cannot be substituted away.
        let mut rep = vec![Lit(0); n];
        let mut have = vec![false; n];
        for i in 0..n as u32 {
            let c = comp[i as usize] as usize;
            if have[c] {
                continue;
            }
            let l = Lit(i);
            rep[c] = l;
            have[c] = true;
            let cn = comp[(!l).0 as usize] as usize;
            rep[cn] = !l;
            have[cn] = true;
        }
        for i in 0..n as u32 {
            let l = Lit(i);
            if !self.frozen[l.var().0 as usize] {
                continue;
            }
            let c = comp[i as usize] as usize;
            if !self.frozen[rep[c].var().0 as usize] {
                rep[c] = l;
                rep[comp[(!l).0 as usize] as usize] = !l;
            }
        }

        // Variables that actually move. Frozen and level-0 fixed variables stay
        // put; the binary clauses that tie them to their representative are
        // left in the formula, so nothing about them changes.
        let mut merged: Vec<Var> = Vec::new();
        for v in 0..nvars as u32 {
            let p = Lit::new(Var(v), true);
            if self.frozen[v as usize] || self.fixed[v as usize] || self.eliminated[v as usize] {
                continue;
            }
            if rep[comp[p.0 as usize] as usize] != p {
                merged.push(Var(v));
            }
        }
        if merged.is_empty() {
            return;
        }

        // The substitution maps *only* merged variables. A variable held back
        // (frozen, or fixed at level 0) must keep its own literals, or the
        // binary clauses that tie it to the representative would collapse into
        // tautologies and the equivalence would be lost -- leaving it
        // unconstrained rather than equal to anything.
        let mut is_merged = vec![false; nvars];
        for &v in &merged {
            is_merged[v.0 as usize] = true;
        }
        let mut sub: Vec<Lit> = (0..n as u32).map(Lit).collect();
        for i in 0..n as u32 {
            let l = Lit(i);
            if is_merged[l.var().0 as usize] {
                let r = rep[comp[i as usize] as usize];
                debug_assert!(!is_merged[r.var().0 as usize]);
                sub[i as usize] = r;
            }
        }

        // Rewrite every live clause through `sub`.
        let mut occ_new: Vec<Vec<u32>> = vec![Vec::new(); n];
        for id in 0..self.cl.len() {
            if self.cl[id].dead {
                continue;
            }
            let mut lits = std::mem::take(&mut self.cl[id].lits);
            self.steps += lits.len() as u64;
            let mut moved = false;
            for l in lits.iter_mut() {
                let r = sub[l.0 as usize];
                if r != *l {
                    *l = r;
                    moved = true;
                }
            }
            if !moved {
                for &l in &lits {
                    occ_new[l.0 as usize].push(id as u32);
                }
                self.cl[id].lits = lits;
                continue;
            }
            lits.sort_unstable();
            lits.dedup();
            let taut = lits.windows(2).any(|w| w[0].var() == w[1].var());
            if taut {
                self.cl[id].dead = true;
                self.cl[id].lits = lits;
                continue;
            }
            match lits.len() {
                0 => {
                    self.unsat = true;
                    self.cl[id].lits = lits;
                    return;
                }
                1 => {
                    // Level-0 truth, but it cannot be asserted mid-pass without
                    // changing level-0 state under the rest of the rewrite, so
                    // it is applied after the commit. Until then the variable
                    // must be treated as fixed: eliminating a variable whose
                    // value is already forced would let `extend_model` overwrite
                    // that value with a reconstruction that never saw the unit,
                    // and the reported model could violate it.
                    if self.keep_adds {
                        self.adds.push(lits.clone());
                    }
                    self.fixed[lits[0].var().0 as usize] = true;
                    self.units.push(lits[0]);
                    self.cl[id].dead = true;
                    self.cl[id].lits = lits;
                }
                _ => {
                    if self.keep_adds {
                        self.adds.push(lits.clone());
                    }
                    for &l in &lits {
                        occ_new[l.0 as usize].push(id as u32);
                    }
                    self.cl[id].sig = signature(&lits);
                    self.cl[id].changed = true;
                    self.cl[id].lits = lits;
                }
            }
        }
        self.occ = occ_new;

        // Record the equivalences. `(¬v ∨ r)` and `(v ∨ ¬r)` are exactly the
        // clauses `extend_model` needs to recover v from r, and exactly what
        // `restore_var` must put back if a later clause mentions v.
        for v in merged {
            let p = Lit::new(v, true);
            let r = sub[p.0 as usize];
            debug_assert_ne!(r.var(), v);
            self.eliminated[v.0 as usize] = true;
            self.n_merged += 1;
            self.elims.push(ElimEntry {
                var: v,
                clauses: vec![vec![!p, r], vec![p, !r]],
            });
        }
    }

    fn bve_rounds(&mut self, nvars: usize) {
        // Round 1: every variable, cheapest first.
        let mut cands: Vec<Var> = (0..nvars as u32)
            .map(Var)
            .filter(|&v| {
                !self.frozen[v.0 as usize]
                    && !self.fixed[v.0 as usize]
                    && !(self.occ[Lit::new(v, true).0 as usize].is_empty()
                        && self.occ[Lit::new(v, false).0 as usize].is_empty())
            })
            .collect();
        cands.sort_by_key(|&v| {
            self.occ[Lit::new(v, true).0 as usize].len()
                + self.occ[Lit::new(v, false).0 as usize].len()
        });
        for _round in 0..BVE_ROUNDS {
            let mut touched: Vec<Var> = Vec::new();
            let mut any = false;
            for v in std::mem::take(&mut cands) {
                if self.steps > self.budget {
                    break;
                }
                let before = self.elims.len();
                if self.try_eliminate(v) {
                    any = true;
                    // Variables sharing a clause with `v` got smaller
                    // occurrence lists: re-try them next round.
                    for cl in &self.elims[before].clauses {
                        for &l in cl {
                            touched.push(l.var());
                        }
                    }
                }
            }
            if !any || self.steps > self.budget {
                break;
            }
            touched.sort_unstable();
            touched.dedup();
            touched.retain(|&v| {
                !self.eliminated[v.0 as usize]
                    && !self.frozen[v.0 as usize]
                    && !self.fixed[v.0 as usize]
            });
            cands = touched;
            if cands.is_empty() {
                break;
            }
        }
    }
}

impl Solver {
    /// Drop every learnt clause. Called before preprocessing: eliminating a
    /// variable that still occurs in a learnt clause would be unsound, and
    /// resolving learnts along with the problem clauses is not worth the
    /// bookkeeping. Deleting them is always sound -- they are implied by the
    /// original formula, so the reconstructed model satisfies them anyway --
    /// and the watch lists are rebuilt from scratch by the commit phase.
    ///
    /// Binary learnts are the exception on *inprocessing* rounds: there they
    /// are promoted to problem clauses instead of dropped. They are the
    /// cheapest clauses in the database, and they are exactly what
    /// equivalent-literal substitution consumes — an equivalence that the
    /// *search* discovered is invisible to a pass over the original CNF.
    /// Promotion is sound in both directions: a learnt is implied by the
    /// problem, so treating it as one adds no models, and BVE records it like
    /// any other clause when it eliminates one of its variables.
    ///
    /// It is nevertheless **off on the first pass**, and that is measured, not
    /// assumed. The counter used to be incremented before this call, so
    /// promotion was on during the one pass that runs at the default
    /// `INPROCESS_ROUNDS_DEFAULT = 1` — the exact case the comment said it
    /// must not be. A/B over 495 QF_BV files (both binaries interleaved in one
    /// harness pass) says the comment had it right: promotion off gains 5 and
    /// loses 0. The mechanism is visible on `Sage2/bench_1947`, where
    /// promotion adds 195 binary clauses to the problem set and those extra
    /// occurrences block 67 variable eliminations (1838 vs 1905) in exchange
    /// for 5 more merged equivalences (133 vs 128). After 2 000 conflicts the
    /// binaries the search has found are not worth what they cost BVE; after
    /// 30 000 they are, which is why later rounds keep them.
    fn flush_learnts(&mut self) {
        // `prepro_rounds` is already incremented for the pass in progress, so
        // the first pass is round 1.
        let promote = self.prepro_rounds > 1 && els_enabled();
        let mut kept_binary = 0u32;
        for i in 0..self.learnts.len() {
            let c = self.learnts[i];
            if self.is_deleted(c) {
                continue;
            }
            if promote && self.clause_len(c) == 2 {
                self.db[c as usize + 1] = 0; // clear learnt/protected/lbd
                kept_binary += 1;
                continue;
            }
            self.drat_delete(c);
            self.set_deleted(c);
        }
        self.learnts.clear();
        self.promoted_binaries += kept_binary as u64;
    }

    /// Run preprocessing, once per solver. `assumptions` are frozen (they must
    /// stay usable as decision literals for this call); anything arriving later
    /// is handled by `restore_var`. Must be called at level 0 with level-0
    /// propagation complete.
    pub(super) fn preprocess(&mut self, assumptions: &[Lit]) {
        if self.preprocessed && self.prepro_rounds >= self.inprocess_rounds {
            return;
        }
        self.preprocessed = true;
        self.prepro_rounds += 1;
        // Schedule the next pass before any early return, so a pass that
        // declines to do work does not spin on the hook every conflict.
        self.prepro_at_conflicts = self.conflicts + self.inprocess_interval;
        if self.prepro_mode == PreproMode::Off || !self.ok || self.decision_level() != 0 {
            return;
        }
        self.flush_learnts();
        let nvars = self.num_vars();
        if nvars == 0 {
            return;
        }
        let t0 = std::time::Instant::now();

        // Level-0 reasons may point at clauses this pass deletes. Nothing reads
        // them (analysis skips level-0 vars), but stale CRefs are a trap.
        for i in 0..self.trail.len() {
            let v = self.trail[i].var();
            self.reason[v.0 as usize] = CREF_NONE;
        }

        // ---- collect + clean the problem clauses ----
        // Clauses satisfied at level 0 are gone for good and clauses with
        // level-0 falsified literals shrink. On bit-blasted CNF this alone is
        // most of the database, so it runs allocation-free: only the survivors
        // get a literal vector.
        let mut crefs: Vec<CRef> = Vec::new();
        let mut n_clauses_before = 0usize;
        let mut dead_originals: Vec<CRef> = Vec::new();
        {
            let mut i = 0usize;
            while i < self.db.len() {
                let len = self.db[i] as usize;
                let c = i as CRef;
                i += 2 + len;
                if self.is_learnt(c) || self.is_deleted(c) {
                    continue;
                }
                n_clauses_before += 1;
                let satisfied = (0..len).any(|k| self.value_lit(self.lit_at(c, k)) == lbool::TRUE);
                if satisfied {
                    dead_originals.push(c);
                } else {
                    crefs.push(c);
                }
            }
        }
        if n_clauses_before == 0 || crefs.is_empty() {
            return;
        }

        let mut p = Prepro {
            cl: Vec::with_capacity(crefs.len()),
            occ: vec![Vec::new(); 2 * nvars],
            frozen: vec![false; nvars],
            eliminated: vec![false; nvars],
            fixed: (0..nvars).map(|v| self.assign[v] != lbool::UNDEF).collect(),
            adds: Vec::new(),
            keep_adds: self.drat.is_some(),
            steps: 0,
            budget: step_budget(),
            n_subsumed: 0,
            n_strengthened: 0,
            n_resolvents: 0,
            n_merged: 0,
            units: Vec::new(),
            unsat: false,
            elims: Vec::new(),
        };
        for &a in assumptions {
            p.frozen[a.var().0 as usize] = true;
        }
        for &v in &self.frozen_vars {
            if (v.0 as usize) < nvars {
                p.frozen[v.0 as usize] = true;
            }
        }

        for &c in &crefs {
            let len = self.clause_len(c);
            let mut lits: Vec<Lit> = Vec::with_capacity(len);
            for i in 0..len {
                let l = self.lit_at(c, i);
                if self.value_lit(l) != lbool::FALSE {
                    lits.push(l);
                }
            }
            // After full level-0 propagation no clause can have fewer than two
            // non-false literals; bail out rather than trust that.
            if lits.len() < 2 {
                return;
            }
            lits.sort_unstable();
            if lits.len() < len {
                // Strengthened by level-0 units: a new clause version.
                dead_originals.push(c);
                p.new_clause(lits);
            } else {
                p.push_clause(lits, c);
            }
        }

        let n_after_clean = p.cl.iter().filter(|c| !c.dead).count();
        // ---- equivalent-literal substitution ----
        // Runs first: it shrinks the variable set that subsumption and
        // elimination then work over, and the clause merges it creates are
        // precisely what backward subsumption is good at cleaning up.
        if self.prepro_mode != PreproMode::Clean && els_enabled() {
            p.els(nvars);
            if p.unsat {
                self.ok = false;
                return;
            }
        }
        let n_merged = p.n_merged;
        self.prepro_vars_merged += n_merged as u64;
        // ---- subsumption / self-subsuming resolution ----
        if self.prepro_mode != PreproMode::Clean {
            p.subsume_pass();
        }
        let n_after_sub = p.cl.iter().filter(|c| !c.dead).count();
        let sub_steps = p.steps;
        // ---- bounded variable elimination ----
        // Its own budget: elimination buys more (a variable *and* clauses) per
        // step than subsumption, so a subsumption pass that ran long must not
        // starve it.
        p.steps = 0;
        if self.prepro_mode == PreproMode::Full {
            p.bve_rounds(nvars);
        }

        // ---- commit ----
        // DRAT: all additions first (each is RUP against the still-complete
        // clause set), deletions afterwards (always sound, and omitting one
        // would only leave the checker with a superset).
        if self.drat.is_some() {
            self.drat_comment("prepro: resolvents and strengthened clauses (RUP)");
            let adds = std::mem::take(&mut p.adds);
            for lits in &adds {
                self.drat_add(lits);
            }
            self.drat_comment("search");
        }
        for c in dead_originals {
            self.drat_delete(c);
            self.set_deleted(c);
        }
        // Watch lists are rebuilt from scratch: unwatching clause by clause
        // costs a scan of two watch lists each, and on bit-blasted CNF most of
        // the database is being removed (measured: 0.85s -> 0.05s on a 1.1M
        // clause input). Nothing else needs its watches: learnt clauses were
        // flushed, and every surviving clause has two non-false literals at
        // level 0, so any pair of positions is a legal watch pair.
        for w in self.watches.iter_mut() {
            w.clear();
        }
        let mut n_clauses_after = 0usize;
        let mut survivors: Vec<CRef> = Vec::with_capacity(p.cl.len());
        for i in 0..p.cl.len() {
            let dead = p.cl[i].dead;
            let cref = p.cl[i].cref;
            let changed = p.cl[i].changed;
            if (dead || changed) && cref != CREF_NONE {
                self.drat_delete(cref);
                self.set_deleted(cref);
            }
            if dead {
                continue;
            }
            n_clauses_after += 1;
            if cref == CREF_NONE || changed {
                let lits = std::mem::take(&mut p.cl[i].lits);
                debug_assert!(lits.len() >= 2);
                survivors.push(self.alloc_clause(&lits, false, 0));
            } else {
                survivors.push(cref);
            }
        }
        for c in survivors {
            self.watch_clause(c);
        }

        // Units derived by the substitution. They hold at level 0; asserting
        // them here (rather than during the rewrite) keeps the pass free of
        // mid-flight level-0 changes.
        let units = std::mem::take(&mut p.units);
        for l in units {
            match self.value_lit(l) {
                lbool::TRUE => {}
                lbool::FALSE => {
                    self.ok = false;
                    return;
                }
                _ => self.enqueue(l, CREF_NONE),
            }
        }

        let n_elim = p.elims.len();
        for e in p.elims {
            self.elim_index[e.var.0 as usize] = self.elim_stack.len() as i32;
            self.heap_remove(e.var);
            self.vmtf_dequeue(e.var);
            self.elim_stack.push(e);
        }
        // Substituted units may force more; the caller's contract is that
        // level-0 propagation is complete when preprocessing returns.
        if self.propagate().is_some() {
            self.ok = false;
            return;
        }
        self.prepro_secs = t0.elapsed().as_secs_f64();
        self.prepro_vars_elim = n_elim as u32;
        self.prepro_clauses_before = n_clauses_before as u32;
        self.prepro_clauses_after = n_clauses_after as u32;

        if std::env::var_os("SMTRS_DEBUG").is_some() {
            let fixed = self.trail.len();
            let unfixed = nvars - fixed;
            let live_vars = unfixed.saturating_sub(self.elim_stack.len());
            eprintln!(
                "; prepro[{}@{}c]: vars={nvars} fixed_l0={fixed} elim={n_elim} merged={n_merged} \
live={live_vars} ({:.1}% of unfixed eliminated) | clauses {n_clauses_before} -> clean \
{n_after_clean} -> sub {n_after_sub} -> bve {n_clauses_after} ({:.1}% total removed) | \
subsumed={} strengthened={} resolvents={} promoted={} steps={}+{} {:.3}s",
                self.prepro_rounds,
                self.conflicts,
                100.0 * n_elim as f64 / unfixed.max(1) as f64,
                100.0 * (n_clauses_before as f64 - n_clauses_after as f64)
                    / n_clauses_before as f64,
                p.n_subsumed,
                p.n_strengthened,
                p.n_resolvents,
                self.promoted_binaries,
                sub_steps,
                p.steps,
                self.prepro_secs,
            );
        }
    }

    /// Re-introduce `v` (and everything eliminated after it) because a clause
    /// or assumption mentions it.
    pub(super) fn restore_var(&mut self, v: Var) {
        let p = self.elim_index[v.0 as usize];
        if p < 0 {
            return;
        }
        // A reconstructed model in `assign` looks like level-0 truth to
        // `add_clause_inner`, which would drop restored clauses as satisfied
        // and restored literals as falsified. Clear it first, always.
        self.clear_extended_model();
        let target = p as usize;
        if self.drat.is_some() {
            self.drat_comment(
                "smtrs: BVE restore -- the additions below are not RUP; proof incomplete",
            );
        }
        let mut stack = std::mem::take(&mut self.elim_stack);
        while stack.len() > target {
            let e = stack.pop().unwrap();
            self.elim_index[e.var.0 as usize] = -1;
            self.heap_insert(e.var);
            self.vmtf_enqueue(e.var);
            self.restored_vars += 1;
            for cl in &e.clauses {
                debug_assert!(cl.iter().all(|&l| self.elim_index[l.var().0 as usize] < 0));
                if self.drat.is_some() {
                    self.drat_add(cl);
                }
                self.add_clause_inner(cl);
            }
        }
        self.elim_stack = stack;
    }

    /// Restore every eliminated variable mentioned in `lits`.
    pub(super) fn restore_lits(&mut self, lits: &[Lit]) {
        if self.elim_stack.is_empty() {
            return;
        }
        for &l in lits {
            if self.elim_index[l.var().0 as usize] >= 0 {
                self.restore_var(l.var());
            }
        }
    }

    /// Give every eliminated variable a value consistent with the clauses that
    /// were removed when it was eliminated. Called on a full model.
    pub(super) fn extend_model(&mut self) {
        if self.elim_stack.is_empty() {
            return;
        }
        let stack = std::mem::take(&mut self.elim_stack);
        // Reverse elimination order: a recorded clause can only mention live
        // variables (already assigned by the search) or variables eliminated
        // later (assigned by an earlier iteration of this loop).
        for e in stack.iter().rev() {
            let v = e.var;
            debug_assert_eq!(self.assign[v.0 as usize], lbool::UNDEF);
            let mut need_true = false;
            let mut need_false = false;
            for cl in &e.clauses {
                let mut own = Lit::new(v, true);
                let mut other_sat = false;
                for &l in cl {
                    if l.var() == v {
                        own = l;
                    } else if self.value_lit(l) == lbool::TRUE {
                        other_sat = true;
                        break;
                    }
                }
                if !other_sat {
                    if own.is_positive() {
                        need_true = true;
                    } else {
                        need_false = true;
                    }
                }
            }
            debug_assert!(
                !(need_true && need_false),
                "eliminated var {} has contradictory clauses",
                v.0
            );
            // `need_true` wins: a clause requiring v=true is only unsatisfiable
            // if the resolvents were violated, which cannot happen on a model.
            self.assign[v.0 as usize] = if need_true { lbool::TRUE } else { lbool::FALSE };
        }
        self.elim_stack = stack;
        self.model_extended = true;
    }

    /// Undo `extend_model`: eliminated variables go back to unassigned before
    /// any clause is added or any search resumes.
    pub(super) fn clear_extended_model(&mut self) {
        if !self.model_extended {
            return;
        }
        for i in 0..self.elim_stack.len() {
            let v = self.elim_stack[i].var;
            self.assign[v.0 as usize] = lbool::UNDEF;
        }
        self.model_extended = false;
    }
}
