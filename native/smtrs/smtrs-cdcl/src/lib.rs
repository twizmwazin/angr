//! smtrs-cdcl: a modern CDCL SAT solver in pure Rust.
//!
//! MiniSat/Glucose lineage: arena-stored clauses, two-watched-literal
//! propagation with blocker literals, VMTF branching with phase saving
//! (`SMTRS_CDCL_DECISION` also offers the EVSIDS heap this replaced),
//! first-UIP conflict analysis with recursive clause minimization, LBD (glue)
//! tracking with glue-based learnt-database reduction, Luby restarts,
//! CaDiCaL-style lucky phases before the first search,
//! chronological backtracking (Nadel-Ryvchin style, threshold-gated),
//! periodic learnt-clause vivification, incremental solving under
//! assumptions, and optional DRAT proof emission.
//!
//! Determinism: no randomness anywhere; identical input produces identical
//! traces.

mod solver;

pub use solver::{lbool, DecisionMode, Lit, Solver, Var};

#[cfg(test)]
mod tests {
    use super::*;

    fn lit(solver_vars: &[Var], i: i32) -> Lit {
        let v = solver_vars[(i.unsigned_abs() as usize) - 1];
        Lit::new(v, i > 0)
    }

    fn nvars(s: &mut Solver, n: usize) -> Vec<Var> {
        (0..n).map(|_| s.new_var()).collect()
    }

    /// A conflict at a decision level above the variable count. `solve` opens
    /// one level per assumption *index* — an already-satisfied assumption
    /// opens an empty pseudo-level — so stacking repeated assumptions drives
    /// the level past `num_vars`, and conflict analysis then indexes its
    /// level-stamped LBD array out of bounds unless it grows with the level.
    /// This is the shape smtrs-solver's bit-fixing minimize/eval_n loops
    /// produce.
    #[test]
    fn conflict_above_variable_count_levels() {
        let mut s = Solver::new();
        let vs = nvars(&mut s, 3);
        // y -> z and y -> !z: assuming y is a conflict found by propagation.
        s.add_clause(&[lit(&vs, -2), lit(&vs, 3)]);
        s.add_clause(&[lit(&vs, -2), lit(&vs, -3)]);
        // x padded out far past the variable count, then the conflicting y.
        let mut assums = vec![lit(&vs, 1); 64];
        assums.push(lit(&vs, 2));
        assert_eq!(s.solve(&assums), lbool::FALSE);
        // And the solver is still usable afterwards.
        assert_eq!(s.solve(&[lit(&vs, 1)]), lbool::TRUE);
    }

    #[test]
    fn trivial() {
        let mut s = Solver::new();
        let vs = nvars(&mut s, 2);
        s.add_clause(&[lit(&vs, 1), lit(&vs, 2)]);
        s.add_clause(&[lit(&vs, -1)]);
        assert_eq!(s.solve(&[]), lbool::TRUE);
        assert_eq!(s.value_lit(lit(&vs, 2)), lbool::TRUE);
        s.add_clause(&[lit(&vs, -2)]);
        assert_eq!(s.solve(&[]), lbool::FALSE);
    }

    #[test]
    fn empty_clause_unsat() {
        let mut s = Solver::new();
        let _ = nvars(&mut s, 1);
        s.add_clause(&[]);
        assert_eq!(s.solve(&[]), lbool::FALSE);
    }

    #[test]
    fn assumptions_incremental() {
        let mut s = Solver::new();
        let vs = nvars(&mut s, 3);
        // 1 -> 2, 2 -> 3
        s.add_clause(&[lit(&vs, -1), lit(&vs, 2)]);
        s.add_clause(&[lit(&vs, -2), lit(&vs, 3)]);
        assert_eq!(s.solve(&[lit(&vs, 1), lit(&vs, -3)]), lbool::FALSE);
        assert_eq!(s.solve(&[lit(&vs, 1)]), lbool::TRUE);
        assert_eq!(s.value_lit(lit(&vs, 3)), lbool::TRUE);
        assert_eq!(s.solve(&[]), lbool::TRUE);
        // Contradictory assumptions.
        assert_eq!(s.solve(&[lit(&vs, 2), lit(&vs, -2)]), lbool::FALSE);
        assert_eq!(s.solve(&[]), lbool::TRUE);
    }

    #[test]
    fn failed_assumptions_are_a_genuine_subset() {
        let mut s = Solver::new();
        let vs = nvars(&mut s, 4);
        // 1 -> 2, 2 -> 3. Assumption 4 is a bystander and must not appear.
        s.add_clause(&[lit(&vs, -1), lit(&vs, 2)]);
        s.add_clause(&[lit(&vs, -2), lit(&vs, 3)]);
        let assumps = [lit(&vs, 4), lit(&vs, 1), lit(&vs, -3)];
        assert_eq!(s.solve(&assumps), lbool::FALSE);
        let failed = s.failed_assumptions().to_vec();
        assert!(failed.iter().all(|f| assumps.contains(f)));
        assert!(failed.contains(&lit(&vs, 1)) && failed.contains(&lit(&vs, -3)));
        assert!(!failed.contains(&lit(&vs, 4)), "bystander in the core");
        assert_eq!(s.solve(&failed), lbool::FALSE);

        // A refutation that owes nothing to the assumptions reports the empty
        // set, which is a stronger statement than any nonempty one.
        s.add_clause(&[lit(&vs, 1)]);
        s.add_clause(&[lit(&vs, -3)]);
        assert_eq!(s.solve(&[lit(&vs, 4)]), lbool::FALSE);
        assert!(s.failed_assumptions().is_empty());
    }

    /// The property that makes a failed-assumption set usable as an unsat
    /// core: re-solving under *only* the reported subset must still be unsat.
    ///
    /// Random CNFs with random assumption sets, across all three preprocessing
    /// entry points, so BVE and equivalent-literal substitution both run
    /// underneath the extraction — an eliminated or merged variable that is
    /// then assumed is exactly the shape that would silently drop a member.
    #[test]
    fn failed_assumptions_re_refute_on_random_cnfs() {
        let mut seed = 0x0a5e_c07eu64;
        let mut rng = move || {
            seed ^= seed << 13;
            seed ^= seed >> 7;
            seed ^= seed << 17;
            seed
        };
        let (mut unsat_under_assumps, mut nonempty_cores, mut strict_subsets) = (0, 0, 0);
        for round in 0..800 {
            let nv = 6 + (rng() % 30) as usize;
            // Below the phase transition: the clause set alone is usually
            // satisfiable, so the refutation has to come from the assumptions
            // and the reported set is usually nonempty. At 3.5+ the formulas
            // refute themselves and the extraction is never exercised.
            let density = 1.0 + (rng() % 20) as f64 / 10.0;
            let nc = (nv as f64 * density) as usize;
            let mut clauses: Vec<Vec<usize>> = Vec::new();
            for _ in 0..nc {
                let len = 1 + (rng() % 4) as usize;
                let mut cl: Vec<usize> = Vec::new();
                for _ in 0..len {
                    let x = (rng() % nv as u64) as usize * 2 + (rng() % 2) as usize;
                    if !cl.contains(&x) {
                        cl.push(x);
                    }
                }
                clauses.push(cl);
            }
            let mut s = Solver::new();
            s.disable_lucky();
            s.set_prepro_at([0, 1, 7][round % 3]);
            let vs = nvars(&mut s, nv);
            let lits = |cl: &[usize], vs: &[Var]| -> Vec<Lit> {
                cl.iter()
                    .map(|&x| Lit::new(vs[x / 2], x % 2 == 0))
                    .collect()
            };
            for cl in &clauses {
                s.add_clause(&lits(cl, &vs));
            }
            // A wide assumption set: most of the variables, so that a real
            // subset selection has something to select from.
            let mut assumps: Vec<usize> = Vec::new();
            for v in 0..nv {
                if rng() % 3 != 0 {
                    assumps.push(v * 2 + (rng() % 2) as usize);
                }
            }
            let a = lits(&assumps, &vs);
            if s.solve(&a) != lbool::FALSE {
                continue;
            }
            unsat_under_assumps += 1;
            let failed = s.failed_assumptions().to_vec();
            for f in &failed {
                assert!(a.contains(f), "round {round}: {f:?} was never assumed");
            }
            if !failed.is_empty() {
                nonempty_cores += 1;
                if failed.len() < a.len() {
                    strict_subsets += 1;
                }
            }
            // The whole point: the reported subset alone still refutes.
            assert_eq!(
                s.solve(&failed),
                lbool::FALSE,
                "round {round}: core of {} of {} assumptions did not re-refute",
                failed.len(),
                a.len()
            );
        }
        // Guard against the test silently exercising nothing, and against a
        // trivially-sound implementation that just returns every assumption.
        assert!(unsat_under_assumps > 200, "{unsat_under_assumps} unsats");
        assert!(nonempty_cores > 100, "{nonempty_cores} nonempty cores");
        assert!(strict_subsets > 100, "{strict_subsets} strict subsets");
    }

    /// Pigeonhole: n+1 pigeons, n holes — small but requires real search.
    fn pigeonhole(n: usize) -> (Solver, Vec<Var>) {
        let mut s = Solver::new();
        let pigeons = n + 1;
        let vs = nvars(&mut s, pigeons * n);
        let at = |p: usize, h: usize| Lit::new(vs[p * n + h], true);
        for p in 0..pigeons {
            let cl: Vec<Lit> = (0..n).map(|h| at(p, h)).collect();
            s.add_clause(&cl);
        }
        for h in 0..n {
            for p1 in 0..pigeons {
                for p2 in p1 + 1..pigeons {
                    s.add_clause(&[!at(p1, h), !at(p2, h)]);
                }
            }
        }
        (s, vs)
    }

    #[test]
    fn pigeonhole_unsat() {
        for n in [3, 5, 7] {
            let (mut s, _) = pigeonhole(n);
            assert_eq!(s.solve(&[]), lbool::FALSE, "php {n}");
        }
    }

    #[test]
    fn graph_coloring_sat() {
        // 3-color a 5-cycle (odd cycle: 3-colorable, not 2-colorable).
        let mut s = Solver::new();
        let n = 5;
        let k = 3;
        let vs = nvars(&mut s, n * k);
        let col = |v: usize, c: usize| Lit::new(vs[v * k + c], true);
        for v in 0..n {
            let cl: Vec<Lit> = (0..k).map(|c| col(v, c)).collect();
            s.add_clause(&cl);
            for c1 in 0..k {
                for c2 in c1 + 1..k {
                    s.add_clause(&[!col(v, c1), !col(v, c2)]);
                }
            }
        }
        for v in 0..n {
            let w = (v + 1) % n;
            for c in 0..k {
                s.add_clause(&[!col(v, c), !col(w, c)]);
            }
        }
        assert_eq!(s.solve(&[]), lbool::TRUE);
        // Verify the coloring.
        for v in 0..n {
            let w = (v + 1) % n;
            for c in 0..k {
                assert!(
                    !(s.value_lit(col(v, c)) == lbool::TRUE
                        && s.value_lit(col(w, c)) == lbool::TRUE),
                    "adjacent same color"
                );
            }
        }
    }

    /// Verify emitted DRAT proofs with a small internal RUP checker: every
    /// learnt clause must be derivable by unit propagation from the clauses
    /// live at that point in the proof.
    #[test]
    fn drat_proofs_are_rup() {
        let dir = std::env::temp_dir();
        let mut seed = 0xabcdefu64;
        let mut rng = move || {
            seed ^= seed << 13;
            seed ^= seed >> 7;
            seed ^= seed << 17;
            seed
        };
        // The later rounds are deliberately larger: at a dozen variables a
        // learnt clause rarely spans enough decision levels for minimization to
        // have anything to remove, so the small rounds alone leave most of
        // `analyze`'s output unexercised.
        for round in 0..30 {
            let path = dir.join(format!("smtrs-drat-{round}.drat"));
            let path_s = path.to_str().unwrap().to_string();
            let nv = if round < 25 {
                12 + (rng() % 10) as usize
            } else {
                45 + (rng() % 10) as usize
            };
            let nc = (nv as f64 * 4.3) as usize;
            let mut s = Solver::new();
            s.enable_drat(&path_s);
            s.set_prepro_at(0); // cover preprocessing additions in the proof
            let vs = nvars(&mut s, nv);
            let mut formula: Vec<Vec<i32>> = Vec::new();
            for _ in 0..nc {
                let mut cl = Vec::new();
                while cl.len() < 3 {
                    let v = (rng() % nv as u64) as i32 + 1;
                    let l = if rng() % 2 == 0 { v } else { -v };
                    if !cl.contains(&l) && !cl.contains(&-l) {
                        cl.push(l);
                    }
                }
                let lits: Vec<Lit> = cl.iter().map(|&i| lit(&vs, i)).collect();
                s.add_clause(&lits);
                formula.push(cl);
            }
            let res = s.solve(&[]);
            s.flush_drat();
            let proof = std::fs::read_to_string(&path_s).unwrap();
            let _ = std::fs::remove_file(&path_s);

            // RUP check each proof step against the live clause set.
            let mut db: Vec<Vec<i32>> = formula.clone();
            let mut checked = 0;
            for line in proof.lines() {
                if line.starts_with('c') {
                    continue; // comment (phase marker)
                }
                let (is_delete, rest) = match line.strip_prefix("d ") {
                    Some(r) => (true, r),
                    None => (false, line),
                };
                let cl: Vec<i32> = rest
                    .split_whitespace()
                    .map(|t| t.parse::<i32>().unwrap())
                    .filter(|&x| x != 0)
                    .collect();
                if is_delete {
                    if let Some(pos) = db
                        .iter()
                        .position(|c| c.len() == cl.len() && cl.iter().all(|l| c.contains(l)))
                    {
                        db.swap_remove(pos);
                    }
                    continue;
                }
                // Unit-propagate the negation of cl over db; must conflict.
                let mut units: Vec<i32> = cl.iter().map(|&l| -l).collect();
                let mut conflict = false;
                'up: loop {
                    let mut progress = false;
                    for c in &db {
                        let mut unassigned: Option<i32> = None;
                        let mut n_unassigned = 0;
                        let mut satisfied = false;
                        for &l in c {
                            if units.contains(&l) {
                                satisfied = true;
                                break;
                            }
                            if !units.contains(&-l) {
                                n_unassigned += 1;
                                unassigned = Some(l);
                            }
                        }
                        if satisfied {
                            continue;
                        }
                        if n_unassigned == 0 {
                            conflict = true;
                            break 'up;
                        }
                        if n_unassigned == 1 {
                            let u = unassigned.unwrap();
                            if !units.contains(&u) {
                                units.push(u);
                                progress = true;
                            }
                        }
                    }
                    if !progress {
                        break;
                    }
                }
                assert!(
                    conflict,
                    "round {round}: learnt clause {cl:?} is not RUP (proof unsound)"
                );
                db.push(cl);
                checked += 1;
            }
            if res == lbool::FALSE {
                assert!(
                    checked > 0,
                    "unsat without any proof steps in round {round}"
                );
            }
        }
    }

    /// CNF preprocessing (subsumption + BVE) must not change any answer, and
    /// every `sat` answer must come with a model over *all* variables — the
    /// eliminated ones included, reconstructed from the elimination stack.
    ///
    /// The schedule deliberately hits the awkward paths: the first solve (which
    /// triggers preprocessing) happens with only part of the formula present,
    /// so the clauses that arrive afterwards mention eliminated variables and
    /// force restores, and assumptions are drawn from the whole variable range.
    #[test]
    fn prepro_preserves_answers_and_models() {
        let mut seed = 0x5eed_1234u64;
        let mut rng = move || {
            seed ^= seed << 13;
            seed ^= seed >> 7;
            seed ^= seed << 17;
            seed
        };
        let mut total_elim = 0usize;
        for round in 0..600 {
            let nv = 6 + (rng() % 40) as usize;
            let density = 1.5 + (rng() % 45) as f64 / 10.0;
            let nc = (nv as f64 * density) as usize;
            // (var, sign) pairs, packed as var*2+sign.
            let mut clauses: Vec<Vec<usize>> = Vec::new();
            for _ in 0..nc {
                let len = 1 + (rng() % 4) as usize;
                let mut cl: Vec<usize> = Vec::new();
                for _ in 0..len {
                    let x = (rng() % nv as u64) as usize * 2 + (rng() % 2) as usize;
                    if !cl.contains(&x) {
                        cl.push(x);
                    }
                }
                clauses.push(cl);
            }
            let mut plain = Solver::new();
            plain.disable_prepro();
            let mut pre = Solver::new();
            // This test is about BVE: the lucky phases would answer many of
            // these small formulas before preprocessing ever ran.
            plain.disable_lucky();
            pre.disable_lucky();
            // Cover both entry points: before the first decision (0) and the
            // deferred mid-search one, which flushes learnt clauses and
            // rebuilds the watch lists under an already-running search.
            pre.set_prepro_at([0, 1, 4, 25][round % 4]);
            let vp = nvars(&mut plain, nv);
            let vq = nvars(&mut pre, nv);
            let lits = |cl: &[usize], vs: &[Var]| -> Vec<Lit> {
                cl.iter()
                    .map(|&x| Lit::new(vs[x / 2], x % 2 == 0))
                    .collect()
            };
            // Three batches, a query after each.
            for batch in 0..3 {
                let lo = clauses.len() * batch / 3;
                let hi = clauses.len() * (batch + 1) / 3;
                for cl in &clauses[lo..hi] {
                    plain.add_clause(&lits(cl, &vp));
                    pre.add_clause(&lits(cl, &vq));
                }
                let mut assumps: Vec<usize> = Vec::new();
                for _ in 0..(rng() % 3) {
                    let x = (rng() % nv as u64) as usize * 2 + (rng() % 2) as usize;
                    if !assumps.contains(&x) && !assumps.contains(&(x ^ 1)) {
                        assumps.push(x);
                    }
                }
                let r1 = plain.solve(&lits(&assumps, &vp));
                let r2 = pre.solve(&lits(&assumps, &vq));
                assert_eq!(r1, r2, "round {round} batch {batch}: answers differ");
                if r2 == lbool::TRUE {
                    // Full model over every clause seen so far, including the
                    // variables that were eliminated.
                    for cl in &clauses[..hi] {
                        let ls = lits(cl, &vq);
                        assert!(
                            ls.iter().any(|&l| pre.value_lit(l) == lbool::TRUE),
                            "round {round} batch {batch}: model violates clause {cl:?}"
                        );
                    }
                    for &a in &lits(&assumps, &vq) {
                        assert_eq!(
                            pre.value_lit(a),
                            lbool::TRUE,
                            "round {round} batch {batch}: assumption not honored"
                        );
                    }
                    for v in &vq {
                        assert_ne!(
                            pre.value_lit(Lit::new(*v, true)),
                            lbool::UNDEF,
                            "round {round}: variable left unassigned in the model"
                        );
                    }
                }
            }
            total_elim += pre.prepro_vars_elim as usize;
        }
        // Guard against the test silently exercising nothing.
        assert!(
            total_elim > 500,
            "BVE eliminated almost nothing: {total_elim}"
        );
    }

    /// Equivalent-literal substitution: formulas with planted equivalences must
    /// get the same answer as an unpreprocessed solver, and every `sat` answer
    /// must still carry a model over *every* variable, merged ones included.
    ///
    /// The random clauses in `prepro_preserves_answers_and_models` almost never
    /// close a cycle in the binary implication graph, so substitution needs its
    /// own generator: chains and cycles of `x <-> y` are planted explicitly, at
    /// a mix of polarities, and sometimes closed into a contradiction.
    #[test]
    fn els_preserves_answers_and_models() {
        let mut seed = 0x1234_5678u64;
        let mut rng = move || {
            seed ^= seed << 13;
            seed ^= seed >> 7;
            seed ^= seed << 17;
            seed
        };
        let mut merged_any = 0usize;
        for round in 0..500 {
            let nv = 8 + (rng() % 24) as usize;
            let mut clauses: Vec<Vec<i32>> = Vec::new();
            // Planted equivalences: x <-> (+/-)y as the two binary clauses.
            let n_eq = 2 + (rng() % (nv as u64 / 2)) as usize;
            for _ in 0..n_eq {
                let a = 1 + (rng() % nv as u64) as i32;
                let b = 1 + (rng() % nv as u64) as i32;
                if a == b {
                    continue;
                }
                let b = if rng() % 2 == 0 { b } else { -b };
                clauses.push(vec![-a, b]);
                clauses.push(vec![a, -b]);
            }
            // Ordinary clauses over the same variables.
            for _ in 0..(nv * 2) {
                let len = 1 + (rng() % 4) as usize;
                let mut cl: Vec<i32> = Vec::new();
                for _ in 0..len {
                    let v = 1 + (rng() % nv as u64) as i32;
                    let l = if rng() % 2 == 0 { v } else { -v };
                    if !cl.contains(&l) && !cl.contains(&-l) {
                        cl.push(l);
                    }
                }
                if !cl.is_empty() {
                    clauses.push(cl);
                }
            }
            let mut plain = Solver::new();
            plain.disable_prepro();
            let mut pre = Solver::new();
            pre.set_prepro_at([0, 1, 3][round % 3]);
            let vp = nvars(&mut plain, nv);
            let vq = nvars(&mut pre, nv);
            let lits =
                |cl: &[i32], vs: &[Var]| -> Vec<Lit> { cl.iter().map(|&x| lit(vs, x)).collect() };
            // Two batches, so the second one arrives after substitution has
            // already merged variables it mentions (exercising `restore_var`).
            for batch in 0..2 {
                let lo = clauses.len() * batch / 2;
                let hi = clauses.len() * (batch + 1) / 2;
                for cl in &clauses[lo..hi] {
                    plain.add_clause(&lits(cl, &vp));
                    pre.add_clause(&lits(cl, &vq));
                }
                let mut assumps: Vec<i32> = Vec::new();
                for _ in 0..(rng() % 3) {
                    let v = 1 + (rng() % nv as u64) as i32;
                    let l = if rng() % 2 == 0 { v } else { -v };
                    if !assumps.contains(&l) && !assumps.contains(&-l) {
                        assumps.push(l);
                    }
                }
                let r1 = plain.solve(&lits(&assumps, &vp));
                let r2 = pre.solve(&lits(&assumps, &vq));
                assert_eq!(r1, r2, "round {round} batch {batch}: answers differ");
                if r2 == lbool::TRUE {
                    for cl in &clauses[..hi] {
                        let ls = lits(cl, &vq);
                        assert!(
                            ls.iter().any(|&l| pre.value_lit(l) == lbool::TRUE),
                            "round {round} batch {batch}: model violates {cl:?}"
                        );
                    }
                    for &a in &lits(&assumps, &vq) {
                        assert_eq!(
                            pre.value_lit(a),
                            lbool::TRUE,
                            "round {round} batch {batch}: assumption not honored"
                        );
                    }
                    for &v in &vq {
                        assert_ne!(
                            pre.value_lit(Lit::new(v, true)),
                            lbool::UNDEF,
                            "round {round} batch {batch}: variable left unassigned"
                        );
                    }
                }
            }
            merged_any += pre.prepro_vars_merged as usize;
        }
        // Guard against the test silently exercising nothing.
        assert!(merged_any > 200, "nothing was merged: {merged_any}");
    }

    /// Repeated preprocessing passes over a database the search has already
    /// changed must not change any answer or any model.
    ///
    /// This is the risky half of inprocessing: each pass flushes the learnt
    /// clauses (promoting the binary ones to problem clauses), rebuilds every
    /// watch list, and eliminates over a clause set that earlier passes already
    /// rewrote. The interval is set to a handful of conflicts so small random
    /// instances actually reach the second, third and fourth pass.
    #[test]
    fn inprocessing_rounds_preserve_answers_and_models() {
        let mut seed = 0xfeed_face_u64;
        let mut rng = move || {
            seed ^= seed << 13;
            seed ^= seed >> 7;
            seed ^= seed << 17;
            seed
        };
        let mut rounds_seen = 0usize;
        for round in 0..400 {
            let nv = 10 + (rng() % 30) as usize;
            let mut clauses: Vec<Vec<i32>> = Vec::new();
            for _ in 0..(nv as u64 / 3) {
                let a = 1 + (rng() % nv as u64) as i32;
                let b = 1 + (rng() % nv as u64) as i32;
                if a != b {
                    let b = if rng() % 2 == 0 { b } else { -b };
                    clauses.push(vec![-a, b]);
                    clauses.push(vec![a, -b]);
                }
            }
            // Around the 3-SAT phase transition, so the search actually burns
            // conflicts and the later passes are reached.
            for _ in 0..(nv * 9 / 2) {
                let len = 3;
                let mut cl: Vec<i32> = Vec::new();
                for _ in 0..len {
                    let v = 1 + (rng() % nv as u64) as i32;
                    let l = if rng() % 2 == 0 { v } else { -v };
                    if !cl.contains(&l) && !cl.contains(&-l) {
                        cl.push(l);
                    }
                }
                if cl.len() >= 2 {
                    clauses.push(cl);
                }
            }
            let mut plain = Solver::new();
            plain.disable_prepro();
            let mut pre = Solver::new();
            pre.set_prepro_at(0);
            pre.set_inprocess(4, 1);
            let vp = nvars(&mut plain, nv);
            let vq = nvars(&mut pre, nv);
            let lits =
                |cl: &[i32], vs: &[Var]| -> Vec<Lit> { cl.iter().map(|&x| lit(vs, x)).collect() };
            for batch in 0..3 {
                let lo = clauses.len() * batch / 3;
                let hi = clauses.len() * (batch + 1) / 3;
                for cl in &clauses[lo..hi] {
                    plain.add_clause(&lits(cl, &vp));
                    pre.add_clause(&lits(cl, &vq));
                }
                let mut assumps: Vec<i32> = Vec::new();
                for _ in 0..(rng() % 3) {
                    let v = 1 + (rng() % nv as u64) as i32;
                    let l = if rng() % 2 == 0 { v } else { -v };
                    if !assumps.contains(&l) && !assumps.contains(&-l) {
                        assumps.push(l);
                    }
                }
                let r1 = plain.solve(&lits(&assumps, &vp));
                let r2 = pre.solve(&lits(&assumps, &vq));
                assert_eq!(r1, r2, "round {round} batch {batch}: answers differ");
                if r2 == lbool::TRUE {
                    for cl in &clauses[..hi] {
                        let ls = lits(cl, &vq);
                        assert!(
                            ls.iter().any(|&l| pre.value_lit(l) == lbool::TRUE),
                            "round {round} batch {batch}: model violates {cl:?}"
                        );
                    }
                    for &a in &lits(&assumps, &vq) {
                        assert_eq!(
                            pre.value_lit(a),
                            lbool::TRUE,
                            "round {round} batch {batch}: assumption not honored"
                        );
                    }
                }
            }
            rounds_seen += pre.prepro_passes() as usize;
        }
        // Guard against the test silently exercising a single pass. The bound
        // is deliberately loose: lucky phases answer some of these formulas
        // before search starts, so the round count legitimately varies with
        // unrelated heuristics. It exists to catch "inprocessing never ran",
        // not to pin an exact number.
        assert!(rounds_seen > 400, "inprocessing barely ran: {rounds_seen}");
    }

    /// A frozen variable is never eliminated, and freezing one that already was
    /// puts it (and its clauses) back.
    #[test]
    fn frozen_vars_are_never_eliminated() {
        for freeze_first in [true, false] {
            let mut s = Solver::new();
            s.set_prepro_at(0);
            let vs = nvars(&mut s, 8);
            let l = |i: i32| lit(&vs, i);
            if freeze_first {
                s.freeze(vs[2]);
            }
            for i in 1..8 {
                s.add_clause(&[l(-i), l(i + 1)]);
                s.add_clause(&[l(i), l(-(i + 1))]);
            }
            assert_eq!(s.solve(&[l(1)]), lbool::TRUE);
            assert_eq!(s.value_lit(l(3)), lbool::TRUE);
            if freeze_first {
                assert!(s.prepro_vars_elim > 0, "nothing was eliminated at all");
            } else {
                // Freezing after the fact restores the variable.
                s.freeze(vs[2]);
            }
            // Either way variable 3 is usable in a later clause.
            s.add_clause(&[l(-3)]);
            assert_eq!(s.solve(&[l(1)]), lbool::FALSE);
            assert_eq!(s.solve(&[]), lbool::TRUE);
            assert_eq!(s.value_lit(l(1)), lbool::FALSE);
        }
    }

    /// A forked solver must inherit the elimination stack: the clone has to be
    /// able to reconstruct models and to restore variables on its own.
    #[test]
    fn prepro_survives_fork() {
        let mut s = Solver::new();
        s.set_prepro_at(0);
        let vs = nvars(&mut s, 12);
        let l = |i: i32| lit(&vs, i);
        // A chain of definitions, so most variables are eliminable.
        for i in 1..11 {
            s.add_clause(&[l(-i), l(i + 1)]);
            s.add_clause(&[l(i), l(-(i + 1)), l(12)]);
        }
        assert_eq!(s.solve(&[l(1)]), lbool::TRUE);
        let mut f = s.clone();
        // Both solvers must answer identically and both must produce models.
        assert_eq!(f.solve(&[l(1), l(-12)]), s.solve(&[l(1), l(-12)]));
        assert_eq!(f.solve(&[l(11)]), lbool::TRUE);
        for v in &vs {
            assert_ne!(f.value_lit(Lit::new(*v, true)), lbool::UNDEF);
        }
        // A clause added to the fork must not affect the parent.
        f.add_clause(&[l(-11)]);
        assert_eq!(f.solve(&[l(11)]), lbool::FALSE);
        assert_eq!(s.solve(&[l(11)]), lbool::TRUE);
    }

    /// Every branching heuristic must return the same answer on the same
    /// formula, and every model it reports must satisfy every clause. The
    /// decision order is the only thing that differs.
    #[test]
    fn decision_modes_agree_on_random_3sat() {
        let mut seed = 0x9e3779b9u64;
        let mut rng = move || {
            seed ^= seed << 13;
            seed ^= seed >> 7;
            seed ^= seed << 17;
            seed
        };
        let modes = [
            DecisionMode::Vsids,
            DecisionMode::Vmtf,
            DecisionMode::Alt,
            DecisionMode::Chb,
        ];
        for round in 0..120 {
            let nv = 20 + (rng() % 30) as usize;
            let nc = (nv as f64 * 4.3) as usize;
            let mut clauses: Vec<Vec<i32>> = Vec::new();
            for _ in 0..nc {
                let mut cl: Vec<i32> = Vec::new();
                while cl.len() < 3 {
                    let v = (rng() % nv as u64) as i32 + 1;
                    let l = if rng() % 2 == 0 { v } else { -v };
                    if !cl.contains(&l) && !cl.contains(&-l) {
                        cl.push(l);
                    }
                }
                clauses.push(cl);
            }
            let mut answer: Option<lbool> = None;
            for mode in modes {
                let mut s = Solver::new();
                s.set_decision_mode(mode);
                let vs = nvars(&mut s, nv);
                for cl in &clauses {
                    let c: Vec<Lit> = cl.iter().map(|&i| lit(&vs, i)).collect();
                    s.add_clause(&c);
                }
                let r = s.solve(&[]);
                if r == lbool::TRUE {
                    for cl in &clauses {
                        assert!(
                            cl.iter().any(|&i| s.value_lit(lit(&vs, i)) == lbool::TRUE),
                            "{mode:?} model violates a clause in round {round}"
                        );
                    }
                }
                match answer {
                    None => answer = Some(r),
                    Some(a) => assert_eq!(a, r, "{mode:?} disagrees in round {round}"),
                }
            }
        }
    }

    /// Deterministic random 3-SAT near the phase transition: check models on
    /// sat instances (internal consistency; cross-solver differential lives
    /// in smtrs-sat).
    #[test]
    fn random_3sat_models_valid() {
        let mut seed = 0x12345678u64;
        let mut rng = move || {
            seed ^= seed << 13;
            seed ^= seed >> 7;
            seed ^= seed << 17;
            seed
        };
        for round in 0..200 {
            let nv = 20 + (rng() % 30) as usize;
            let nc = (nv as f64 * 4.1) as usize;
            let mut s = Solver::new();
            let vs = nvars(&mut s, nv);
            let mut clauses = Vec::new();
            for _ in 0..nc {
                let mut cl = Vec::new();
                while cl.len() < 3 {
                    let v = (rng() % nv as u64) as usize;
                    let pos = rng() % 2 == 0;
                    let l = Lit::new(vs[v], pos);
                    if !cl.contains(&l) && !cl.contains(&!l) {
                        cl.push(l);
                    }
                }
                clauses.push(cl.clone());
                s.add_clause(&cl);
            }
            if s.solve(&[]) == lbool::TRUE {
                for cl in &clauses {
                    assert!(
                        cl.iter().any(|&l| s.value_lit(l) == lbool::TRUE),
                        "model violates clause in round {round}"
                    );
                }
            }
        }
    }

    /// The lucky phases must answer without search on the shapes they exist
    /// for, and must stay out of the way otherwise.
    #[test]
    fn lucky_phases_answer_the_uniform_shapes() {
        // Every clause has a negative literal: the all-false walk wins.
        let mut s = Solver::new();
        let vs = nvars(&mut s, 6);
        for i in 0..5 {
            s.add_clause(&[lit(&vs, -(i + 1)), lit(&vs, i + 2)]);
        }
        assert_eq!(s.solve(&[]), lbool::TRUE);
        assert_eq!(s.lucky_hit, 1, "forward-false should have answered");
        assert_eq!(s.conflicts, 0);
        assert_eq!(s.decisions, 0);

        // A unit forcing var 1 true does *not* defeat the all-false walk: the
        // discrepancy repair flips a decision whose propagation conflicts, so
        // the walk still lands on the chain's forced model. This is what makes
        // the pass fire as often as it does, and it is worth pinning.
        let mut s = Solver::new();
        let vs = nvars(&mut s, 6);
        for i in 0..5 {
            s.add_clause(&[lit(&vs, -(i + 1)), lit(&vs, i + 2)]);
        }
        s.add_clause(&[lit(&vs, 1)]);
        assert_eq!(s.solve(&[]), lbool::TRUE);
        assert_eq!(s.lucky_hit, 1);
        assert_eq!(s.conflicts, 0);
        for i in 1..=6 {
            assert_eq!(s.value_lit(lit(&vs, i)), lbool::TRUE);
        }

        // Nothing lucky about an unsatisfiable formula: all four passes fail,
        // the search runs, and the answer is unaffected.
        let (mut s, _) = pigeonhole(4);
        assert_eq!(s.solve(&[]), lbool::FALSE);
        assert_eq!(s.lucky_hit, 0);
    }

    /// Branching and lucky phases were written independently and merged; this
    /// pins the *product*, which neither sibling test covers.
    /// `decision_modes_agree_on_random_3sat` varies the brancher on a single
    /// one-shot solve, and `lucky_preserves_answers_and_models` varies lucky
    /// only in the default mode. The coupling between them is not in either
    /// feature but in `backtrack`, which is the sole place that restores the
    /// VMTF search cursor after lucky's decide/undo walk — and which keys that
    /// repair off `decision_mode`, not off `vmtf_active`, so it must stay live
    /// in `Alt`'s VSIDS half and during a lucky pass in any mode. A cursor left
    /// below an unassigned variable makes `vmtf_next_decision` report "no
    /// variable left to decide", which the search reads as a *model*: the
    /// failure mode is a wrong `sat`, not a crash, so the models are checked
    /// here and not just the answers.
    ///
    /// Every configuration runs the same three-query incremental session
    /// (solve, solve-under-assumptions, add-a-clause-and-solve) so that lucky
    /// is exercised both before and after a BVE pass, and so that its
    /// deep-trail success path is followed by an `add_clause`.
    #[test]
    fn branching_and_lucky_compose() {
        let mut seed = 0xdead_beef_1234_5678u64;
        let mut rng = move || {
            seed ^= seed << 13;
            seed ^= seed >> 7;
            seed ^= seed << 17;
            seed
        };
        // (mode, lucky, prepro-at-conflicts or None for "no preprocessing")
        let cfgs: [(DecisionMode, bool, Option<u64>); 10] = [
            (DecisionMode::Vsids, false, None),
            (DecisionMode::Vsids, true, Some(0)),
            (DecisionMode::Vmtf, false, None),
            (DecisionMode::Vmtf, true, None),
            (DecisionMode::Vmtf, true, Some(0)),
            (DecisionMode::Vmtf, true, Some(5)),
            (DecisionMode::Alt, false, None),
            (DecisionMode::Alt, true, Some(0)),
            (DecisionMode::Chb, false, None),
            (DecisionMode::Chb, true, Some(0)),
        ];
        for round in 0..1500usize {
            let nv = 3 + (rng() % 26) as usize;
            // Low density keeps the uniform-polarity walks succeeding often,
            // which is what exercises lucky's accepting path.
            let density = 0.5 + (rng() % 45) as f64 / 10.0;
            let nc = (nv as f64 * density) as usize;
            let mut clauses: Vec<Vec<i32>> = Vec::new();
            for _ in 0..nc {
                let len = 1 + (rng() % 3) as usize;
                let mut cl: Vec<i32> = Vec::new();
                for _ in 0..len {
                    let v = (rng() % nv as u64) as i32 + 1;
                    let l = if rng() % 2 == 0 { v } else { -v };
                    if !cl.contains(&l) && !cl.contains(&-l) {
                        cl.push(l);
                    }
                }
                clauses.push(cl);
            }
            let na = (rng() % 3) as usize;
            let asm: Vec<i32> = (0..na)
                .map(|_| {
                    let v = (rng() % nv as u64) as i32 + 1;
                    if rng() % 2 == 0 {
                        v
                    } else {
                        -v
                    }
                })
                .collect();
            let extra: Vec<i32> = (0..2)
                .map(|_| {
                    let v = (rng() % nv as u64) as i32 + 1;
                    if rng() % 2 == 0 {
                        v
                    } else {
                        -v
                    }
                })
                .collect();

            let mut expect: Option<(lbool, lbool, lbool)> = None;
            for &(mode, lucky, prepro_at) in &cfgs {
                let what = format!("{mode:?}/lucky={lucky}/prepro={prepro_at:?}");
                let mut s = Solver::new();
                s.set_decision_mode(mode);
                if !lucky {
                    s.disable_lucky();
                }
                match prepro_at {
                    None => s.disable_prepro(),
                    Some(c) => s.set_prepro_at(c),
                }
                let vs = nvars(&mut s, nv);
                for cl in &clauses {
                    let l: Vec<Lit> = cl.iter().map(|&i| lit(&vs, i)).collect();
                    s.add_clause(&l);
                }
                // A model must satisfy every clause *and* leave no variable
                // unassigned — a stale VMTF cursor shows up as the latter.
                let check = |s: &Solver, cls: &[Vec<i32>]| {
                    for cl in cls {
                        assert!(
                            cl.iter().any(|&i| s.value_lit(lit(&vs, i)) == lbool::TRUE),
                            "{what} round {round}: model violates {cl:?}"
                        );
                    }
                    for v in &vs {
                        assert_ne!(
                            s.value_lit(Lit::new(*v, true)),
                            lbool::UNDEF,
                            "{what} round {round}: variable unassigned in a reported model"
                        );
                    }
                };

                let r0 = s.solve(&[]);
                if r0 == lbool::TRUE {
                    check(&s, &clauses);
                }
                // Assumptions skip lucky, but must see its root units.
                let alits: Vec<Lit> = asm.iter().map(|&i| lit(&vs, i)).collect();
                let r1 = s.solve(&alits);
                if r1 == lbool::TRUE {
                    check(&s, &clauses);
                    for a in &alits {
                        assert_eq!(
                            s.value_lit(*a),
                            lbool::TRUE,
                            "{what} round {round}: assumption unsatisfied in a model"
                        );
                    }
                }
                // `add_clause` after a lucky success must cope with a trail
                // sitting at one decision level per variable.
                let elits: Vec<Lit> = extra.iter().map(|&i| lit(&vs, i)).collect();
                s.add_clause(&elits);
                let r2 = s.solve(&[]);
                if r2 == lbool::TRUE {
                    let mut all = clauses.clone();
                    all.push(extra.clone());
                    check(&s, &all);
                }
                match expect {
                    None => expect = Some((r0, r1, r2)),
                    Some(e) => assert_eq!(
                        e,
                        (r0, r1, r2),
                        "{what} disagrees in round {round}: \
                         nv={nv} clauses={clauses:?} asm={asm:?} extra={extra:?}"
                    ),
                }
            }
        }
    }

    /// Random formulas: the lucky phases may only change *how* an answer is
    /// reached, never what it is, and a model they produce must satisfy every
    /// clause. Assumption queries must be unaffected — lucky is skipped there,
    /// but its root units survive into the search that follows.
    #[test]
    fn lucky_preserves_answers_and_models() {
        let mut seed = 0x1_c0de_9e37_79b9u64;
        let mut rng = move || {
            seed ^= seed << 13;
            seed ^= seed >> 7;
            seed ^= seed << 17;
            seed
        };
        let mut lucky_answers = 0usize;
        for round in 0..600 {
            let nv = 4 + (rng() % 24) as usize;
            // Low density and short clauses make uniform-polarity walks
            // succeed often enough to exercise the accepting path.
            let density = 0.5 + (rng() % 40) as f64 / 10.0;
            let nc = (nv as f64 * density) as usize;
            let mut clauses: Vec<Vec<usize>> = Vec::new();
            for _ in 0..nc {
                let len = 1 + (rng() % 3) as usize;
                let mut cl: Vec<usize> = Vec::new();
                for _ in 0..len {
                    let x = (rng() % nv as u64) as usize * 2 + (rng() % 2) as usize;
                    if !cl.contains(&x) {
                        cl.push(x);
                    }
                }
                clauses.push(cl);
            }
            let mut plain = Solver::new();
            plain.disable_lucky();
            let mut lucky = Solver::new();
            let vp = nvars(&mut plain, nv);
            let vq = nvars(&mut lucky, nv);
            let lits = |cl: &[usize], vs: &[Var]| -> Vec<Lit> {
                cl.iter()
                    .map(|&x| Lit::new(vs[x / 2], x % 2 == 0))
                    .collect()
            };
            for cl in &clauses {
                plain.add_clause(&lits(cl, &vp));
                lucky.add_clause(&lits(cl, &vq));
            }
            let r1 = plain.solve(&[]);
            let r2 = lucky.solve(&[]);
            assert_eq!(r1, r2, "round {round}: lucky changed the answer");
            if lucky.lucky_hit > 0 {
                lucky_answers += 1;
            }
            if r2 == lbool::TRUE {
                for cl in &clauses {
                    assert!(
                        lits(cl, &vq)
                            .iter()
                            .any(|&l| lucky.value_lit(l) == lbool::TRUE),
                        "round {round}: model violates clause {cl:?}"
                    );
                }
            }
            // A follow-up assumption query skips lucky but must still agree.
            let x = (rng() % nv as u64) as usize * 2 + (rng() % 2) as usize;
            let a = [x];
            assert_eq!(
                plain.solve(&lits(&a, &vp)),
                lucky.solve(&lits(&a, &vq)),
                "round {round}: lucky changed an assumption answer"
            );
        }
        assert!(
            lucky_answers > 50,
            "only {lucky_answers} rounds exercised the accepting path"
        );
    }

    // ---------- carrying the trail from one `solve` to the next ----------

    /// The differential that governs [`Solver::disable_solve_reuse`]: a solver
    /// that carries its trail across `solve` calls must answer a *sequence* of
    /// incremental queries exactly as one that tears the trail down every
    /// time, and every model it reports must really satisfy the clauses.
    ///
    /// The sequence is what matters. A single query cannot exercise reuse at
    /// all (there is no previous trail), so the generator interleaves the
    /// three things that decide whether the retained state is still valid:
    /// repeating an assumption set, extending it by one literal the way
    /// `minimize` does, and adding a clause — which must invalidate the
    /// retained model whether or not it also backtracks.
    #[test]
    fn carrying_the_trail_never_changes_an_answer() {
        let mut seed = 0x7a11_c0deu64;
        let mut rng = move || {
            seed ^= seed << 13;
            seed ^= seed >> 7;
            seed ^= seed << 17;
            seed
        };
        let (mut sats, mut unsats, mut model_hits, mut level_hits) = (0u64, 0u64, 0u64, 0u64);
        for round in 0..400 {
            let nv = 6 + (rng() % 24) as usize;
            // Under-constrained on purpose: reuse only ever fires on a SAT
            // answer, so the interesting formulas are the satisfiable ones.
            let density = 1.0 + (rng() % 25) as f64 / 10.0;
            let nc = (nv as f64 * density) as usize;
            let mut clauses: Vec<Vec<usize>> = Vec::new();
            for _ in 0..nc {
                let len = 1 + (rng() % 4) as usize;
                let mut cl: Vec<usize> = Vec::new();
                for _ in 0..len {
                    let x = (rng() % nv as u64) as usize * 2 + (rng() % 2) as usize;
                    if !cl.contains(&x) {
                        cl.push(x);
                    }
                }
                clauses.push(cl);
            }
            let lits = |cl: &[usize], vs: &[Var]| -> Vec<Lit> {
                cl.iter()
                    .map(|&x| Lit::new(vs[x / 2], x % 2 == 0))
                    .collect()
            };
            // Two solvers over the same input, differing only in reuse. Both
            // see the same preprocessing entry point so that BVE and
            // equivalent-literal substitution run underneath reuse too: an
            // assumption over an eliminated variable is answered off the
            // reconstructed model by the fast path and by `restore_lits`
            // otherwise, and those two had better agree.
            let mut reuse = Solver::new();
            let mut plain = Solver::new();
            plain.disable_solve_reuse();
            // Rotate the two halves independently: with both on, the fast path
            // intercepts most of the repeats and the carried-level code would
            // barely run.
            let (m, l) = [(true, true), (true, false), (false, true)][round % 3];
            reuse.set_solve_reuse(m, l);
            for s in [&mut reuse, &mut plain] {
                s.set_prepro_at([0, 1, 9][round % 3]);
            }
            let vr = nvars(&mut reuse, nv);
            let vp = nvars(&mut plain, nv);
            for cl in &clauses {
                reuse.add_clause(&lits(cl, &vr));
                plain.add_clause(&lits(cl, &vp));
            }

            let mut assumps: Vec<usize> = Vec::new();
            for step in 0..12 {
                match rng() % 5 {
                    // Repeat the current set verbatim — the shape a repeated
                    // `check-sat-assuming` produces.
                    0 => {}
                    // Extend by one literal: the `minimize` bit-fixing shape.
                    1 | 2 => assumps.push((rng() % nv as u64) as usize * 2 + (rng() % 2) as usize),
                    // Drop back down.
                    3 => {
                        assumps.pop();
                    }
                    // Add a clause. `eval_n`'s blocking clauses are this, and
                    // a retained model that survived one would be a wrong
                    // `sat` — or, in `eval_n`, an infinite loop.
                    _ => {
                        let len = 1 + (rng() % 3) as usize;
                        let mut cl: Vec<usize> = Vec::new();
                        for _ in 0..len {
                            let x = (rng() % nv as u64) as usize * 2 + (rng() % 2) as usize;
                            if !cl.contains(&x) {
                                cl.push(x);
                            }
                        }
                        reuse.add_clause(&lits(&cl, &vr));
                        plain.add_clause(&lits(&cl, &vp));
                        clauses.push(cl);
                    }
                }
                let ar = lits(&assumps, &vr);
                let ap = lits(&assumps, &vp);
                let got = reuse.solve(&ar);
                let want = plain.solve(&ap);
                assert_eq!(
                    got, want,
                    "round {round} step {step}: reuse changed the answer under {assumps:?}"
                );
                match got {
                    lbool::TRUE => {
                        sats += 1;
                        // TRUE claims a *complete* assignment, and the fast
                        // path claims the retained one still is. Nothing else
                        // here is sensitive to a variable quietly going
                        // unassigned — a clause check only notices when the
                        // missing literal was the clause's only true one.
                        for &v in &vr {
                            assert_ne!(
                                reuse.value_lit(Lit::new(v, true)),
                                lbool::UNDEF,
                                "round {round} step {step}: sat with {v:?} unassigned"
                            );
                        }
                        for cl in &clauses {
                            assert!(
                                lits(cl, &vr)
                                    .iter()
                                    .any(|&l| reuse.value_lit(l) == lbool::TRUE),
                                "round {round} step {step}: reported model violates {cl:?}"
                            );
                        }
                        for &a in &ar {
                            assert_eq!(
                                reuse.value_lit(a),
                                lbool::TRUE,
                                "round {round} step {step}: reported model violates an assumption"
                            );
                        }
                    }
                    lbool::FALSE => {
                        unsats += 1;
                        // `analyze_final` reads the failed set off the
                        // decisions on the trail, and carried levels are
                        // decisions this call did not make. If one of them
                        // were not an assumption it would land here.
                        for f in reuse.failed_assumptions() {
                            assert!(
                                ar.contains(f),
                                "round {round} step {step}: {f:?} was never assumed"
                            );
                        }
                    }
                    _ => {}
                }
            }
            let (m, l) = reuse.reuse_counts();
            model_hits += m;
            level_hits += l;
            let (m0, l0) = plain.reuse_counts();
            assert_eq!((m0, l0), (0, 0), "the disabled side reused something");
        }
        // Guard against the test passing because nothing was ever reused.
        assert!(sats > 500, "only {sats} sat answers");
        assert!(unsats > 100, "only {unsats} unsat answers");
        assert!(
            model_hits > 200,
            "only {model_hits} solves came off the model"
        );
        assert!(level_hits > 200, "only {level_hits} levels were carried");
    }

    /// A model must not survive a clause it does not satisfy — the exact
    /// failure that would turn `eval_n`'s enumeration into an infinite loop
    /// handing back the same value forever.
    #[test]
    fn a_blocking_clause_retires_the_retained_model() {
        let mut s = Solver::new();
        s.disable_lucky();
        let vs = nvars(&mut s, 3);
        let l = |i: i32| lit(&vs, i);
        s.add_clause(&[l(1), l(2), l(3)]);
        let mut seen: Vec<(bool, bool, bool)> = Vec::new();
        for _ in 0..8 {
            if s.solve(&[]) != lbool::TRUE {
                break;
            }
            let v = (
                s.value_lit(l(1)) == lbool::TRUE,
                s.value_lit(l(2)) == lbool::TRUE,
                s.value_lit(l(3)) == lbool::TRUE,
            );
            assert!(!seen.contains(&v), "the same model came back twice: {v:?}");
            seen.push(v);
            s.add_clause(&[
                l(if v.0 { -1 } else { 1 }),
                l(if v.1 { -2 } else { 2 }),
                l(if v.2 { -3 } else { 3 }),
            ]);
        }
        // Seven assignments satisfy the clause; the eighth call must refute.
        assert_eq!(seen.len(), 7, "enumerated {seen:?}");
        assert_eq!(s.solve(&[]), lbool::FALSE);
    }

    /// A fresh variable is unassigned, so the retained assignment stops being
    /// a *complete* model and must not be handed back as one.
    #[test]
    fn a_fresh_variable_retires_the_retained_model() {
        let mut s = Solver::new();
        s.disable_lucky();
        let vs = nvars(&mut s, 1);
        assert_eq!(s.solve(&[lit(&vs, 1)]), lbool::TRUE);
        let (before, _) = s.reuse_counts();
        let w = s.new_var();
        assert_eq!(s.solve(&[lit(&vs, 1)]), lbool::TRUE);
        assert_eq!(s.reuse_counts().0, before, "answered off a stale model");
        assert_ne!(s.value_lit(Lit::new(w, true)), lbool::UNDEF);
    }

    /// The whole point of the fast path: a repeat of a satisfied query costs
    /// no propagation at all.
    #[test]
    fn a_repeated_query_costs_nothing() {
        let mut s = Solver::new();
        s.disable_lucky();
        let vs = nvars(&mut s, 4);
        s.add_clause(&[lit(&vs, -1), lit(&vs, 2)]);
        s.add_clause(&[lit(&vs, -2), lit(&vs, 3)]);
        s.add_clause(&[lit(&vs, -3), lit(&vs, 4)]);
        assert_eq!(s.solve(&[lit(&vs, 1)]), lbool::TRUE);
        let props = s.propagations;
        let decs = s.decisions;
        // Same query, and a strictly weaker one: both hold in the model.
        assert_eq!(s.solve(&[lit(&vs, 1)]), lbool::TRUE);
        assert_eq!(s.solve(&[]), lbool::TRUE);
        assert_eq!(s.solve(&[lit(&vs, 4)]), lbool::TRUE);
        assert_eq!((s.propagations, s.decisions), (props, decs));
        assert_eq!(s.reuse_counts().0, 3);
        assert_eq!(s.value_lit(lit(&vs, 4)), lbool::TRUE);
    }
}
