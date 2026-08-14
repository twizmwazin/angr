//! The angr-shaped query stream: `minimize`, `maximize`, `eval_n` and
//! `check_sat` fired at one long-lived solver, over and over.
//!
//! These four run *on top of the same live engine*. `check_sat` builds it,
//! then `minimize` and `maximize` fix bits with width-many extra SAT calls and
//! `eval_n` enumerates behind a blocking-clause activation literal — all
//! without rebuilding anything. Everything the SAT engine keeps between those
//! calls (learnt clauses, activities, phases, and now the trail itself) is
//! therefore load-bearing for their answers, and nothing in the tree covered
//! them before.
//!
//! Two properties are checked, and they are chosen to fail loudly if state
//! leaks from one query into the next:
//!
//! 1. **Against an oracle.** `minimize`/`maximize` are compared with the true
//!    extremum computed by enumerating every value of a narrow bit-vector, and
//!    `eval_n` with the true value set. A stale trail handed back as a model
//!    shows up immediately as a wrong extremum.
//! 2. **Against a fresh solver.** The same query asked of a solver that has
//!    answered a hundred others must give what a solver that has answered
//!    none gives.

use smtrs_core::{BvConst, Op, Sort, TermId, TermPool, Value};
use smtrs_solver::{Answer, Solver};

/// A tiny problem over one 5-bit variable plus a couple of bystanders, small
/// enough that the oracle can enumerate the whole domain.
struct Problem {
    pool: TermPool,
    x: TermId,
    y: TermId,
    declared: Vec<smtrs_core::SymbolId>,
    assertions: Vec<TermId>,
}

const W: u32 = 5;

fn problem(build: impl Fn(&mut TermPool, TermId, TermId) -> Vec<TermId>) -> Problem {
    let mut pool = TermPool::new();
    let xs = pool.fresh_symbol("x".to_string(), Sort::BitVec(W));
    let ys = pool.fresh_symbol("y".to_string(), Sort::BitVec(W));
    let x = pool.var(xs);
    let y = pool.var(ys);
    let assertions = build(&mut pool, x, y);
    Problem {
        pool,
        x,
        y,
        declared: vec![xs, ys],
        assertions,
    }
}

fn solver_for(p: &Problem) -> Solver {
    let mut s = Solver::new();
    s.declared = p.declared.clone();
    for &a in &p.assertions {
        s.assert(a);
    }
    s
}

/// Every value of `x` for which the assertions (plus `extra`) are satisfiable,
/// found by asserting `x = k` for all 2^W values of `k` on a fresh solver.
/// Slow and obviously correct — which is the point.
fn feasible_values(p: &mut Problem, extra: &[TermId]) -> Vec<u64> {
    let mut out = Vec::new();
    for k in 0..(1u64 << W) {
        let kv = p.pool.bv(BvConst::from_u64(W, k));
        let eq = p.pool.mk(Op::Eq, &[p.x, kv]).expect("well-sorted");
        let mut s = Solver::new();
        s.declared = p.declared.clone();
        for &a in &p.assertions {
            s.assert(a);
        }
        s.assert(eq);
        let mut assuming = extra.to_vec();
        assuming.dedup();
        if s.check_sat(&mut p.pool, &assuming) == Answer::Sat {
            out.push(k);
        }
    }
    out
}

fn as_u64(v: Option<BvConst>) -> Option<u64> {
    v.and_then(|c| c.as_u64())
}

#[test]
fn minimize_and_maximize_hit_the_true_extrema() {
    // 6 <= x <= 23, and x is odd — so the extrema are 7 and 23 and neither is
    // a bound of the interval, which a bit-fixing bug that stops one step
    // early would still get right.
    let mut p = problem(|pool, x, _y| {
        let lo = pool.bv(BvConst::from_u64(W, 6));
        let hi = pool.bv(BvConst::from_u64(W, 23));
        let one = pool.bv(BvConst::from_u64(W, 1));
        let bit = pool.mk(Op::BvAnd, &[x, one]).expect("well-sorted");
        vec![
            pool.mk(Op::BvUle, &[lo, x]).expect("well-sorted"),
            pool.mk(Op::BvUle, &[x, hi]).expect("well-sorted"),
            pool.mk(Op::Eq, &[bit, one]).expect("well-sorted"),
        ]
    });
    let want = feasible_values(&mut p, &[]);
    assert_eq!(want.first().copied(), Some(7));
    assert_eq!(want.last().copied(), Some(23));

    let mut s = solver_for(&p);
    assert_eq!(s.check_sat(&mut p.pool, &[]), Answer::Sat);
    let x = p.x;
    // Twice in a row: the second call runs entirely on state the first left
    // behind, which is exactly what this file exists to check.
    for round in 0..3 {
        assert_eq!(
            as_u64(s.minimize(&mut p.pool, x, &[])),
            Some(7),
            "round {round}"
        );
        assert_eq!(
            as_u64(s.maximize(&mut p.pool, x, &[])),
            Some(23),
            "round {round}"
        );
    }
}

#[test]
fn extrema_under_an_assumption_do_not_leak_into_the_next_query() {
    let mut p = problem(|pool, x, _y| {
        let hi = pool.bv(BvConst::from_u64(W, 20));
        vec![pool.mk(Op::BvUle, &[x, hi]).expect("well-sorted")]
    });
    let x = p.x;
    let ten = p.pool.bv(BvConst::from_u64(W, 10));
    let ge10 = p.pool.mk(Op::BvUle, &[ten, x]).expect("well-sorted");
    let le3 = {
        let three = p.pool.bv(BvConst::from_u64(W, 3));
        p.pool.mk(Op::BvUle, &[x, three]).expect("well-sorted")
    };

    let mut s = solver_for(&p);
    assert_eq!(s.check_sat(&mut p.pool, &[]), Answer::Sat);
    // Unconstrained, then under an assumption, then unconstrained again. The
    // last must not remember the assumption.
    assert_eq!(as_u64(s.minimize(&mut p.pool, x, &[])), Some(0));
    assert_eq!(as_u64(s.minimize(&mut p.pool, x, &[ge10])), Some(10));
    assert_eq!(as_u64(s.maximize(&mut p.pool, x, &[le3])), Some(3));
    assert_eq!(as_u64(s.minimize(&mut p.pool, x, &[])), Some(0));
    assert_eq!(as_u64(s.maximize(&mut p.pool, x, &[])), Some(20));
    // And a plain check under the assumptions still agrees with a fresh
    // solver, which has no state at all.
    for a in [ge10, le3] {
        let mut fresh = solver_for(&p);
        assert_eq!(
            s.check_sat(&mut p.pool, &[a]),
            fresh.check_sat(&mut p.pool, &[a])
        );
    }
}

#[test]
fn eval_n_enumerates_the_value_set_exactly_once_each() {
    // x in {2, 5, 9} by construction.
    let mut p = problem(|pool, x, _y| {
        let mut disj = Vec::new();
        for k in [2u64, 5, 9] {
            let kv = pool.bv(BvConst::from_u64(W, k));
            disj.push(pool.mk(Op::Eq, &[x, kv]).expect("well-sorted"));
        }
        vec![pool.mk(Op::Or, &disj).expect("well-sorted")]
    });
    assert_eq!(feasible_values(&mut p, &[]), vec![2, 5, 9]);

    let mut s = solver_for(&p);
    let x = p.x;
    // Asking for more than exist must terminate with exactly the value set —
    // the loop's only exit is `unsat`, so a blocking clause that failed to
    // retire the previous model would spin forever or repeat a value.
    let mut got: Vec<u64> = s
        .eval_n(&mut p.pool, x, 10, &[])
        .iter()
        .filter_map(|v| v.as_u64())
        .collect();
    got.sort_unstable();
    assert_eq!(got, vec![2, 5, 9]);

    // Bounded, and then again: the activation literal of the first call is
    // retired, so the second call sees the same value set.
    let first = s.eval_n(&mut p.pool, x, 2, &[]);
    assert_eq!(first.len(), 2);
    let mut again: Vec<u64> = s
        .eval_n(&mut p.pool, x, 10, &[])
        .iter()
        .filter_map(|v| v.as_u64())
        .collect();
    again.sort_unstable();
    assert_eq!(again, vec![2, 5, 9], "a retired blocking clause survived");
}

/// The stream property, and the reason this file is here: a long-lived solver
/// answering a mixed stream must answer every query the way a solver created
/// for that one query does.
#[test]
fn a_long_mixed_stream_agrees_with_a_fresh_solver_at_every_step() {
    let mut p = problem(|pool, x, y| {
        let hi = pool.bv(BvConst::from_u64(W, 25));
        let sum = pool.mk(Op::BvAdd, &[x, y]).expect("well-sorted");
        vec![
            pool.mk(Op::BvUle, &[x, hi]).expect("well-sorted"),
            pool.mk(Op::BvUlt, &[y, x]).expect("well-sorted"),
            pool.mk(Op::BvUle, &[sum, hi]).expect("well-sorted"),
        ]
    });
    let (x, y) = (p.x, p.y);

    // A deterministic spread of assumption sets, including contradictory ones.
    let mut queries: Vec<Vec<TermId>> = vec![Vec::new()];
    for k in 0..(1u64 << W) {
        let kv = p.pool.bv(BvConst::from_u64(W, k));
        let eqx = p.pool.mk(Op::Eq, &[x, kv]).expect("well-sorted");
        let ltx = p.pool.mk(Op::BvUlt, &[x, kv]).expect("well-sorted");
        let gty = p.pool.mk(Op::BvUlt, &[kv, y]).expect("well-sorted");
        queries.push(vec![eqx]);
        queries.push(vec![ltx]);
        queries.push(vec![ltx, gty]);
    }

    let mut s = solver_for(&p);
    assert_eq!(s.check_sat(&mut p.pool, &[]), Answer::Sat);
    for (i, q) in queries.iter().enumerate() {
        let got = s.check_sat(&mut p.pool, q);
        let mut fresh = solver_for(&p);
        let want = fresh.check_sat(&mut p.pool, q);
        assert_eq!(got, want, "query {i} disagreed with a fresh solver");
        if got == Answer::Sat {
            // The model handed back has to satisfy the query, not merely the
            // assertions: a retained model that no longer fits is exactly the
            // failure the trail carries.
            let model = s.model().expect("sat gives a model").clone();
            let vals = smtrs_core::eval(&p.pool, q, &model).expect("evaluable");
            for (j, v) in vals.iter().enumerate() {
                assert_eq!(*v, Value::Bool(true), "query {i} literal {j} unsatisfied");
            }
            let asserted = smtrs_core::eval(&p.pool, &p.assertions, &model).expect("evaluable");
            for (j, v) in asserted.iter().enumerate() {
                assert_eq!(*v, Value::Bool(true), "query {i} assertion {j} unsatisfied");
            }
        }
        // Interleave the other two query kinds so their state lands in the
        // middle of the stream rather than at the end of it.
        if i % 7 == 0 {
            let lo = as_u64(s.minimize(&mut p.pool, x, q));
            let hi = as_u64(s.maximize(&mut p.pool, x, q));
            let want = feasible_values(&mut p, q);
            assert_eq!(lo, want.first().copied(), "min at query {i}");
            assert_eq!(hi, want.last().copied(), "max at query {i}");
        }
        if i % 11 == 0 {
            let mut vs: Vec<u64> = s
                .eval_n(&mut p.pool, y, 4, q)
                .iter()
                .filter_map(|v| v.as_u64())
                .collect();
            vs.sort_unstable();
            vs.dedup();
            assert_eq!(
                vs.len(),
                s.eval_n(&mut p.pool, y, 4, q).len(),
                "eval_n repeated a value at query {i}"
            );
        }
    }
}
