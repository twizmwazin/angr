//! Adversarial cover for the `PrefixScan` cache on the two shapes no SMT-LIB2
//! script can reach through the CLI: `declared` growing *between* checks (the
//! CLI assigns it once, from the whole parsed script) and `Solver::fork`,
//! which hands a copy of the cache to a second solver that then diverges from
//! its parent over a *shared* term pool.
//!
//! Oracle throughout: a solver that has seen exactly the same asserts and
//! declarations but has no history to be confused by.

use smtrs_core::{Op, Sort, SymbolId, TermPool};
use smtrs_solver::{Answer, Solver};

fn bv8(pool: &mut TermPool, name: &str) -> (SymbolId, smtrs_core::TermId) {
    let s = pool.fresh_symbol(name, Sort::BitVec(8));
    let t = pool.var(s);
    (s, t)
}

fn lt(pool: &mut TermPool, a: smtrs_core::TermId, k: u64) -> smtrs_core::TermId {
    let c = pool.bv_u64(8, k);
    pool.mk(Op::BvUlt, &[a, c]).expect("well-sorted")
}

fn model_syms(s: &Solver) -> Vec<SymbolId> {
    let mut v: Vec<SymbolId> = s.model().expect("model").keys().copied().collect();
    v.sort_unstable();
    v
}

/// A fresh solver with the same declarations and assertions, checked under the
/// same assumptions.
fn oracle(
    pool: &mut TermPool,
    declared: &[SymbolId],
    asserts: &[smtrs_core::TermId],
    assumptions: &[smtrs_core::TermId],
) -> (Answer, Option<Vec<SymbolId>>) {
    let mut s = Solver::new();
    s.declared = declared.to_vec();
    for &a in asserts {
        s.assert(a);
    }
    let ans = s.check_sat(pool, assumptions);
    let syms = (ans == Answer::Sat).then(|| model_syms(&s));
    (ans, syms)
}

/// `declared` is public and callers may grow it between checks. The cache
/// keeps its own copy of the prefix it folded in; if it failed to notice the
/// growth, the late declaration would never get a model value.
#[test]
fn declared_growing_between_checks() {
    let mut pool = TermPool::new();
    let (sa, ta) = bv8(&mut pool, "a");
    let (sb, _tb) = bv8(&mut pool, "b"); // declared late, never asserted
    let (sc, tc) = bv8(&mut pool, "c"); // declared later still, and asserted
    let si = pool.fresh_symbol("i", Sort::Int);

    let a1 = lt(&mut pool, ta, 0x40);
    let a2 = lt(&mut pool, tc, 0x10);

    let mut s = Solver::new();
    s.declared = vec![sa];
    s.assert(a1);

    // Grow `declared` and re-check at each step, always against a fresh
    // solver holding exactly the same state.
    let steps: Vec<(Vec<SymbolId>, Vec<smtrs_core::TermId>)> = vec![
        (vec![sa], vec![a1]),
        (vec![sa, sb], vec![a1]),
        (vec![sa, sb], vec![a1, a2]),
        (vec![sa, sb, sc], vec![a1, a2]),
        // An Int declaration is unsupported as a *sort*, but only reaches the
        // unsupported test if it is reachable from a root; a bare declaration
        // is not, and must stay harmless.
        (vec![sa, sb, sc, si], vec![a1, a2]),
    ];
    let mut asserted = 1usize;
    for (declared, asserts) in &steps {
        s.declared = declared.clone();
        while asserted < asserts.len() {
            s.assert(asserts[asserted]);
            asserted += 1;
        }
        let got = s.check_sat(&mut pool, &[]);
        let (want, want_syms) = oracle(&mut pool, declared, asserts, &[]);
        assert_eq!(got, want, "declared={declared:?} asserts={asserts:?}");
        if got == Answer::Sat {
            assert_eq!(
                model_syms(&s),
                want_syms.unwrap(),
                "model symbols after declared={declared:?}"
            );
            // The fresh-solver oracle runs the same code, so it cannot catch a
            // break that is in the shared path rather than in the caching. The
            // absolute statement is: every BV/Bool declaration gets a value,
            // completed to zero when nothing constrains it.
            for &d in declared {
                if matches!(pool.symbol(d).sort, Sort::Bool | Sort::BitVec(_)) {
                    assert!(
                        s.model().expect("model").contains_key(&d),
                        "declared {} has no model value (declared={declared:?})",
                        pool.symbol(d).name
                    );
                }
            }
        }
    }
}

/// `declared` may also be *replaced* rather than grown, and a replacement of
/// the same length leaves the cache's length test saying "still extends".
/// Only comparing the elements catches it. (Mutation-found: deleting that
/// comparison broke no other test.)
#[test]
fn declared_replaced_by_a_same_length_list() {
    let mut pool = TermPool::new();
    let (sa, ta) = bv8(&mut pool, "a");
    let (sc, _tc) = bv8(&mut pool, "c"); // declared, never asserted
    let (sd, _td) = bv8(&mut pool, "d"); // ditto, and swapped in for `c`
    let a1 = lt(&mut pool, ta, 0x40);

    let mut s = Solver::new();
    s.declared = vec![sa, sc];
    s.assert(a1);
    assert_eq!(s.check_sat(&mut pool, &[]), Answer::Sat);
    assert_eq!(
        model_syms(&s),
        oracle(&mut pool, &[sa, sc], &[a1], &[]).1.unwrap()
    );

    // Same length, different content: `d` must now get a value and `c` must
    // not, which is exactly what a cache that only compared lengths would
    // get backwards.
    s.declared = vec![sa, sd];
    assert_eq!(s.check_sat(&mut pool, &[]), Answer::Sat);
    let model = s.model().expect("sat");
    assert!(model.contains_key(&sd), "the new declaration has no value");
    assert!(
        !model.contains_key(&sc),
        "a declaration that was replaced still has a value"
    );
    assert_eq!(
        model_syms(&s),
        oracle(&mut pool, &[sa, sd], &[a1], &[]).1.unwrap()
    );
}

/// `fork` copies the cache. Parent and child then diverge while sharing one
/// term pool, so the child's new terms land in the pool the parent's stamp
/// array is indexed by — and neither may believe the other's facts.
#[test]
fn fork_then_diverge_over_a_shared_pool() {
    let mut pool = TermPool::new();
    let (sa, ta) = bv8(&mut pool, "a");
    let (sb, tb) = bv8(&mut pool, "b");
    let si = pool.fresh_symbol("i", Sort::Int);
    let ti = pool.var(si);
    let declared = vec![sa, sb, si];

    let a1 = lt(&mut pool, ta, 0x40);
    let child_only = lt(&mut pool, tb, 0x08);
    let parent_only = lt(&mut pool, ta, 0x02);

    let mut parent = Solver::new();
    parent.declared = declared.clone();
    parent.assert(a1);
    assert_eq!(parent.check_sat(&mut pool, &[]), Answer::Sat);

    let mut child = parent.fork();
    child.assert(child_only);
    let got = child.check_sat(&mut pool, &[]);
    let (want, want_syms) = oracle(&mut pool, &declared, &[a1, child_only], &[]);
    assert_eq!(got, want, "child after fork");
    assert_eq!(
        model_syms(&child),
        want_syms.unwrap(),
        "child model symbols"
    );

    // Parent moves on independently, after the child has grown the pool.
    parent.assert(parent_only);
    let got = parent.check_sat(&mut pool, &[]);
    let (want, want_syms) = oracle(&mut pool, &declared, &[a1, parent_only], &[]);
    assert_eq!(got, want, "parent after the child diverged");
    assert_eq!(
        model_syms(&parent),
        want_syms.unwrap(),
        "parent model symbols"
    );

    // A second fork, this one dragging in an unsupported sort. The parent's
    // own next answer must be untouched by it.
    let mut child2 = parent.fork();
    let bad = {
        let name = pool.fresh_symbol("int-is-positive", Sort::Bool);
        pool.other(name, 0, 0, &[ti], Sort::Bool)
    };
    child2.assert(bad);
    assert!(
        matches!(child2.check_sat(&mut pool, &[]), Answer::Unknown(_)),
        "an Int assertion is outside the fragment"
    );
    let got = parent.check_sat(&mut pool, &[]);
    let (want, _) = oracle(&mut pool, &declared, &[a1, parent_only], &[]);
    assert_eq!(got, want, "parent after an unsupported fork");
}
