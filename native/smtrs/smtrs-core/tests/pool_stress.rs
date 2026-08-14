//! Randomized stress of the three hot-path structures in `TermPool`: the
//! open-addressed hash-cons table, the epoch-stamped `post_order` scratch, and
//! the reused `substitute_many` rebuild buffer.
//!
//! Each is checked against an independent reference computed from the public
//! API only, so the test does not share code (or bugs) with the thing it
//! guards. The generator deliberately produces the shapes the fast paths
//! special-case: commutative operands either side of the arity-8 inline sort
//! buffer, repeated operands, heavy sharing, and enough distinct nodes to
//! drive the intern table through several growths.

use rustc_hash::{FxHashMap, FxHashSet};
use smtrs_core::{Op, Sort, TermId, TermPool};

/// xorshift64*, so the corpus is reproducible without a dependency.
struct Rng(u64);
impl Rng {
    fn next(&mut self) -> u64 {
        let mut x = self.0;
        x ^= x >> 12;
        x ^= x << 25;
        x ^= x >> 27;
        self.0 = x;
        x.wrapping_mul(0x2545_F491_4F6C_DD1D)
    }
    fn below(&mut self, n: usize) -> usize {
        (self.next() % n as u64) as usize
    }
}

const W: u32 = 8;

/// Reference post-order: children before parents, each reachable node once,
/// computed recursively with a plain visited set.
fn ref_post_order(pool: &TermPool, roots: &[TermId]) -> Vec<TermId> {
    fn go(pool: &TermPool, t: TermId, seen: &mut FxHashSet<TermId>, out: &mut Vec<TermId>) {
        if !seen.insert(t) {
            return;
        }
        for &c in pool.args(t) {
            go(pool, c, seen, out);
        }
        out.push(t);
    }
    let mut seen = FxHashSet::default();
    let mut out = Vec::new();
    for &r in roots {
        go(pool, r, &mut seen, &mut out);
    }
    out
}

/// Reference simultaneous substitution: recursive, memoized, keeping the
/// original id whenever nothing underneath changed.
fn ref_substitute(
    pool: &mut TermPool,
    t: TermId,
    map: &FxHashMap<TermId, TermId>,
    memo: &mut FxHashMap<TermId, TermId>,
) -> TermId {
    if let Some(&v) = map.get(&t) {
        return v;
    }
    if let Some(&v) = memo.get(&t) {
        return v;
    }
    let op = pool.op(t);
    let args = pool.args(t).to_vec();
    let mut new_args = Vec::with_capacity(args.len());
    for a in &args {
        let na = ref_substitute(pool, *a, map, memo);
        new_args.push(na);
    }
    let out = if new_args == args {
        t
    } else {
        pool.mk(op, &new_args).expect("rebuild")
    };
    memo.insert(t, out);
    out
}

/// Build a random DAG, checking the hash-consing bijection against a reference
/// map on every single construction.
///
/// The invariant under test is the one the open-addressed table replaced a
/// `HashMap` to provide: structurally equal keys get the same id, structurally
/// different keys never do, and the node an id names is exactly the key that
/// was asked for.
fn build_and_check(pool: &mut TermPool, rng: &mut Rng, rounds: usize) -> Vec<TermId> {
    // Reference table, keyed on the *normalized* key (commutative operands
    // sorted), which is what `mk` is specified to intern.
    let mut reference: FxHashMap<(Op, Vec<TermId>), TermId> = FxHashMap::default();
    let mut bv: Vec<TermId> = Vec::new();
    let mut boolean: Vec<TermId> = Vec::new();

    for i in 0..12 {
        let s = pool.fresh_symbol(format!("x{i}"), Sort::BitVec(W));
        bv.push(pool.var(s));
        let b = pool.fresh_symbol(format!("p{i}"), Sort::Bool);
        boolean.push(pool.var(b));
    }
    for v in 0..8u64 {
        bv.push(pool.bv_u64(W, v));
    }

    // Commutative ops at every arity from 1 to 12 straddle the arity-8 inline
    // sort buffer in `mk`; the unary/binary ops keep non-commutative keys in
    // the table alongside them.
    let bv_comm = [
        Op::BvAdd,
        Op::BvMul,
        Op::BvAnd,
        Op::BvOr,
        Op::BvXor,
        Op::BvNand,
        Op::BvNor,
        Op::BvXnor,
    ];
    let bv_bin = [Op::BvSub, Op::BvUdiv, Op::BvUrem, Op::BvShl, Op::BvLshr];
    let bool_comm = [Op::And, Op::Or, Op::Xor];

    let mut record = |pool: &mut TermPool, op: Op, args: &[TermId]| -> Option<TermId> {
        let t = pool.mk(op, args).ok()?;
        let mut key = args.to_vec();
        if op.is_commutative() && key.len() > 1 {
            key.sort_unstable();
        }
        if let Some(&prev) = reference.get(&(op, key.clone())) {
            assert_eq!(prev, t, "same key interned twice: {op:?} {key:?}");
        }
        // The id must name exactly this key.
        assert_eq!(pool.op(t), op, "operator does not round-trip");
        assert_eq!(pool.args(t), &key[..], "operands do not round-trip");
        reference.insert((op, key), t);
        Some(t)
    };

    for _ in 0..rounds {
        match rng.below(10) {
            0..=4 => {
                let op = bv_comm[rng.below(bv_comm.len())];
                // Arity 1..=12: 8 is the inline-buffer boundary.
                let n = 1 + rng.below(12);
                let args: Vec<TermId> = (0..n).map(|_| bv[rng.below(bv.len())]).collect();
                if let Some(t) = record(pool, op, &args) {
                    bv.push(t);
                }
            }
            5..=6 => {
                let op = bv_bin[rng.below(bv_bin.len())];
                let args = [bv[rng.below(bv.len())], bv[rng.below(bv.len())]];
                if let Some(t) = record(pool, op, &args) {
                    bv.push(t);
                }
            }
            7 => {
                let op = bool_comm[rng.below(bool_comm.len())];
                let n = 1 + rng.below(12);
                let args: Vec<TermId> = (0..n).map(|_| boolean[rng.below(boolean.len())]).collect();
                if let Some(t) = record(pool, op, &args) {
                    boolean.push(t);
                }
            }
            8 => {
                let args = [bv[rng.below(bv.len())], bv[rng.below(bv.len())]];
                if let Some(t) = record(pool, Op::Eq, &args) {
                    boolean.push(t);
                }
            }
            _ => {
                let args = [
                    boolean[rng.below(boolean.len())],
                    bv[rng.below(bv.len())],
                    bv[rng.below(bv.len())],
                ];
                if let Some(t) = record(pool, Op::Ite, &args) {
                    bv.push(t);
                }
            }
        }
        // Re-ask for a key already interned, which is the 71% case the table
        // is optimized for and the one a bad probe would silently duplicate.
        if !bv.is_empty() && rng.below(4) == 0 {
            let t = bv[rng.below(bv.len())];
            let op = pool.op(t);
            let args = pool.args(t).to_vec();
            if !args.is_empty() {
                let again = pool.mk(op, &args).expect("re-intern");
                assert_eq!(again, t, "re-interning an existing key produced a new id");
            }
        }
    }

    // Distinct keys, distinct ids.
    let ids: FxHashSet<TermId> = reference.values().copied().collect();
    assert_eq!(ids.len(), reference.len(), "two distinct keys share one id");
    bv.into_iter().chain(boolean).collect()
}

#[test]
fn intern_table_is_a_bijection_under_random_construction() {
    for seed in 1..=6u64 {
        let mut rng = Rng(seed.wrapping_mul(0x9E37_79B9_7F4A_7C15) | 1);
        let mut pool = TermPool::new();
        let terms = build_and_check(&mut pool, &mut rng, 4000);
        assert!(
            pool.num_terms() > 2000,
            "corpus too small to grow the table"
        );
        assert!(!terms.is_empty());
    }
}

#[test]
fn post_order_matches_a_reference_across_reuse_growth_and_nesting() {
    let mut rng = Rng(0xDEAD_BEEF);
    let mut pool = TermPool::new();
    let terms = build_and_check(&mut pool, &mut rng, 1500);

    // Many traversals against the one parked buffer, with the pool growing in
    // between, and repeated roots so a stale stamp would show as a short walk.
    for round in 0..200 {
        let n = 1 + rng.below(4);
        let roots: Vec<TermId> = (0..n).map(|_| terms[rng.below(terms.len())]).collect();
        let mut got = Vec::new();
        pool.post_order(&roots, |_, t| got.push(t));
        assert_eq!(got, ref_post_order(&pool, &roots), "round {round}");
        // Immediately again: the second call must not inherit the first's
        // stamps.
        let mut again = Vec::new();
        pool.post_order(&roots, |_, t| again.push(t));
        assert_eq!(again, got, "traversal not independent, round {round}");

        // Grow the pool between traversals so the stamp buffer is resized
        // while a nonzero epoch is parked on it.
        let a = terms[rng.below(terms.len())];
        let b = terms[rng.below(terms.len())];
        if pool.sort(a) == pool.sort(b) && pool.sort(a) == Sort::BitVec(W) {
            let _ = pool.mk(Op::BvSub, &[a, b]);
        }
    }

    // Nested traversals: the callback of one walk starts another, which is why
    // the scratch is moved out of the pool rather than borrowed from it.
    let root = terms[rng.below(terms.len())];
    let want = ref_post_order(&pool, &[root]);
    let mut outer = Vec::new();
    pool.post_order(&[root], |p, t| {
        outer.push(t);
        // Depth two, from inside the inner callback as well.
        p.post_order(&[t], |p2, u| {
            p2.post_order(&[u], |_, _| {});
        });
    });
    assert_eq!(outer, want, "a nested traversal disturbed its parent");

    // And the outer walk is still repeatable after all that nesting.
    let mut after = Vec::new();
    pool.post_order(&[root], |_, t| after.push(t));
    assert_eq!(after, want, "parked scratch was left inconsistent");
}

#[test]
fn substitute_many_matches_a_reference() {
    let mut rng = Rng(0x0BAD_F00D);
    let mut pool = TermPool::new();
    let terms = build_and_check(&mut pool, &mut rng, 1200);
    let bvs: Vec<TermId> = terms
        .iter()
        .copied()
        .filter(|&t| pool.sort(t) == Sort::BitVec(W))
        .collect();
    assert!(bvs.len() > 50);

    for round in 0..120 {
        let nmap = 1 + rng.below(6);
        let mut map: FxHashMap<TermId, TermId> = FxHashMap::default();
        for _ in 0..nmap {
            let k = bvs[rng.below(bvs.len())];
            let v = bvs[rng.below(bvs.len())];
            map.insert(k, v);
        }
        let roots: Vec<TermId> = (0..1 + rng.below(3))
            .map(|_| bvs[rng.below(bvs.len())])
            .collect();

        // Reference first, so both see the same starting pool for the
        // "unchanged subterms keep their id" half of the check.
        let mut memo = FxHashMap::default();
        let want: Vec<TermId> = roots
            .iter()
            .map(|&r| ref_substitute(&mut pool, r, &map, &mut memo))
            .collect();
        let got = pool.substitute_many(&roots, &map).expect("substitute");
        assert_eq!(got, want, "round {round}");
    }
}
