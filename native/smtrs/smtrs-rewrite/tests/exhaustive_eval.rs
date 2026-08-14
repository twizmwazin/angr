//! Rewrite verification without a reference solver.
//!
//! `soundness.rs` proves rewrites equivalent at widths 1..=65 by shelling out
//! to z3. That is the stronger gate, but z3 is deliberately absent from CI, so
//! those tests skip and the rules go unchecked on every automated run. This
//! file is the gate that always runs.
//!
//! The oracle is `smtrs_core::eval`, the ground evaluator: arbitrary-width
//! `BvConst` arithmetic implementing SMT-LIB semantics, written independently
//! of the rewriter (the rewriter's constant folding calls into it, but no rule
//! logic lives there). So for a closed term we can compute the exact value of
//! the original and of the rewritten form and demand they agree. Enumerating
//! *all* assignments at a small width turns that into a proof of equivalence
//! at that width: 3 variables at width 4 is 4096 cases, which is nothing.
//!
//! What this catches: essentially every syntactic rule bug, every operand
//! mix-up, every off-by-one in an extract boundary, and any over-claim by the
//! `nonzero_mask` zero-bit analysis. What it cannot catch: a rule that is
//! correct at widths 1..=4 and wrong at, say, 33 — a width-dependent constant,
//! a limb-boundary bug, a rule keyed on a width threshold. Those need the z3
//! sweep, which is why it stays.
//!
//! Every check here is exact and exhaustive: there is no sampling anywhere in
//! this file, so a failure is a real counterexample and never flakes.
//!
//! Calibration: the suite was mutation-tested against 19 hand-written faults in
//! `rules.rs` — a swapped `bvudiv` shift direction, a dropped `lo == 0` guard on
//! the arithmetic extract pushdown, an off-by-one `eq-concat-split` boundary, a
//! `nonzero_mask` that intersects instead of unions, `x * -1 -> bvnot x`, a
//! sign-extend replicating the lsb, and so on. All 19 are now caught; one
//! (`extract-concat` dropping a slice) only by `random_terms_survive_rewriting`.
//! Two are worth knowing about. The `extract-concat` one is why the random
//! generator exists at all. And `lin_accumulate` negating the minuend instead
//! of the subtrahend initially *survived*: the linear normalizer's cost test
//! declines a mis-signed form for being larger, so the fault is invisible
//! except on the shapes where the wrong sign is the one that cancels — hence
//! the `bvsub` arrangements in `linear_normalization_rules`. Add mutations, not
//! just tests, when extending this file: a rule the suite reaches but cannot
//! falsify is not covered.

use rustc_hash::FxHashMap;
use smtrs_core::{eval, BvConst, Op, Sort, SymbolId, TermId, TermPool, Value};
use smtrs_rewrite::{soundness::linear_and_or_seeds, Rewriter};

/// Cap on the assignments one check will enumerate. Nothing in this file
/// should come close; the assert exists so that a widened test fails loudly
/// instead of quietly running for an hour.
const MAX_CASES: u64 = 1 << 17;

// ---------------------------------------------------------------------------
// enumeration harness
// ---------------------------------------------------------------------------

/// Free symbols of `roots`, in first-visit order (deterministic).
fn free_syms(pool: &TermPool, roots: &[TermId]) -> Vec<SymbolId> {
    let mut syms: Vec<SymbolId> = Vec::new();
    pool.post_order(roots, |pool, t| {
        if let Op::Var(s) = pool.op(t) {
            if !syms.contains(&s) {
                syms.push(s);
            }
        }
    });
    syms
}

fn domain_size(sort: Sort) -> u64 {
    match sort {
        Sort::Bool => 2,
        Sort::BitVec(w) => {
            assert!(w <= 16, "width {w} is too wide to enumerate exhaustively");
            1u64 << w
        }
        other => panic!("cannot enumerate sort {other}"),
    }
}

fn value_at(sort: Sort, index: u64) -> Value {
    match sort {
        Sort::Bool => Value::Bool(index == 1),
        Sort::BitVec(w) => Value::Bv(BvConst::from_u64(w, index)),
        other => panic!("cannot enumerate sort {other}"),
    }
}

/// Call `f` on every assignment to `syms`. Returns the number of assignments.
fn for_each_assignment(
    pool: &TermPool,
    syms: &[SymbolId],
    mut f: impl FnMut(&FxHashMap<SymbolId, Value>),
) -> u64 {
    let sorts: Vec<Sort> = syms.iter().map(|&s| pool.symbol(s).sort).collect();
    let mut total: u64 = 1;
    for &s in &sorts {
        total = total
            .checked_mul(domain_size(s))
            .expect("assignment count overflowed");
    }
    assert!(
        total <= MAX_CASES,
        "{total} assignments over {} variables exceeds the enumeration cap",
        syms.len()
    );
    let mut asg: FxHashMap<SymbolId, Value> = FxHashMap::default();
    for n in 0..total {
        let mut rest = n;
        for (i, &sort) in sorts.iter().enumerate() {
            let d = domain_size(sort);
            asg.insert(syms[i], value_at(sort, rest % d));
            rest /= d;
        }
        f(&asg);
    }
    total
}

fn show_value(v: &Value) -> String {
    match v {
        Value::Bool(b) => b.to_string(),
        Value::Bv(c) => c.to_binary_string(),
    }
}

fn show_assignment(pool: &TermPool, asg: &FxHashMap<SymbolId, Value>) -> String {
    let mut parts: Vec<String> = asg
        .iter()
        .map(|(&s, v)| format!("{} = {}", pool.symbol(s).name, show_value(v)))
        .collect();
    parts.sort();
    parts.join(", ")
}

/// The oracle. Evaluates both sides of every pair under every assignment to
/// their free variables; returns a description of the first disagreement.
///
/// All pairs are checked in one enumeration and one `eval` call per
/// assignment, so the shared DAG is walked once rather than once per pair.
fn find_disagreement(pool: &TermPool, pairs: &[(TermId, TermId)]) -> Option<String> {
    if pairs.is_empty() {
        return None;
    }
    let roots: Vec<TermId> = pairs.iter().flat_map(|&(a, b)| [a, b]).collect();
    let syms = free_syms(pool, &roots);
    let mut found: Option<String> = None;
    for_each_assignment(pool, &syms, |asg| {
        if found.is_some() {
            return;
        }
        let vals = eval(pool, &roots, asg).expect("closed term under a total assignment");
        for (i, &(a, b)) in pairs.iter().enumerate() {
            if vals[2 * i] != vals[2 * i + 1] {
                found = Some(format!(
                    "  under {}\n  before: {}\n       = {}\n  after:  {}\n       = {}",
                    show_assignment(pool, asg),
                    pool.display(a),
                    show_value(&vals[2 * i]),
                    pool.display(b),
                    show_value(&vals[2 * i + 1]),
                ));
                return;
            }
        }
    });
    found
}

/// Rewrite every term in `terms` and prove each rewrite meaning-preserving by
/// exhaustive evaluation. Returns the rule-hit statistics and how many terms
/// the rewriter actually changed.
fn rewrite_and_check(
    pool: &mut TermPool,
    terms: &[TermId],
    ctx: &str,
) -> (FxHashMap<&'static str, u64>, usize) {
    let mut rw = Rewriter::new();
    let mut pairs: Vec<(TermId, TermId)> = Vec::new();
    for &t in terms {
        let r = rw.rewrite(pool, t);
        if r != t {
            pairs.push((t, r));
        }
    }
    if let Some(msg) = find_disagreement(pool, &pairs) {
        panic!("UNSOUND REWRITE [{ctx}]\n{msg}");
    }
    (rw.stats.clone(), pairs.len())
}

/// Merge rule-hit counts across widths.
fn merge(into: &mut FxHashMap<&'static str, u64>, from: FxHashMap<&'static str, u64>) {
    for (k, v) in from {
        *into.entry(k).or_insert(0) += v;
    }
}

/// Fail when a rule the test claims to cover never fired: a green test that
/// never reached its rule is worse than no test.
fn assert_fired(stats: &FxHashMap<&'static str, u64>, rules: &[&str]) {
    let mut missing: Vec<&str> = rules
        .iter()
        .copied()
        .filter(|r| !stats.contains_key(r))
        .collect();
    missing.sort();
    assert!(
        missing.is_empty(),
        "rules never fired, so nothing was verified for them: {missing:?}\n\
         fired: {:?}",
        {
            let mut f: Vec<&str> = stats.keys().copied().collect();
            f.sort();
            f
        }
    );
}

/// Widths for the three-variable piles: 4 is the largest that keeps them at
/// 4096 cases. 1 and 2 are where the degenerate cases live (`w - 1 == 0`
/// boundaries, single-bit signedness, `w / 2 == 1`).
const WIDTHS: std::ops::RangeInclusive<u32> = 1..=4;

/// Widths for the two-variable piles, where the case count is only 2^(2w) and
/// 6 still costs 4096. Worth the extra two widths: they are where `bvudiv` by
/// 2^4 and 2^5, half-word boundaries at 2 and 3 bits, and shift amounts that
/// are neither tiny nor saturating first appear.
const WIDE_WIDTHS: std::ops::RangeInclusive<u32> = 1..=6;

// ---------------------------------------------------------------------------
// the harness itself must be able to fail
// ---------------------------------------------------------------------------

/// Negative control. Everything else here asserts that a check *passes*, which
/// proves nothing unless the check can fail. `x + y` and `x xor y` agree on
/// plenty of inputs and differ on others, so a working oracle rejects them and
/// a broken one (wrong roots, empty enumeration, swallowed comparison) does not.
#[test]
fn harness_rejects_a_wrong_equivalence() {
    let mut p = TermPool::new();
    let xs = p.fresh_symbol("x", Sort::BitVec(3));
    let ys = p.fresh_symbol("y", Sort::BitVec(3));
    let (x, y) = (p.var(xs), p.var(ys));
    let add = p.mk(Op::BvAdd, &[x, y]).unwrap();
    let xor = p.mk(Op::BvXor, &[x, y]).unwrap();
    assert!(
        find_disagreement(&p, &[(add, xor)]).is_some(),
        "the oracle accepted bvadd == bvxor"
    );
    // ... and accepts a genuine identity (x + y == y + x, and x - x == 0).
    let commuted = p.mk(Op::BvAdd, &[y, x]).unwrap();
    let sub = p.mk(Op::BvSub, &[x, x]).unwrap();
    let zero = p.bv_u64(3, 0);
    assert!(find_disagreement(&p, &[(add, commuted), (sub, zero)]).is_none());
}

/// The evaluator is the oracle, so its handling of the partial operators is
/// load-bearing: if `bvudiv` by zero evaluated to anything other than all-ones
/// every division rule would appear unsound. Pin the SMT-LIB totalization.
#[test]
fn evaluator_totalizes_division_by_zero_per_smtlib() {
    for w in [1u32, 3, 4, 8] {
        let zero = BvConst::zero(w);
        for v in 0..(1u64 << w.min(8)) {
            let a = BvConst::from_u64(w, v);
            assert_eq!(a.udiv(&zero), BvConst::ones(w), "bvudiv {v} 0 at width {w}");
            assert_eq!(a.urem(&zero), a, "bvurem {v} 0 at width {w}");
            // bvsdiv/bvsrem/bvsmod inherit their zero cases from bvudiv.
            let expect_sdiv = if a.sign_bit() {
                BvConst::from_u64(w, 1)
            } else {
                BvConst::ones(w)
            };
            assert_eq!(a.sdiv(&zero), expect_sdiv, "bvsdiv {v} 0 at width {w}");
            assert_eq!(a.srem(&zero), a, "bvsrem {v} 0 at width {w}");
            assert_eq!(a.smod(&zero), a, "bvsmod {v} 0 at width {w}");
        }
    }
}

// ---------------------------------------------------------------------------
// end-to-end: the whole rewriter on the term piles
// ---------------------------------------------------------------------------

/// The pile the z3 gate uses for the linear-normalization and disjoint-`or`
/// work, checked here without z3. This is an *end-to-end* check — the terms go
/// through `Rewriter::rewrite`, so rule interactions are covered, not just the
/// rules in isolation.
#[test]
fn linear_and_disjoint_or_seeds_preserve_meaning() {
    let mut stats = FxHashMap::default();
    let mut fired = 0;
    for w in WIDTHS {
        let mut pool = TermPool::new();
        let seeds = linear_and_or_seeds(&mut pool, w);
        let (s, n) = rewrite_and_check(&mut pool, &seeds, &format!("linear/or seeds, width {w}"));
        merge(&mut stats, s);
        fired += n;
    }
    assert!(
        fired > 40,
        "expected the seed pile to rewrite widely, got {fired}"
    );
    assert_fired(
        &stats,
        &[
            "add-collect-coeffs",
            "add-distribute",
            "or-disjoint-concat",
            "eq-concat-split",
            "ac-flatten",
            "extract-concat",
            "shift-const",
        ],
    );
}

/// A broad pile over the whole supported operator set, mirroring the shapes
/// the z3 gate builds: every binary BV op against a variable, a constant and
/// itself; the unary ops nested; the extensions, rotations and repeats; every
/// comparison; and the boolean layer on top.
fn general_pile(pool: &mut TermPool, w: u32) -> Vec<TermId> {
    let xs = pool.fresh_symbol("x", Sort::BitVec(w));
    let ys = pool.fresh_symbol("y", Sort::BitVec(w));
    let (x, y) = (pool.var(xs), pool.var(ys));
    let c1 = pool.bv_u64(w, 1 % (1u64 << w));
    let c3 = pool.bv_u64(w, 3 % (1u64 << w));
    let mut terms = vec![x, y, c1, c3];
    let seeds = terms.clone();

    let binops = [
        Op::BvAdd,
        Op::BvSub,
        Op::BvMul,
        Op::BvUdiv,
        Op::BvUrem,
        Op::BvSdiv,
        Op::BvSrem,
        Op::BvSmod,
        Op::BvAnd,
        Op::BvOr,
        Op::BvXor,
        Op::BvNand,
        Op::BvNor,
        Op::BvXnor,
        Op::BvShl,
        Op::BvLshr,
        Op::BvAshr,
    ];
    for (i, &op) in binops.iter().enumerate() {
        let a = seeds[i % seeds.len()];
        let b = seeds[(i + 1) % seeds.len()];
        terms.push(pool.mk(op, &[a, b]).unwrap());
        terms.push(pool.mk(op, &[a, a]).unwrap());
        // Both operand orders, so a rule that mixes up dividend and divisor
        // (the asymmetric ops) cannot hide behind a symmetric operand pair.
        terms.push(pool.mk(op, &[b, a]).unwrap());
        // A variable divisor ranges over zero: the partial operators get their
        // totalized cases enumerated for free.
        terms.push(pool.mk(op, &[x, y]).unwrap());
    }
    for &op in &[Op::BvNeg, Op::BvNot] {
        let n1 = pool.mk(op, &[x]).unwrap();
        terms.push(n1);
        terms.push(pool.mk(op, &[n1]).unwrap());
    }
    let notx = pool.mk(Op::BvNot, &[x]).unwrap();
    terms.push(pool.mk(Op::BvAnd, &[x, notx]).unwrap());
    terms.push(pool.mk(Op::BvOr, &[x, notx]).unwrap());
    terms.push(pool.mk(Op::BvXor, &[x, notx]).unwrap());
    if w >= 2 {
        terms.push(pool.mk(Op::Extract { hi: w - 1, lo: 1 }, &[x]).unwrap());
        terms.push(pool.mk(Op::Extract { hi: w - 2, lo: 0 }, &[x]).unwrap());
        let cc = pool.mk(Op::Concat, &[x, y]).unwrap();
        terms.push(cc);
        terms.push(pool.mk(Op::Extract { hi: w, lo: w - 1 }, &[cc]).unwrap());
        terms.push(
            pool.mk(
                Op::Extract {
                    hi: 2 * w - 1,
                    lo: w,
                },
                &[cc],
            )
            .unwrap(),
        );
    }
    for &op in &[
        Op::ZeroExtend(3),
        Op::SignExtend(3),
        Op::RotateLeft(1),
        Op::RotateRight(2),
        Op::Repeat(2),
    ] {
        terms.push(pool.mk(op, &[x]).unwrap());
    }
    let cmps = [
        Op::BvUlt,
        Op::BvUle,
        Op::BvUgt,
        Op::BvUge,
        Op::BvSlt,
        Op::BvSle,
        Op::BvSgt,
        Op::BvSge,
        Op::BvComp,
    ];
    for (i, &op) in cmps.iter().enumerate() {
        let a = seeds[i % seeds.len()];
        terms.push(pool.mk(op, &[a, seeds[(i + 3) % seeds.len()]]).unwrap());
        terms.push(pool.mk(op, &[x, y]).unwrap());
    }
    // Bool layer.
    let p1 = pool.mk(Op::BvUlt, &[x, y]).unwrap();
    let p2 = pool.mk(Op::Eq, &[x, c3]).unwrap();
    let np1 = pool.mk(Op::Not, &[p1]).unwrap();
    let f = pool.false_term;
    for t in [
        pool.mk(Op::And, &[p1, np1]).unwrap(),
        pool.mk(Op::Or, &[p1, np1]).unwrap(),
        pool.mk(Op::Xor, &[p1, p2]).unwrap(),
        pool.mk(Op::Implies, &[p1, p2]).unwrap(),
        pool.mk(Op::Ite, &[p1, x, y]).unwrap(),
        pool.mk(Op::Ite, &[p1, c1, c3]).unwrap(),
        pool.mk(Op::Distinct, &[x, y, c1]).unwrap(),
        pool.mk(Op::Distinct, &[x, y]).unwrap(),
        pool.mk(Op::Eq, &[p1, f]).unwrap(),
    ] {
        terms.push(t);
    }
    terms
}

#[test]
fn general_operator_pile_preserves_meaning() {
    let mut stats = FxHashMap::default();
    let mut fired = 0;
    for w in WIDE_WIDTHS {
        let mut pool = TermPool::new();
        let pile = general_pile(&mut pool, w);
        let (s, n) = rewrite_and_check(&mut pool, &pile, &format!("general pile, width {w}"));
        merge(&mut stats, s);
        fired += n;
    }
    assert!(fired > 100, "expected many rewrites, got {fired}");
    assert_fired(
        &stats,
        &[
            "nand-elim",
            "bvcomp-elim",
            "zext-to-concat",
            "sext-to-concat",
            "rotl-to-concat",
            "repeat-to-concat",
            "implies-to-or",
            "distinct-to-eq",
            "not-ult",
            "sub-self",
            "bvxor-cancel",
            "bv-idempotent",
            "bv-complement",
            "fold",
        ],
    );
}

/// Rule interactions specifically: terms built so that one rule's output is
/// another's input (a disjoint-`or` feeding an equality that splits over the
/// resulting concat, a linear form feeding a comparison, an extract landing on
/// a rewritten arithmetic node). Per-rule tests structurally cannot see these.
#[test]
fn rule_interactions_preserve_meaning() {
    let mut fired = 0;
    for w in 2..=4u32 {
        let mut pool = TermPool::new();
        let xs = pool.fresh_symbol("x", Sort::BitVec(w));
        let ys = pool.fresh_symbol("y", Sort::BitVec(w));
        let zs = pool.fresh_symbol("z", Sort::BitVec(w));
        let (x, y, z) = (pool.var(xs), pool.var(ys), pool.var(zs));
        let h = w / 2;
        let mut terms: Vec<TermId> = Vec::new();

        // Byte-assembly -> disjoint or -> concat -> equality split -> per-slice
        // equalities, with a linear form on one of the slices.
        let sh = pool.bv_u64(w, h as u64);
        let hi = pool.mk(Op::BvShl, &[x, sh]).unwrap();
        let lo_bits = pool.mk(Op::Extract { hi: h - 1, lo: 0 }, &[y]).unwrap();
        let lo = pool.mk(Op::ZeroExtend(w - h), &[lo_bits]).unwrap();
        let asm = pool.mk(Op::BvOr, &[hi, lo]).unwrap();
        let k = pool.bv_u64(w, 3 % (1u64 << w));
        terms.push(pool.mk(Op::Eq, &[asm, k]).unwrap());
        let sum = pool.mk(Op::BvAdd, &[asm, x, k]).unwrap();
        terms.push(pool.mk(Op::Eq, &[sum, z]).unwrap());
        terms.push(pool.mk(Op::BvUle, &[sum, z]).unwrap());

        // Extract of a linear form: pushdown meets coefficient collection.
        let lin = pool.mk(Op::BvAdd, &[x, x, y, k]).unwrap();
        terms.push(pool.mk(Op::Extract { hi: h, lo: 0 }, &[lin]).unwrap());
        let neg = pool.mk(Op::BvNeg, &[lin]).unwrap();
        terms.push(pool.mk(Op::BvAdd, &[lin, neg, z]).unwrap());

        // Bitwise extract pushdown over a term the or-rule rebuilt.
        let masked = pool.mk(Op::BvAnd, &[asm, k]).unwrap();
        terms.push(
            pool.mk(Op::Extract { hi: w - 1, lo: h }, &[masked])
                .unwrap(),
        );
        terms.push(pool.mk(Op::BvXor, &[masked, asm, x]).unwrap());

        // ite whose branches are rewritten forms, under an extract and an eq.
        let c = pool.mk(Op::BvUlt, &[x, y]).unwrap();
        let ite = pool.mk(Op::Ite, &[c, sum, neg]).unwrap();
        terms.push(pool.mk(Op::Extract { hi: h, lo: 0 }, &[ite]).unwrap());
        terms.push(pool.mk(Op::Eq, &[ite, asm]).unwrap());

        // Division and remainder over rewritten operands (divisor reaches 0).
        terms.push(pool.mk(Op::BvUdiv, &[sum, asm]).unwrap());
        terms.push(pool.mk(Op::BvUrem, &[asm, sum]).unwrap());
        terms.push(pool.mk(Op::BvSmod, &[neg, asm]).unwrap());

        let (_, n) = rewrite_and_check(&mut pool, &terms, &format!("interactions, width {w}"));
        fired += n;
    }
    assert!(
        fired > 20,
        "expected interaction terms to rewrite, got {fired}"
    );
}

// ---------------------------------------------------------------------------
// per-rule coverage
// ---------------------------------------------------------------------------

/// `LinForm` / `lin_accumulate` / `collect_add_coefficients`: coefficient
/// collection, cancellation, and distribution through a coefficient.
#[test]
fn linear_normalization_rules() {
    let mut stats = FxHashMap::default();
    for w in WIDTHS {
        let mut pool = TermPool::new();
        let xs = pool.fresh_symbol("x", Sort::BitVec(w));
        let ys = pool.fresh_symbol("y", Sort::BitVec(w));
        let zs = pool.fresh_symbol("z", Sort::BitVec(w));
        let (x, y, z) = (pool.var(xs), pool.var(ys), pool.var(zs));
        let m = |v: u64| v % (1u64 << w);
        let k1 = pool.bv_u64(w, m(1));
        let k2 = pool.bv_u64(w, m(2));
        let k3 = pool.bv_u64(w, m(3));
        let k7 = pool.bv_u64(w, m(7));
        let mut terms: Vec<TermId> = Vec::new();

        // x + x -> 2x; x + 3x -> 4x; 2x + (-2)x -> 0.
        terms.push(pool.mk(Op::BvAdd, &[x, x]).unwrap());
        let m3x = pool.mk(Op::BvMul, &[k3, x]).unwrap();
        terms.push(pool.mk(Op::BvAdd, &[x, m3x]).unwrap());
        let m2x = pool.mk(Op::BvMul, &[k2, x]).unwrap();
        let nm2x = pool.mk(Op::BvNeg, &[m2x]).unwrap();
        terms.push(pool.mk(Op::BvAdd, &[m2x, nm2x]).unwrap());
        terms.push(pool.mk(Op::BvAdd, &[m2x, nm2x, y]).unwrap());

        // Distribution through a coefficient: c*(a+b), -(a+b), c*(a-b).
        let xy = pool.mk(Op::BvAdd, &[x, y]).unwrap();
        let m3xy = pool.mk(Op::BvMul, &[k3, xy]).unwrap();
        let m3y = pool.mk(Op::BvMul, &[k3, y]).unwrap();
        let nm3y = pool.mk(Op::BvNeg, &[m3y]).unwrap();
        terms.push(pool.mk(Op::BvAdd, &[m3xy, nm3y]).unwrap());
        let nxy = pool.mk(Op::BvNeg, &[xy]).unwrap();
        terms.push(pool.mk(Op::BvAdd, &[nxy, x]).unwrap());
        terms.push(pool.mk(Op::BvAdd, &[nxy, xy]).unwrap());
        let sub = pool.mk(Op::BvSub, &[x, y]).unwrap();
        let m7sub = pool.mk(Op::BvMul, &[k7, sub]).unwrap();
        let m7y = pool.mk(Op::BvMul, &[k7, y]).unwrap();
        terms.push(pool.mk(Op::BvAdd, &[m7sub, m7y]).unwrap());

        // `bvsub` under the linear form, in every arrangement where the
        // *wrong* operand sign would still shrink the term. The cost test
        // ("take the deeper form only when it is smaller") otherwise hides a
        // sign error by declining to distribute: a mutation that negates the
        // minuend instead of the subtrahend survives `k*(x-y) + k*y`, because
        // the mis-signed form is bigger and loses. It does not survive these,
        // where the mis-signed form is the one that cancels.
        terms.push(pool.mk(Op::BvAdd, &[sub, x]).unwrap());
        terms.push(pool.mk(Op::BvAdd, &[sub, y]).unwrap());
        terms.push(pool.mk(Op::BvAdd, &[sub, x, y]).unwrap());
        let nsub = pool.mk(Op::BvNeg, &[sub]).unwrap();
        terms.push(pool.mk(Op::BvAdd, &[nsub, x]).unwrap());
        terms.push(pool.mk(Op::BvAdd, &[nsub, y]).unwrap());
        terms.push(pool.mk(Op::BvAdd, &[nsub, sub, x]).unwrap());
        let m7x = pool.mk(Op::BvMul, &[k7, x]).unwrap();
        terms.push(pool.mk(Op::BvAdd, &[m7sub, m7x]).unwrap());
        let nm7sub = pool.mk(Op::BvNeg, &[m7sub]).unwrap();
        terms.push(pool.mk(Op::BvAdd, &[nm7sub, m7x]).unwrap());
        terms.push(pool.mk(Op::BvAdd, &[nm7sub, m7y]).unwrap());
        // Nested subtraction: the inner sign flips again on the way down.
        let inner_sub = pool.mk(Op::BvSub, &[y, z]).unwrap();
        let outer_sub = pool.mk(Op::BvSub, &[x, inner_sub]).unwrap();
        terms.push(pool.mk(Op::BvAdd, &[outer_sub, y]).unwrap());
        terms.push(pool.mk(Op::BvAdd, &[outer_sub, z]).unwrap());
        terms.push(pool.mk(Op::BvAdd, &[outer_sub, x, z]).unwrap());
        let m2osub = pool.mk(Op::BvMul, &[k2, outer_sub]).unwrap();
        let m2z = pool.mk(Op::BvMul, &[k2, z]).unwrap();
        terms.push(pool.mk(Op::BvAdd, &[m2osub, m2z]).unwrap());
        // And the subtrahend as a sum, so distribution has to sign both parts.
        let sum_sub = pool.mk(Op::BvSub, &[x, xy]).unwrap();
        terms.push(pool.mk(Op::BvAdd, &[sum_sub, x]).unwrap());
        terms.push(pool.mk(Op::BvAdd, &[sum_sub, y]).unwrap());
        terms.push(pool.mk(Op::BvAdd, &[sum_sub, xy]).unwrap());

        // Nested coefficients, three levels deep.
        let inner = pool.mk(Op::BvAdd, &[x, k1]).unwrap();
        let l1 = pool.mk(Op::BvMul, &[k2, inner]).unwrap();
        let l2 = pool.mk(Op::BvAdd, &[l1, y]).unwrap();
        let l3 = pool.mk(Op::BvMul, &[k3, l2]).unwrap();
        terms.push(l3);
        terms.push(pool.mk(Op::BvAdd, &[l3, z, k7]).unwrap());

        // A shared sum, scaled and unscaled at once (the `Full` mode case).
        let s = pool.mk(Op::BvAdd, &[x, k7]).unwrap();
        let ns = pool.mk(Op::BvNeg, &[s]).unwrap();
        terms.push(pool.mk(Op::BvAdd, &[s, ns, s, y]).unwrap());
        let m2s = pool.mk(Op::BvMul, &[k2, s]).unwrap();
        terms.push(pool.mk(Op::BvAdd, &[m2s, ns, z]).unwrap());

        // A non-constant product must stay an opaque atom, not get expanded.
        let xz = pool.mk(Op::BvMul, &[x, z]).unwrap();
        terms.push(pool.mk(Op::BvAdd, &[xz, xz, y]).unwrap());
        let m3xz = pool.mk(Op::BvMul, &[k3, xz]).unwrap();
        terms.push(pool.mk(Op::BvAdd, &[m3xz, xz]).unwrap());

        // Pulling a factor shared by every summand back out of the sum. Every
        // arrangement the multiset intersection has to get right: repeated
        // factors (x*x + x*y shares one x, not two), a bare summand that
        // becomes the unit, a negated summand that becomes -1, coefficients
        // that must ride along with the quotient, and a three-way sum.
        let xx = pool.mk(Op::BvMul, &[x, x]).unwrap();
        let xy2 = pool.mk(Op::BvMul, &[x, y]).unwrap();
        let xz2 = pool.mk(Op::BvMul, &[x, z]).unwrap();
        let xyz = pool.mk(Op::BvMul, &[x, y, z]).unwrap();
        terms.push(pool.mk(Op::BvAdd, &[xx, xy2]).unwrap());
        terms.push(pool.mk(Op::BvAdd, &[xy2, xz2]).unwrap());
        terms.push(pool.mk(Op::BvAdd, &[xy2, xz2, xyz]).unwrap());
        terms.push(pool.mk(Op::BvAdd, &[xy2, x]).unwrap());
        terms.push(pool.mk(Op::BvAdd, &[xyz, xy2]).unwrap());
        let nxy2 = pool.mk(Op::BvNeg, &[xy2]).unwrap();
        terms.push(pool.mk(Op::BvAdd, &[xx, nxy2]).unwrap());
        let nx = pool.mk(Op::BvNeg, &[x]).unwrap();
        terms.push(pool.mk(Op::BvAdd, &[xy2, nx]).unwrap());
        let k3xy = pool.mk(Op::BvMul, &[k3, x, y]).unwrap();
        terms.push(pool.mk(Op::BvAdd, &[k3xy, xz2]).unwrap());
        terms.push(pool.mk(Op::BvAdd, &[k3xy, x]).unwrap());
        // No common factor, or a constant summand: the rule must decline.
        terms.push(pool.mk(Op::BvAdd, &[xy2, z]).unwrap());
        terms.push(pool.mk(Op::BvAdd, &[xy2, k3]).unwrap());
        terms.push(pool.mk(Op::BvAdd, &[xy2, xz2, k3]).unwrap());

        // `~(-x) == x - 1` and `-(~x) == x + 1`, alone and inside a sum where
        // the constant they expose has to cancel.
        let negx3 = pool.mk(Op::BvNeg, &[x]).unwrap();
        let notnegx = pool.mk(Op::BvNot, &[negx3]).unwrap();
        terms.push(notnegx);
        let notx3 = pool.mk(Op::BvNot, &[x]).unwrap();
        let negnotx = pool.mk(Op::BvNeg, &[notx3]).unwrap();
        terms.push(negnotx);
        terms.push(pool.mk(Op::BvAdd, &[notnegx, negnotx]).unwrap());
        terms.push(pool.mk(Op::BvMul, &[y, notnegx]).unwrap());

        let (s, _) = rewrite_and_check(&mut pool, &terms, &format!("linear rules, width {w}"));
        merge(&mut stats, s);
    }
    assert_fired(
        &stats,
        &[
            "add-collect-coeffs",
            "add-distribute",
            "add-factor",
            "bvnot-bvneg",
            "bvneg-bvnot",
        ],
    );
}

/// `or_disjoint_concat` and the `nonzero_mask` analysis that licenses it.
#[test]
fn or_disjoint_concat_rule() {
    let mut stats = FxHashMap::default();
    for w in 2..=4u32 {
        let mut pool = TermPool::new();
        let xs = pool.fresh_symbol("x", Sort::BitVec(w));
        let ys = pool.fresh_symbol("y", Sort::BitVec(w));
        let zs = pool.fresh_symbol("z", Sort::BitVec(w));
        let (x, y, z) = (pool.var(xs), pool.var(ys), pool.var(zs));
        let h = w / 2;
        let sh = pool.bv_u64(w, h as u64);
        let zhi = pool.bv(BvConst::zero(w - h));
        let zlo = pool.bv(BvConst::zero(h));
        let lo_mask = pool.bv(BvConst::ones(h).zero_extend(w - h));
        let hi_mask = pool.bv(BvConst::ones(w - h).concat(&BvConst::zero(h)));
        let zero_w = pool.bv(BvConst::zero(w));
        let mut terms: Vec<TermId> = Vec::new();

        // Shift/extend assembly, both orders.
        let shifted = pool.mk(Op::BvShl, &[x, sh]).unwrap();
        let lo_bits = pool.mk(Op::Extract { hi: h - 1, lo: 0 }, &[y]).unwrap();
        let ext = pool.mk(Op::ZeroExtend(w - h), &[lo_bits]).unwrap();
        terms.push(pool.mk(Op::BvOr, &[shifted, ext]).unwrap());
        terms.push(pool.mk(Op::BvOr, &[ext, shifted]).unwrap());

        // Concat-built operands with matching boundaries.
        let top = pool
            .mk(
                Op::Extract {
                    hi: w - h - 1,
                    lo: 0,
                },
                &[z],
            )
            .unwrap();
        let a = pool.mk(Op::Concat, &[zhi, lo_bits]).unwrap();
        let b = pool.mk(Op::Concat, &[top, zlo]).unwrap();
        terms.push(pool.mk(Op::BvOr, &[a, b]).unwrap());

        // Masked operands: the analysis must see through bvand.
        let ml = pool.mk(Op::BvAnd, &[x, lo_mask]).unwrap();
        let mh = pool.mk(Op::BvAnd, &[y, hi_mask]).unwrap();
        terms.push(pool.mk(Op::BvOr, &[ml, mh]).unwrap());
        // Three-way, with a constant operand carrying no live bits.
        terms.push(pool.mk(Op::BvOr, &[ml, mh, zero_w]).unwrap());

        // Overlapping operands: the rule must *decline*. If it fired anyway
        // the enumeration below would catch the wrong answer.
        terms.push(pool.mk(Op::BvOr, &[ml, x]).unwrap());
        terms.push(pool.mk(Op::BvOr, &[a, x]).unwrap());
        terms.push(pool.mk(Op::BvOr, &[shifted, x]).unwrap());
        terms.push(pool.mk(Op::BvOr, &[mh, mh]).unwrap());
        // Shifts the other way round, and a lshr/shl pair that just touches.
        let sr = pool.mk(Op::BvLshr, &[x, sh]).unwrap();
        let sl = pool.mk(Op::BvShl, &[y, sh]).unwrap();
        terms.push(pool.mk(Op::BvOr, &[sr, sl]).unwrap());
        // A non-constant shift amount: the analysis must give up (mask = ones).
        let vsh = pool.mk(Op::BvShl, &[x, z]).unwrap();
        terms.push(pool.mk(Op::BvOr, &[vsh, ext]).unwrap());
        // ite of two disjoint-range branches.
        let c = pool.mk(Op::BvUlt, &[x, y]).unwrap();
        let it = pool.mk(Op::Ite, &[c, ml, zero_w]).unwrap();
        terms.push(pool.mk(Op::BvOr, &[it, mh]).unwrap());

        let (s, _) = rewrite_and_check(&mut pool, &terms, &format!("or-disjoint, width {w}"));
        merge(&mut stats, s);
    }
    assert_fired(&stats, &["or-disjoint-concat"]);
}

/// `disjoint-to-or`: a `bvadd`/`bvxor` whose operands can never set the same
/// bit is the `bvor` of them, because no carry is ever generated.
///
/// Two variables only, so this runs to width 6 rather than 4. The declining
/// cases matter as much as the firing ones: there is no cost heuristic in
/// front of this rule, only the mask analysis, and the wrong answer is always
/// the *cheaper* one — wiring instead of an adder — so an over-claimed zero
/// bit would show up here as a value mismatch and nowhere else.
#[test]
fn disjoint_add_and_xor_rule() {
    let mut stats = FxHashMap::default();
    for w in 2..=*WIDE_WIDTHS.end() {
        let mut pool = TermPool::new();
        let xs = pool.fresh_symbol("x", Sort::BitVec(w));
        let ys = pool.fresh_symbol("y", Sort::BitVec(w));
        let (x, y) = (pool.var(xs), pool.var(ys));
        let h = w / 2;
        let sh = pool.bv_u64(w, h as u64);
        let zhi = pool.bv(BvConst::zero(w - h));
        let zlo = pool.bv(BvConst::zero(h));
        let lo_mask = pool.bv(BvConst::ones(h).zero_extend(w - h));
        let hi_mask = pool.bv(BvConst::ones(w - h).concat(&BvConst::zero(h)));
        let mut terms: Vec<TermId> = Vec::new();

        // Byte assembly written with `+`: (x << h) + zero_extend(y[h-1:0]).
        let shifted = pool.mk(Op::BvShl, &[x, sh]).unwrap();
        let lo_bits = pool.mk(Op::Extract { hi: h - 1, lo: 0 }, &[y]).unwrap();
        let ext = pool.mk(Op::ZeroExtend(w - h), &[lo_bits]).unwrap();
        terms.push(pool.mk(Op::BvAdd, &[shifted, ext]).unwrap());
        terms.push(pool.mk(Op::BvXor, &[shifted, ext]).unwrap());

        // Built from concats instead, both operand orders.
        let a = pool.mk(Op::Concat, &[zhi, lo_bits]).unwrap();
        let hi_bits = pool
            .mk(
                Op::Extract {
                    hi: w - h - 1,
                    lo: 0,
                },
                &[x],
            )
            .unwrap();
        let b = pool.mk(Op::Concat, &[hi_bits, zlo]).unwrap();
        terms.push(pool.mk(Op::BvAdd, &[a, b]).unwrap());
        terms.push(pool.mk(Op::BvAdd, &[b, a]).unwrap());
        terms.push(pool.mk(Op::BvXor, &[a, b]).unwrap());

        // Masked operands: the analysis has to see through `bvand`.
        let ml = pool.mk(Op::BvAnd, &[x, lo_mask]).unwrap();
        let mh = pool.mk(Op::BvAnd, &[y, hi_mask]).unwrap();
        terms.push(pool.mk(Op::BvAdd, &[ml, mh]).unwrap());

        // --- must decline. `x` may set every bit, so nothing is disjoint
        // from it; `a + a` and `ml + ml` overlap with themselves; and a
        // non-constant shift amount leaves the analysis knowing nothing.
        terms.push(pool.mk(Op::BvAdd, &[shifted, x]).unwrap());
        terms.push(pool.mk(Op::BvAdd, &[a, a]).unwrap());
        terms.push(pool.mk(Op::BvAdd, &[ml, ml]).unwrap());
        terms.push(pool.mk(Op::BvXor, &[mh, mh]).unwrap());
        let vsh = pool.mk(Op::BvShl, &[x, y]).unwrap();
        terms.push(pool.mk(Op::BvAdd, &[vsh, ext]).unwrap());
        // Adjacent-but-touching ranges: `ml` owns bits 0..h-1 and a *one*-bit
        // wider mask would collide with `mh`. Off-by-one in either direction
        // is a wrong answer.
        let one = pool.bv_u64(w, 1);
        let plus_one = pool.mk(Op::BvAdd, &[ml, one]).unwrap();
        terms.push(pool.mk(Op::BvAdd, &[plus_one, mh]).unwrap());

        // Under an equality, where the concat the rule produces goes on to
        // feed `eq-concat-split`.
        let asm = pool.mk(Op::BvAdd, &[shifted, ext]).unwrap();
        terms.push(pool.mk(Op::Eq, &[asm, x]).unwrap());
        terms.push(pool.mk(Op::BvUle, &[asm, y]).unwrap());

        let (s, _) = rewrite_and_check(&mut pool, &terms, &format!("disjoint-add, width {w}"));
        merge(&mut stats, s);
    }
    assert_fired(&stats, &["disjoint-to-or", "or-disjoint-concat"]);
}

/// `eq-concat-split`, plus the constant cancellation and ite lifting that sit
/// beside it on equalities.
#[test]
fn eq_split_and_cancel_rules() {
    let mut stats = FxHashMap::default();
    for w in 2..=*WIDE_WIDTHS.end() {
        let mut pool = TermPool::new();
        let xs = pool.fresh_symbol("x", Sort::BitVec(w));
        let ys = pool.fresh_symbol("y", Sort::BitVec(w));
        let (x, y) = (pool.var(xs), pool.var(ys));
        let m = |v: u64| v % (1u64 << w);
        let k3 = pool.bv_u64(w, m(3));
        let k5 = pool.bv_u64(w, m(5));
        let mut terms: Vec<TermId> = Vec::new();

        // concat vs constant: every slice of the constant is free -> splits.
        let cc = pool.mk(Op::Concat, &[x, y]).unwrap();
        let wide_const = pool.bv_u64(2 * w, m(3) * (1u64 << w) + m(1));
        terms.push(pool.mk(Op::Eq, &[cc, wide_const]).unwrap());
        // concat vs concat with identical boundaries.
        let cc2 = pool.mk(Op::Concat, &[y, x]).unwrap();
        terms.push(pool.mk(Op::Eq, &[cc, cc2]).unwrap());
        // Mismatched boundaries: slices must be invented, so the rule declines.
        let half = pool.mk(Op::Extract { hi: w - 1, lo: 1 }, &[x]).unwrap();
        let bit = pool.mk(Op::Extract { hi: 0, lo: 0 }, &[y]).unwrap();
        let cc3 = pool.mk(Op::Concat, &[half, bit, y]).unwrap();
        terms.push(pool.mk(Op::Eq, &[cc3, cc]).unwrap());

        // Constant cancellation: (= (bvadd x c1) c2) -> (= x (c2-c1)).
        let sum = pool.mk(Op::BvAdd, &[x, k3]).unwrap();
        terms.push(pool.mk(Op::Eq, &[sum, k5]).unwrap());
        let sum2 = pool.mk(Op::BvAdd, &[x, y, k5]).unwrap();
        terms.push(pool.mk(Op::Eq, &[sum2, k3]).unwrap());
        terms.push(pool.mk(Op::Eq, &[k3, sum]).unwrap());

        // ite with constant branches under an equality.
        let c = pool.mk(Op::BvUlt, &[x, y]).unwrap();
        let it = pool.mk(Op::Ite, &[c, k3, k5]).unwrap();
        terms.push(pool.mk(Op::Eq, &[it, x]).unwrap());
        terms.push(pool.mk(Op::Eq, &[it, k5]).unwrap());
        // n-ary equality, with a duplicate and a conflicting constant pair.
        terms.push(pool.mk(Op::Eq, &[x, y, x]).unwrap());
        terms.push(pool.mk(Op::Eq, &[x, k3, k5]).unwrap());

        let (s, _) = rewrite_and_check(&mut pool, &terms, &format!("eq rules, width {w}"));
        merge(&mut stats, s);
    }
    assert_fired(
        &stats,
        &[
            "eq-concat-split",
            "eq-add-const-cancel",
            "eq-ite-const-lift",
            "eq-dedup",
        ],
    );
}

/// Extract pushdown: through bitwise ops at any offset, through low-bit
/// arithmetic, through concat and nested extracts, and through constant ites.
#[test]
fn extract_pushdown_rules() {
    let mut stats = FxHashMap::default();
    for w in 2..=*WIDE_WIDTHS.end() {
        let mut pool = TermPool::new();
        let xs = pool.fresh_symbol("x", Sort::BitVec(w));
        let ys = pool.fresh_symbol("y", Sort::BitVec(w));
        let (x, y) = (pool.var(xs), pool.var(ys));
        let k = pool.bv_u64(w, 3 % (1u64 << w));
        let mut terms: Vec<TermId> = Vec::new();

        // Bitwise: extraction commutes at every offset.
        for op in [Op::BvAnd, Op::BvOr, Op::BvXor] {
            let t = pool.mk(op, &[x, y]).unwrap();
            for hi in 0..w {
                for lo in 0..=hi {
                    terms.push(pool.mk(Op::Extract { hi, lo }, &[t]).unwrap());
                }
            }
            let n = pool.mk(Op::BvNot, &[t]).unwrap();
            terms.push(
                pool.mk(
                    Op::Extract {
                        hi: w - 1,
                        lo: w - 1,
                    },
                    &[n],
                )
                .unwrap(),
            );
        }
        // Arithmetic: only the low slice may be pushed. Both are checked; a
        // pushdown that ignored `lo == 0` would be caught here.
        for op in [Op::BvAdd, Op::BvMul, Op::BvSub] {
            let t = pool.mk(op, &[x, y]).unwrap();
            for hi in 0..w {
                terms.push(pool.mk(Op::Extract { hi, lo: 0 }, &[t]).unwrap());
                if hi > 0 {
                    terms.push(pool.mk(Op::Extract { hi, lo: 1 }, &[t]).unwrap());
                }
            }
        }
        let neg = pool.mk(Op::BvNeg, &[x]).unwrap();
        terms.push(pool.mk(Op::Extract { hi: 0, lo: 0 }, &[neg]).unwrap());
        terms.push(pool.mk(Op::Extract { hi: w - 1, lo: 0 }, &[neg]).unwrap());

        // Concat and nested extracts: every window of x ++ y.
        let cc = pool.mk(Op::Concat, &[x, y]).unwrap();
        for hi in 0..2 * w {
            for lo in 0..=hi {
                terms.push(pool.mk(Op::Extract { hi, lo }, &[cc]).unwrap());
            }
        }
        let e = pool.mk(Op::Extract { hi: w - 1, lo: 1 }, &[cc]).unwrap();
        terms.push(pool.mk(Op::Extract { hi: 0, lo: 0 }, &[e]).unwrap());

        // ite of constants.
        let c = pool.mk(Op::BvUlt, &[x, y]).unwrap();
        let zero = pool.bv_u64(w, 0);
        let it = pool.mk(Op::Ite, &[c, k, zero]).unwrap();
        terms.push(pool.mk(Op::Extract { hi: w - 1, lo: 0 }, &[it]).unwrap());
        if w >= 2 {
            terms.push(pool.mk(Op::Extract { hi: w - 1, lo: 1 }, &[it]).unwrap());
        }

        let (s, _) = rewrite_and_check(&mut pool, &terms, &format!("extract rules, width {w}"));
        merge(&mut stats, s);
    }
    assert_fired(
        &stats,
        &[
            "extract-bitwise",
            "extract-arith-low",
            "extract-concat",
            "extract-extract",
            "extract-full",
            "extract-ite-const",
        ],
    );
}

/// The BV identity rules: `x * -1 -> -x`, udiv/urem by a power of two and by
/// one, the shift normalizations, and the multiplier hoists.
#[test]
fn bv_identity_rules() {
    let mut stats = FxHashMap::default();
    for w in WIDE_WIDTHS {
        let mut pool = TermPool::new();
        let xs = pool.fresh_symbol("x", Sort::BitVec(w));
        let ys = pool.fresh_symbol("y", Sort::BitVec(w));
        let (x, y) = (pool.var(xs), pool.var(ys));
        let ones = pool.bv(BvConst::ones(w));
        let zero = pool.bv_u64(w, 0);
        let one = pool.bv_u64(w, 1);
        let mut terms: Vec<TermId> = Vec::new();

        // x * -1 -> -x, and the same inside a larger product.
        terms.push(pool.mk(Op::BvMul, &[x, ones]).unwrap());
        terms.push(pool.mk(Op::BvMul, &[x, y, ones]).unwrap());

        // udiv/urem by every constant divisor at this width, powers of two
        // included, plus the zero divisor and the unit.
        for d in 0..(1u64 << w) {
            let c = pool.bv_u64(w, d);
            terms.push(pool.mk(Op::BvUdiv, &[x, c]).unwrap());
            terms.push(pool.mk(Op::BvUrem, &[x, c]).unwrap());
            terms.push(pool.mk(Op::BvSdiv, &[x, c]).unwrap());
            terms.push(pool.mk(Op::BvSrem, &[x, c]).unwrap());
            terms.push(pool.mk(Op::BvSmod, &[x, c]).unwrap());
            // Constant dividend, variable divisor: the other operand order.
            terms.push(pool.mk(Op::BvUdiv, &[c, y]).unwrap());
            terms.push(pool.mk(Op::BvUrem, &[c, y]).unwrap());
        }
        terms.push(pool.mk(Op::BvUdiv, &[x, y]).unwrap());
        terms.push(pool.mk(Op::BvUrem, &[x, y]).unwrap());

        // Constant shifts (turned into wiring) and saturating shifts.
        for s in 0..=(w as u64 + 1) {
            let c = pool.bv_u64(w, s.min((1u64 << w) - 1));
            for op in [Op::BvShl, Op::BvLshr, Op::BvAshr] {
                terms.push(pool.mk(op, &[x, c]).unwrap());
            }
        }
        // Variable shifts stay opaque but must still round-trip.
        for op in [Op::BvShl, Op::BvLshr, Op::BvAshr] {
            terms.push(pool.mk(op, &[x, y]).unwrap());
        }
        // Shifting a term by its own value: `x >>u x` is 0 and `x >>a x` is
        // the sign, because `x < 2^x` at every width. Negative cases too --
        // `x << x` and shifts by an unrelated amount must survive untouched.
        let notx = pool.mk(Op::BvNot, &[x]).unwrap();
        let noty = pool.mk(Op::BvNot, &[y]).unwrap();
        let negx2 = pool.mk(Op::BvNeg, &[x]).unwrap();
        // `x + (x << x)` is `x | (x << x)`: the operands are bit-disjoint.
        // `y + (x << x)` and `x + (x << y)` are not, and must survive.
        let shlxx = pool.mk(Op::BvShl, &[x, x]).unwrap();
        terms.push(pool.mk(Op::BvAdd, &[x, shlxx]).unwrap());
        terms.push(pool.mk(Op::BvAdd, &[y, shlxx]).unwrap());
        let shlxy = pool.mk(Op::BvShl, &[x, y]).unwrap();
        terms.push(pool.mk(Op::BvAdd, &[x, shlxy]).unwrap());
        for op in [Op::BvShl, Op::BvLshr, Op::BvAshr] {
            terms.push(pool.mk(op, &[x, x]).unwrap());
            terms.push(pool.mk(op, &[notx, x]).unwrap());
            terms.push(pool.mk(op, &[noty, x]).unwrap());
            terms.push(pool.mk(op, &[negx2, x]).unwrap());
            terms.push(pool.mk(op, &[x, notx]).unwrap());
        }

        // Multiplier hoists: a non-constant shift amount keeps the shl alive
        // long enough for `mul-shl-hoist` to see it.
        let vshl = pool.mk(Op::BvShl, &[x, y]).unwrap();
        terms.push(pool.mk(Op::BvMul, &[vshl, y]).unwrap());
        let nx = pool.mk(Op::BvNeg, &[x]).unwrap();
        terms.push(pool.mk(Op::BvMul, &[nx, y]).unwrap());

        // Units and absorbing elements.
        terms.push(pool.mk(Op::BvAdd, &[x, zero]).unwrap());
        terms.push(pool.mk(Op::BvMul, &[x, one]).unwrap());
        terms.push(pool.mk(Op::BvMul, &[x, zero]).unwrap());
        terms.push(pool.mk(Op::BvAnd, &[x, ones]).unwrap());
        terms.push(pool.mk(Op::BvAnd, &[x, zero]).unwrap());
        terms.push(pool.mk(Op::BvOr, &[x, ones]).unwrap());
        terms.push(pool.mk(Op::BvSub, &[x, x]).unwrap());
        terms.push(pool.mk(Op::BvSub, &[zero, x]).unwrap());
        let nnx = pool.mk(Op::BvNot, &[x]).unwrap();
        terms.push(pool.mk(Op::BvAnd, &[x, nnx]).unwrap());
        terms.push(pool.mk(Op::BvOr, &[x, nnx]).unwrap());

        let (s, _) = rewrite_and_check(&mut pool, &terms, &format!("bv identities, width {w}"));
        merge(&mut stats, s);
    }
    assert_fired(
        &stats,
        &[
            "mul-minus-one",
            "udiv-pow2",
            "urem-pow2",
            "div-one",
            "shift-const",
            "shift-saturate",
            "shift-self",
            "lshr-not-self",
            "add-shl-self",
            "mul-shl-hoist",
            "mul-neg-hoist",
            "bv-absorb",
            "bv-complement",
            "sub-self",
            "zero-sub",
        ],
    );
}

/// AC flattening of the n-ary ops, on both the boolean and the BV side. The
/// flattened forms must mean exactly what the nested ones did — including the
/// duplicate-elimination and parity handling that runs on the flattened list.
#[test]
fn ac_flattening_rules() {
    let mut stats = FxHashMap::default();
    for w in WIDTHS {
        let mut pool = TermPool::new();
        let xs = pool.fresh_symbol("x", Sort::BitVec(w));
        let ys = pool.fresh_symbol("y", Sort::BitVec(w));
        let zs = pool.fresh_symbol("z", Sort::BitVec(w));
        let (x, y, z) = (pool.var(xs), pool.var(ys), pool.var(zs));
        let k = pool.bv_u64(w, 3 % (1u64 << w));
        let mut terms: Vec<TermId> = Vec::new();

        for op in [Op::BvAdd, Op::BvMul, Op::BvAnd, Op::BvOr, Op::BvXor] {
            let inner = pool.mk(op, &[x, y]).unwrap();
            terms.push(pool.mk(op, &[inner, z]).unwrap());
            terms.push(pool.mk(op, &[inner, inner]).unwrap());
            terms.push(pool.mk(op, &[inner, x, k]).unwrap());
            let deep = pool.mk(op, &[inner, z]).unwrap();
            terms.push(pool.mk(op, &[deep, y, k]).unwrap());
        }

        // Boolean layer: nested and/or/xor with duplicates and complements.
        let a = pool.mk(Op::BvUlt, &[x, y]).unwrap();
        let b = pool.mk(Op::BvUlt, &[y, z]).unwrap();
        let c = pool.mk(Op::Eq, &[x, k]).unwrap();
        let na = pool.mk(Op::Not, &[a]).unwrap();
        for op in [Op::And, Op::Or, Op::Xor] {
            let inner = pool.mk(op, &[a, b]).unwrap();
            terms.push(pool.mk(op, &[inner, c]).unwrap());
            terms.push(pool.mk(op, &[inner, a]).unwrap());
            terms.push(pool.mk(op, &[inner, na]).unwrap());
            let deep = pool.mk(op, &[inner, c]).unwrap();
            terms.push(pool.mk(op, &[deep, b, na]).unwrap());
        }
        // Nested concats flatten and merge too.
        let cc = pool.mk(Op::Concat, &[x, y]).unwrap();
        terms.push(pool.mk(Op::Concat, &[cc, z]).unwrap());
        terms.push(pool.mk(Op::Concat, &[k, cc, k]).unwrap());

        let (s, _) = rewrite_and_check(&mut pool, &terms, &format!("ac-flatten, width {w}"));
        merge(&mut stats, s);
    }
    assert_fired(
        &stats,
        &[
            "ac-flatten",
            "xor-shrink",
            "and-or-complement",
            "concat-merge",
        ],
    );
}

// ---------------------------------------------------------------------------
// random terms, exhaustively checked
// ---------------------------------------------------------------------------

/// xorshift64*, so the term generator is deterministic and a failure is
/// reproducible from the seed printed in the panic message.
struct Rng(u64);

impl Rng {
    fn next_u64(&mut self) -> u64 {
        let mut x = self.0;
        x ^= x >> 12;
        x ^= x << 25;
        x ^= x >> 27;
        self.0 = x;
        x.wrapping_mul(0x2545_f491_4f6c_dd1d)
    }

    fn below(&mut self, n: usize) -> usize {
        (self.next_u64() % n as u64) as usize
    }

    fn pick(&mut self, xs: &[TermId]) -> TermId {
        xs[self.below(xs.len())]
    }
}

/// Widest term the generator will build at a given base width. At least twice
/// the base, so a concat of two base-width terms is always in range, and
/// capped so `Repeat`/`SignExtend` cannot run away. Width costs the evaluator
/// nothing here (everything fits one limb); the cap is about term size.
fn fuzz_max_width(base_w: u32) -> u32 {
    (2 * base_w).clamp(8, 12)
}

/// Build `count` random well-sorted terms over `base_w`-bit variables.
///
/// Deliberately unstructured: the hand-written piles above encode what we
/// *think* the rules do, and only random shapes find the combinations nobody
/// thought to write down. Every generated term is a root to be checked, so a
/// term that no rule touches costs one comparison and nothing else.
fn random_terms(pool: &mut TermPool, rng: &mut Rng, base_w: u32, count: usize) -> Vec<TermId> {
    let max_w = fuzz_max_width(base_w);
    let xs = pool.fresh_symbol("x", Sort::BitVec(base_w));
    let ys = pool.fresh_symbol("y", Sort::BitVec(base_w));
    let mut bv: Vec<TermId> = vec![pool.var(xs), pool.var(ys)];
    for v in [0u64, 1, (1u64 << base_w) - 1, 2 % (1u64 << base_w)] {
        let c = pool.bv_u64(base_w, v);
        bv.push(c);
    }
    let mut bools: Vec<TermId> = vec![pool.true_term, pool.false_term];
    let mut out: Vec<TermId> = Vec::with_capacity(count);

    let bv_binops = [
        Op::BvAdd,
        Op::BvSub,
        Op::BvMul,
        Op::BvUdiv,
        Op::BvUrem,
        Op::BvSdiv,
        Op::BvSrem,
        Op::BvSmod,
        Op::BvAnd,
        Op::BvOr,
        Op::BvXor,
        Op::BvNand,
        Op::BvNor,
        Op::BvXnor,
        Op::BvShl,
        Op::BvLshr,
        Op::BvAshr,
    ];
    let cmps = [
        Op::BvUlt,
        Op::BvUle,
        Op::BvUgt,
        Op::BvUge,
        Op::BvSlt,
        Op::BvSle,
        Op::BvSgt,
        Op::BvSge,
    ];

    while out.len() < count {
        let a = rng.pick(&bv);
        let w = pool.width(a);
        // Same-width partner, so the binary BV ops are always well-sorted.
        let same: Vec<TermId> = bv.iter().copied().filter(|&t| pool.width(t) == w).collect();
        let b = rng.pick(&same);
        let made: Option<TermId> = match rng.below(14) {
            0 => {
                let op = bv_binops[rng.below(bv_binops.len())];
                pool.mk(op, &[a, b]).ok()
            }
            1 => {
                // n-ary application of a commutative op.
                let op = [Op::BvAdd, Op::BvMul, Op::BvAnd, Op::BvOr, Op::BvXor][rng.below(5)];
                let c = rng.pick(&same);
                pool.mk(op, &[a, b, c]).ok()
            }
            2 => pool.mk([Op::BvNeg, Op::BvNot][rng.below(2)], &[a]).ok(),
            3 => {
                let hi = rng.below(w as usize) as u32;
                let lo = rng.below(hi as usize + 1) as u32;
                pool.mk(Op::Extract { hi, lo }, &[a]).ok()
            }
            4 => {
                if w + pool.width(b) <= max_w {
                    pool.mk(Op::Concat, &[a, b]).ok()
                } else {
                    None
                }
            }
            5 => {
                let n = 1 + rng.below(2) as u32;
                if w + n <= max_w {
                    pool.mk([Op::ZeroExtend(n), Op::SignExtend(n)][rng.below(2)], &[a])
                        .ok()
                } else {
                    None
                }
            }
            6 => {
                let n = rng.below(w as usize + 2) as u32;
                pool.mk([Op::RotateLeft(n), Op::RotateRight(n)][rng.below(2)], &[a])
                    .ok()
            }
            7 => {
                if w * 2 <= max_w {
                    pool.mk(Op::Repeat(2), &[a]).ok()
                } else {
                    None
                }
            }
            8 => {
                let c = rng.pick(&bools);
                pool.mk(Op::Ite, &[c, a, b]).ok()
            }
            9 => {
                let op = cmps[rng.below(cmps.len())];
                pool.mk(op, &[a, b]).ok()
            }
            10 => pool.mk([Op::Eq, Op::Distinct][rng.below(2)], &[a, b]).ok(),
            11 => {
                let c = rng.pick(&bools);
                let d = rng.pick(&bools);
                let op = [Op::And, Op::Or, Op::Xor, Op::Implies, Op::Eq][rng.below(5)];
                pool.mk(op, &[c, d]).ok()
            }
            12 => {
                let c = rng.pick(&bools);
                pool.mk(Op::Not, &[c]).ok()
            }
            _ => {
                let c = rng.pick(&bools);
                let d = rng.pick(&bools);
                let e = rng.pick(&bools);
                pool.mk([Op::And, Op::Or, Op::Xor][rng.below(3)], &[c, d, e])
                    .ok()
            }
        };
        let Some(t) = made else { continue };
        if pool.sort(t) == Sort::Bool {
            bools.push(t);
        } else {
            bv.push(t);
        }
        out.push(t);
    }
    out
}

/// Random terms through the full rewriter, each verified exhaustively.
///
/// This is where rule *interactions* get real coverage: the generator builds
/// shapes nobody anticipated, and every one of them is a proof obligation
/// discharged by enumeration. Two variables keeps the case count at 2^(2w),
/// so width 4 is 256 assignments for hundreds of terms.
#[test]
fn random_terms_survive_rewriting() {
    const SEED: u64 = 0x5D_EE_C0_DE_12_34_56_78;
    let mut fired = 0;
    for w in WIDE_WIDTHS {
        // Fewer rounds where an assignment sweep costs 16x more.
        let rounds = if w <= 4 { 4 } else { 2 };
        for round in 0..rounds {
            let mut rng = Rng(SEED ^ (u64::from(w) << 8) ^ round);
            let mut pool = TermPool::new();
            let terms = random_terms(&mut pool, &mut rng, w, 300);
            let (_, n) = rewrite_and_check(
                &mut pool,
                &terms,
                &format!("random terms, width {w}, round {round} (seed {SEED:#x})"),
            );
            fired += n;
        }
    }
    assert!(
        fired > 500,
        "expected random terms to rewrite widely, got {fired}"
    );
}

// ---------------------------------------------------------------------------
// the zero-bit analysis
// ---------------------------------------------------------------------------

/// `nonzero_mask` is the one non-syntactic soundness step in the recent work:
/// it *claims* certain bits of a term are always zero, and `or_disjoint_concat`
/// rebuilds an `or` as a concat on the strength of that claim. An over-claiming
/// mask is a wrong-answer bug, so check the claim directly and exhaustively:
/// for every subterm whose mask clears any bit, `value & ~mask` must be 0 under
/// every assignment.
///
/// A named pile builder: given a pool and a width, produce the roots to check.
type PileBuilder = fn(&mut TermPool, u32) -> Vec<TermId>;

#[test]
fn nonzero_mask_never_overclaims_exhaustively() {
    let mut checked_terms = 0usize;
    // The two piles are built in separate pools: each introduces its own
    // variables, and enumerating their union would multiply the case count
    // instead of adding it.
    let builders: [(&str, PileBuilder); 2] = [
        ("linear/or seeds", linear_and_or_seeds),
        ("general pile", general_pile),
    ];
    for w in WIDTHS {
        for (name, build) in builders {
            let mut pool = TermPool::new();
            // The pile before *and* after rewriting: masks are consulted on
            // whatever the rewriter has built so far, so the rewritten forms
            // are as much in scope as the originals.
            let mut roots = build(&mut pool, w);
            let mut rw = Rewriter::new();
            let rewritten: Vec<TermId> = roots.iter().map(|&t| rw.rewrite(&mut pool, t)).collect();
            roots.extend(rewritten);

            let mut bv_subterms: Vec<TermId> = Vec::new();
            pool.post_order(&roots, |pool, t| {
                if pool.sort(t).is_bv() {
                    bv_subterms.push(t);
                }
            });
            // Keep only the terms whose mask actually claims a zero bit.
            let claims: Vec<(TermId, BvConst)> = bv_subterms
                .into_iter()
                .map(|t| (t, smtrs_rewrite::nonzero_mask(&pool, t)))
                .filter(|(t, m)| *m != BvConst::ones(pool.width(*t)))
                .collect();
            checked_terms += claims.len();

            let terms: Vec<TermId> = claims.iter().map(|&(t, _)| t).collect();
            let syms = free_syms(&pool, &terms);
            let mut failure: Option<String> = None;
            for_each_assignment(&pool, &syms, |asg| {
                if failure.is_some() {
                    return;
                }
                let vals = eval(&pool, &terms, asg).expect("closed term");
                for (i, (t, mask)) in claims.iter().enumerate() {
                    let v = vals[i].as_bv().expect("bv-sorted subterm");
                    if !v.and(&mask.not()).is_zero() {
                        failure = Some(format!(
                            "nonzero_mask OVER-CLAIMS in {name} at width {w}\n  term:  {}\n  \
                             mask:  {}\n  value: {}\n  under {}",
                            pool.display(*t),
                            mask.to_binary_string(),
                            show_value(&vals[i]),
                            show_assignment(&pool, asg),
                        ));
                        return;
                    }
                }
            });
            if let Some(msg) = failure {
                panic!("{msg}");
            }
        }
    }
    assert!(
        checked_terms > 100,
        "expected many masks to claim zero bits, got {checked_terms}"
    );
}
