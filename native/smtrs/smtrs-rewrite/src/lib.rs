//! smtrs-rewrite: bottom-up word-level rewriting over the term DAG.
//!
//! Scope: exhaustive constant folding, the boolean/BV identities, and the
//! structural normalizations that carry the QF_BV benchmarks — linear
//! normalization over Z/2^w with three distribution modes, a conservative
//! zero-bit analysis backing disjoint-`or`-to-concat, extract pushdown,
//! equality/concat splitting, and sharing-aware AC flattening. Every rule
//! must be locally sound, validated by the soundness-query generator in
//! `soundness.rs` (Z3-checked at widths 1..=65) and differentially by the
//! harness.
//!
//! Design: `rewrite` processes the DAG bottom-up with a memo table, so each
//! distinct subterm is rewritten once. Rules apply at a node after its
//! children have been rewritten; when a rule fires, the (already-normalized)
//! result is re-entered through `rewrite_node` until fixpoint, bounded by
//! `MAX_LOCAL_ITERS`.

mod rules;
pub mod soundness;

/// Test hook: the "which bits can be 1" analysis behind the disjoint-`or`
/// rule. Exposed so the soundness suite can check the claim directly —
/// every bit the analysis clears must really be zero for all assignments.
#[doc(hidden)]
pub fn nonzero_mask(pool: &TermPool, t: TermId) -> smtrs_core::BvConst {
    rules::nonzero_mask(pool, t, rules::MASK_DEPTH)
}

use rustc_hash::FxHashMap;
use smtrs_core::{TermId, TermPool};

#[derive(Clone)]
pub struct Rewriter {
    cache: FxHashMap<TermId, TermId>,
    /// Rule name -> hit count, for profiling which rules earn their keep.
    pub stats: FxHashMap<&'static str, u64>,
    /// Parent counts of pre-existing terms across the assertion set (see
    /// rules::REFCOUNTS). Callers set this before rewriting; flattening
    /// consults it to avoid re-associating shared arithmetic.
    pub refcounts: FxHashMap<TermId, u32>,
    /// When false the caller wants the *unguarded* encoding: parent counts are
    /// never installed, so every flattening decision goes ahead. Kept as a
    /// field rather than a call-site argument because `preprocess` recounts
    /// per substitution round and has to honour the same choice.
    pub share_guard: bool,
    /// How many flattenings the sharing guard blocked across every `rewrite`
    /// on this rewriter. Zero means the unguarded encoding would have been
    /// term-for-term identical, so there is nothing to compare against.
    pub share_declines: u64,
    /// Cooperative interrupt. Rewriting is not bounded by the SAT budget —
    /// the recursive rules can spend minutes on a large shared DAG — so the
    /// flag has to be visible here too, or `--timeout-ms` simply does not
    /// apply to this phase.
    terminate: Option<std::sync::Arc<std::sync::atomic::AtomicBool>>,
    /// Set when a `rewrite` was cut short. The terms it returned are still
    /// logically equivalent to their inputs, but only partially normalized,
    /// so the caller must abandon them rather than bit-blast them.
    interrupted: bool,
    /// Ceiling on `TermPool::num_terms()`, or 0 for unbounded. See
    /// `set_size_budget`.
    size_budget: usize,
    /// Sticky: some `rewrite` crossed `size_budget`.
    over_budget: bool,
    /// Suppress the DAG-multiplying pushdown rules (see `set_conservative`).
    conservative: bool,
}

impl Default for Rewriter {
    fn default() -> Self {
        Self::new()
    }
}

impl Rewriter {
    pub fn new() -> Self {
        Rewriter {
            cache: FxHashMap::default(),
            stats: FxHashMap::default(),
            refcounts: FxHashMap::default(),
            share_guard: true,
            share_declines: 0,
            terminate: None,
            interrupted: false,
            size_budget: 0,
            over_budget: false,
            conservative: false,
        }
    }

    /// Cap the term pool at `limit` nodes for the duration of each `rewrite`.
    ///
    /// Rewriting is supposed to shrink the formula, but extract pushdown can
    /// do the opposite: every distinct slice boundary above a bitwise node
    /// re-enters the whole subterm, and on a term whose boundaries multiply
    /// with depth — a bit-reversal network is the extreme case — the DAG grows
    /// by three orders of magnitude and the phase runs for minutes. Once the
    /// cap is crossed the remaining nodes are built without rules and
    /// `over_budget` is set; the caller is expected to throw the result away
    /// and rewrite again with `set_conservative(true)`.
    pub fn set_size_budget(&mut self, limit: usize) {
        self.size_budget = limit;
    }

    /// Did any `rewrite` cross the size budget? The terms returned are only
    /// partially normalized (see `set_size_budget`).
    pub fn over_budget(&self) -> bool {
        self.over_budget
    }

    /// Switch off the pushdown rules that can multiply the DAG. Everything
    /// else — folding, the identities, linear normalization — still applies.
    pub fn set_conservative(&mut self, on: bool) {
        self.conservative = on;
    }

    /// Install the cooperative interrupt observed during `rewrite`.
    pub fn set_terminate(&mut self, flag: std::sync::Arc<std::sync::atomic::AtomicBool>) {
        self.terminate = Some(flag);
    }

    /// Drop the interrupt *and* the sticky record of having seen it. A clone
    /// that inherited both would otherwise be permanently interrupted.
    pub fn clear_terminate(&mut self) {
        self.terminate = None;
        self.interrupted = false;
        self.over_budget = false;
    }

    /// True when the last `rewrite` was cut short by the interrupt. Results
    /// produced under it must not be blasted (see the field docs).
    pub fn interrupted(&self) -> bool {
        self.interrupted
    }

    /// Rewrite `root` to an equivalent (ideally simpler) term.
    pub fn rewrite(&mut self, pool: &mut TermPool, root: TermId) -> TermId {
        if let Some(&r) = self.cache.get(&root) {
            return r;
        }
        let prev_flag = rules::swap_terminate(self.terminate.clone());
        let prev_limit = rules::swap_size_limit(self.size_budget);
        let prev_cons = rules::swap_conservative(self.conservative);
        let declines_before = rules::share_declines();
        // Install refcounts for the flattening heuristics (swapped, not
        // cloned; restored on exit).
        rules::REFCOUNTS.with(|r| std::mem::swap(&mut *r.borrow_mut(), &mut self.refcounts));
        // Iterative bottom-up: collect post-order, then rebuild.
        let mut order: Vec<TermId> = Vec::new();
        pool.post_order(&[root], |_, t| order.push(t));
        for t in order {
            if self.cache.contains_key(&t) {
                continue;
            }
            let op = pool.op(t);
            let args: Vec<TermId> = pool.args(t).iter().map(|a| self.cache[a]).collect();
            let new_t = rules::rewrite_node(pool, op, &args, &mut self.stats);
            self.cache.insert(t, new_t);
            // Refcounts are keyed on original terms; carry them over to the
            // rewritten form so sharing checks see through the rewrite.
            if new_t != t {
                rules::REFCOUNTS.with(|r| {
                    let mut r = r.borrow_mut();
                    if let Some(&c) = r.get(&t) {
                        *r.entry(new_t).or_insert(0) += c;
                    }
                });
            }
        }
        rules::REFCOUNTS.with(|r| std::mem::swap(&mut *r.borrow_mut(), &mut self.refcounts));
        self.share_declines += rules::share_declines() - declines_before;
        self.interrupted |= rules::interrupted();
        self.over_budget |= rules::size_limit_hit();
        rules::swap_conservative(prev_cons);
        rules::swap_size_limit(prev_limit);
        rules::swap_terminate(prev_flag);
        self.cache[&root]
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use smtrs_core::{Op, Sort};

    fn setup() -> (TermPool, Rewriter, TermId, TermId) {
        let mut p = TermPool::new();
        let xs = p.fresh_symbol("x", Sort::BitVec(8));
        let ys = p.fresh_symbol("y", Sort::BitVec(8));
        let x = p.var(xs);
        let y = p.var(ys);
        (p, Rewriter::new(), x, y)
    }

    #[test]
    fn constant_folding() {
        let (mut p, mut rw, _, _) = setup();
        let a = p.bv_u64(8, 20);
        let b = p.bv_u64(8, 22);
        let sum = p.mk(Op::BvAdd, &[a, b]).unwrap();
        let folded = rw.rewrite(&mut p, sum);
        assert_eq!(p.as_bv_const(folded).unwrap().as_u64(), Some(42));
    }

    #[test]
    fn identity_elimination() {
        let (mut p, mut rw, x, _) = setup();
        let zero = p.bv_u64(8, 0);
        let sum = p.mk(Op::BvAdd, &[x, zero]).unwrap();
        assert_eq!(rw.rewrite(&mut p, sum), x);

        let one = p.bv_u64(8, 1);
        let prod = p.mk(Op::BvMul, &[x, one]).unwrap();
        assert_eq!(rw.rewrite(&mut p, prod), x);

        let ones = p.bv_u64(8, 0xff);
        let masked = p.mk(Op::BvAnd, &[x, ones]).unwrap();
        assert_eq!(rw.rewrite(&mut p, masked), x);

        let zeroand = p.mk(Op::BvAnd, &[x, zero]).unwrap();
        assert_eq!(rw.rewrite(&mut p, zeroand), zero);
    }

    #[test]
    fn xor_self_cancels() {
        let (mut p, mut rw, x, _) = setup();
        let xx = p.mk(Op::BvXor, &[x, x]).unwrap();
        let zero = p.bv_u64(8, 0);
        assert_eq!(rw.rewrite(&mut p, xx), zero);
    }

    #[test]
    fn double_negation() {
        let (mut p, mut rw, x, _) = setup();
        let n1 = p.mk(Op::BvNot, &[x]).unwrap();
        let n2 = p.mk(Op::BvNot, &[n1]).unwrap();
        assert_eq!(rw.rewrite(&mut p, n2), x);
    }

    #[test]
    fn bool_simplification() {
        let (mut p, mut rw, x, y) = setup();
        let ult = p.mk(Op::BvUlt, &[x, y]).unwrap();
        let tt = p.true_term;
        let conj = p.mk(Op::And, &[ult, tt]).unwrap();
        assert_eq!(rw.rewrite(&mut p, conj), ult);

        let not_ult = p.mk(Op::Not, &[ult]).unwrap();
        let contradiction = p.mk(Op::And, &[ult, not_ult]).unwrap();
        assert_eq!(rw.rewrite(&mut p, contradiction), p.false_term);
    }

    #[test]
    fn ite_and_eq() {
        let (mut p, mut rw, x, y) = setup();
        let c = p.mk(Op::BvUlt, &[x, y]).unwrap();
        let ite_same = p.mk(Op::Ite, &[c, x, x]).unwrap();
        assert_eq!(rw.rewrite(&mut p, ite_same), x);

        let eq_same = p.mk(Op::Eq, &[x, x]).unwrap();
        assert_eq!(rw.rewrite(&mut p, eq_same), p.true_term);

        let a = p.bv_u64(8, 1);
        let b = p.bv_u64(8, 2);
        let eq_diff = p.mk(Op::Eq, &[a, b]).unwrap();
        assert_eq!(rw.rewrite(&mut p, eq_diff), p.false_term);
    }

    /// Complement detection must not depend on the arity: above
    /// `COMPLEMENT_INDEX_ARITY` the rule switches from a pairwise scan to a
    /// hash index, and the two have to agree.
    #[test]
    fn wide_conjunctions_still_find_their_complements() {
        for n in [2usize, 12, 13, 64] {
            for (op, expect) in [(Op::And, false), (Op::Or, true)] {
                let mut p = TermPool::new();
                let mut rw = Rewriter::new();
                let mut args: Vec<TermId> = (0..n)
                    .map(|i| {
                        let s = p.fresh_symbol(format!("b{i}"), Sort::Bool);
                        p.var(s)
                    })
                    .collect();
                // Padding alone must not collapse.
                let plain = p.mk(op, &args).unwrap();
                let got = rw.rewrite(&mut p, plain);
                assert!(
                    got != p.true_term && got != p.false_term,
                    "n={n} {op:?}: independent literals collapsed"
                );

                // A literal and its negation anywhere in the list must.
                let neg = p.mk(Op::Not, &[args[0]]).unwrap();
                args.push(neg);
                let t = p.mk(op, &args).unwrap();
                let want = if expect { p.true_term } else { p.false_term };
                assert_eq!(rw.rewrite(&mut p, t), want, "n={n} {op:?}: not-complement");

                // The same, through the comparison normalisation: `bvult x y`
                // and `bvule y x` are complements without a `not` in sight.
                let xs = p.fresh_symbol("cx", Sort::BitVec(8));
                let ys = p.fresh_symbol("cy", Sort::BitVec(8));
                let (x, y) = (p.var(xs), p.var(ys));
                let lt = p.mk(Op::BvUlt, &[x, y]).unwrap();
                let ge = p.mk(Op::BvUle, &[y, x]).unwrap();
                let mut cmp_args = args[..n].to_vec();
                cmp_args.push(lt);
                cmp_args.push(ge);
                let t = p.mk(op, &cmp_args).unwrap();
                assert_eq!(
                    rw.rewrite(&mut p, t),
                    want,
                    "n={n} {op:?}: ult/ule complement"
                );
            }
        }
    }

    /// A flag that is already set when `rewrite` starts must be seen at the
    /// first node, not 1024 nodes later, and must leave the rewriter in the
    /// "abandon this result" state rather than panicking.
    #[test]
    fn a_set_terminate_flag_is_observed_immediately() {
        let (mut p, mut rw, x, _) = setup();
        let zero = p.bv_u64(8, 0);
        let sum = p.mk(Op::BvAdd, &[x, zero]).unwrap();
        rw.set_terminate(std::sync::Arc::new(std::sync::atomic::AtomicBool::new(
            true,
        )));
        let out = rw.rewrite(&mut p, sum);
        assert!(rw.interrupted(), "terminate flag not observed");
        // Degraded rewriting is sound but not normalizing: `x + 0` survives.
        assert_eq!(out, sum);
    }

    /// Extract pushdown recurses through `rewrite_node` per child. On a DAG
    /// where every level shares its input twice that is 2^n rewrites without
    /// a memo — this term is ~2^40 — so a regression here does not merely
    /// slow the test down, it never finishes. The armed flag is the safety
    /// net that turns "hangs the test suite" into "fails the assertion".
    #[test]
    fn extract_pushdown_over_a_shared_dag_is_not_exponential() {
        let mut p = TermPool::new();
        let mut rw = Rewriter::new();
        let s = p.fresh_symbol("x", Sort::BitVec(32));
        let mut cur = p.var(s);
        for i in 0..40u64 {
            let c = p.bv_u64(32, i * 2 + 1);
            let a = p.mk(Op::BvXor, &[cur, c]).unwrap();
            let b = p.mk(Op::BvAdd, &[cur, c]).unwrap();
            cur = p.mk(Op::BvAnd, &[a, b]).unwrap();
        }
        let top = p.mk(Op::Extract { hi: 7, lo: 0 }, &[cur]).unwrap();

        let flag = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
        rw.set_terminate(flag.clone());
        let armed = flag.clone();
        std::thread::spawn(move || {
            std::thread::sleep(std::time::Duration::from_secs(20));
            armed.store(true, std::sync::atomic::Ordering::Relaxed);
        });
        let t0 = std::time::Instant::now();
        let out = rw.rewrite(&mut p, top);
        let elapsed = t0.elapsed();

        assert!(!rw.interrupted(), "took longer than the 20 s interrupt");
        assert!(elapsed.as_secs_f64() < 10.0, "rewrite took {elapsed:?}");
        assert_eq!(p.width(out), 8);
    }

    #[test]
    fn extract_of_concat() {
        let (mut p, mut rw, x, y) = setup();
        let cc = p.mk(Op::Concat, &[x, y]).unwrap(); // x = bits 15..8, y = bits 7..0
        let hi = p.mk(Op::Extract { hi: 15, lo: 8 }, &[cc]).unwrap();
        assert_eq!(rw.rewrite(&mut p, hi), x);
        let lo = p.mk(Op::Extract { hi: 7, lo: 0 }, &[cc]).unwrap();
        assert_eq!(rw.rewrite(&mut p, lo), y);
    }

    #[test]
    fn extract_full_width() {
        let (mut p, mut rw, x, _) = setup();
        let e = p.mk(Op::Extract { hi: 7, lo: 0 }, &[x]).unwrap();
        assert_eq!(rw.rewrite(&mut p, e), x);
    }

    #[test]
    fn shift_saturation() {
        let (mut p, mut rw, x, _) = setup();
        let big = p.bv_u64(8, 9);
        let sh = p.mk(Op::BvShl, &[x, big]).unwrap();
        let zero = p.bv_u64(8, 0);
        assert_eq!(rw.rewrite(&mut p, sh), zero);
    }

    #[test]
    fn comparison_bounds() {
        let (mut p, mut rw, x, _) = setup();
        let zero = p.bv_u64(8, 0);
        let ult0 = p.mk(Op::BvUlt, &[x, zero]).unwrap();
        assert_eq!(rw.rewrite(&mut p, ult0), p.false_term);
        let uge0 = p.mk(Op::BvUge, &[x, zero]).unwrap();
        assert_eq!(rw.rewrite(&mut p, uge0), p.true_term);
    }
}
